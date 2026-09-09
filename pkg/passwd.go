package pkg

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// Changement de mot de passe.
//
// Ce que l'enveloppe rend possible : la clé qui chiffre les données est tirée
// au hasard et scellée dans l'en-tête. Changer de mot de passe revient donc à
// rouvrir cette enveloppe et à la refermer avec une autre clé — les 117 premiers
// octets du fichier, et rien d'autre. Sur un fichier de 100 Go, l'opération dure
// le temps d'un Argon2 au lieu d'une heure de disque.
//
// Les paramètres Argon2 du fichier sont conservés : c'est le mot de passe qu'on
// change, pas le coût de la dérivation. Un fichier scellé en profil « maximum »
// le reste.

// VersionEnveloppe est la première version de format dont la clé de contenu est
// scellée dans l'en-tête plutôt que dérivée du mot de passe. C'est donc la
// première où changer de mot de passe ne demande pas de tout re-chiffrer.
const VersionEnveloppe = versionV4

// suffixeSauvegarde nomme le fichier qui garde l'ancien en-tête le temps du
// remplacement.
const suffixeSauvegarde = ".entete-precedent"

// ChangePassword remplace le mot de passe d'un .chto sans toucher à son contenu.
func ChangePassword(path string, oldPassword, newPassword []byte) error {
	if len(newPassword) == 0 {
		return errors.New("le nouveau mot de passe est vide")
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("ouverture de %s: %w", path, err)
	}
	ferme := true
	defer func() {
		if ferme {
			f.Close()
		}
	}()

	h, err := readHeader(f)
	if err != nil {
		return err
	}
	if h.Version < VersionEnveloppe {
		return fmt.Errorf("ce fichier est au format v%d, où la clé du contenu vient directement du mot de passe : "+
			"il faut le déchiffrer puis le rechiffrer pour en changer (le format v4 permet le changement direct)", h.Version)
	}

	// Ouverture avec l'ancien mot de passe. Un échec s'arrête ici, avant la
	// moindre écriture : un mot de passe refusé ne doit pas laisser le fichier
	// dans un état différent de celui où on l'a trouvé.
	ancien, err := deriveMasterV4(oldPassword, h)
	if err != nil {
		return err
	}
	defer ancien.wipe()
	if !constantTimeEqual(ancien.commit, h.Commit) {
		return ErrBadPassword
	}
	dek, err := unwrapDEK(ancien, h)
	if err != nil {
		return err
	}
	defer wipe(dek)

	// L'en-tête d'origine est copié avant d'être touché : c'est lui qu'on
	// remettra en place si l'écriture échoue.
	ancienEntete := make([]byte, len(h.Raw))
	copy(ancienEntete, h.Raw)

	// Nouveau sel : sans lui, la clé maîtresse et son nonce d'enveloppe se
	// répéteraient d'un mot de passe à l'autre pour qui réutilise le même.
	sel := make([]byte, saltSize)
	if _, err := rand.Read(sel); err != nil {
		return fmt.Errorf("génération du sel: %w", err)
	}
	h.Salt = sel

	nouveau, err := deriveMasterV4(newPassword, h)
	if err != nil {
		return err
	}
	defer nouveau.wipe()
	h.Commit = nouveau.commit

	wrapped, err := wrapDEK(nouveau, h, dek)
	if err != nil {
		return err
	}
	h.Wrapped = wrapped

	entete := h.marshal()
	if len(entete) != headerSizeV4 {
		return fmt.Errorf("en-tête de %d octets, attendu %d", len(entete), headerSizeV4)
	}

	// Filet avant d'écrire. Une écriture de 117 octets à l'octet zéro n'est pas
	// garantie atomique : une erreur d'entrée-sortie à mi-chemin — disque plein,
	// partage réseau qui décroche — laisserait un en-tête mi-ancien mi-nouveau,
	// que ni l'ancien ni le nouveau mot de passe n'ouvriraient. Le fichier
	// serait perdu alors que sa clé est connue.
	//
	// L'ancien en-tête part donc à côté avant le remplacement, et n'est retiré
	// qu'une fois le nouveau sur le disque. Sa création est exclusive : elle sert
	// du même coup de verrou, et deux changements lancés en même temps sur le
	// même fichier ne peuvent plus s'entrelacer.
	if err := ecrireSauvegarde(path, ancienEntete); err != nil {
		return err
	}

	if _, err := f.WriteAt(entete, 0); err != nil {
		// Tentative de retour en arrière avec ce qu'on a encore en mémoire.
		// Réussie, elle rend le fichier à son ancien mot de passe ; échouée, la
		// sauvegarde reste sur le disque et le message dit quoi en faire.
		if _, errRetour := f.WriteAt(ancienEntete, 0); errRetour == nil {
			f.Sync()
			os.Remove(path + suffixeSauvegarde)
			return fmt.Errorf("réécriture de l'en-tête: %w (le fichier a été remis dans son état d'origine)", err)
		}
		return fmt.Errorf("réécriture de l'en-tête: %w\n  l'en-tête d'origine est dans %s%s : "+
			"le remettre en place avec « dd if=%s%s of=%s bs=%d count=1 conv=notrunc »",
			err, path, suffixeSauvegarde, path, suffixeSauvegarde, path, headerSizeV4)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("synchronisation sur disque: %w", err)
	}
	ferme = false
	if err := f.Close(); err != nil {
		return err
	}
	// Le nouvel en-tête est sur le disque : la sauvegarde n'a plus lieu d'être.
	if err := os.Remove(path + suffixeSauvegarde); err != nil {
		return fmt.Errorf("suppression de la sauvegarde d'en-tête: %w", err)
	}
	return nil
}

// ecrireSauvegarde dépose l'ancien en-tête à côté du fichier, en refusant
// d'écraser une sauvegarde existante.
//
// O_EXCL fait les deux à la fois : il protège une sauvegarde laissée par un
// changement interrompu — elle contient peut-être le seul en-tête encore valide
// — et il empêche deux processus de réécrire le même fichier en même temps.
func ecrireSauvegarde(path string, entete []byte) error {
	nom := path + suffixeSauvegarde
	f, err := os.OpenFile(nom, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s existe déjà : soit un changement de mot de passe est en cours, "+
			"soit le précédent a été interrompu — dans ce cas ce fichier contient l'en-tête d'origine, "+
			"à remettre en place avant de réessayer", nom)
	}
	if err != nil {
		return fmt.Errorf("sauvegarde de l'en-tête: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(entete); err != nil {
		os.Remove(nom)
		return fmt.Errorf("sauvegarde de l'en-tête: %w", err)
	}
	if err := f.Sync(); err != nil {
		os.Remove(nom)
		return fmt.Errorf("sauvegarde de l'en-tête: %w", err)
	}
	return nil
}
