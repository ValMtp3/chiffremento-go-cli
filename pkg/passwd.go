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
	sauvegarde := path + suffixeSauvegarde
	if err := ecrireSauvegarde(sauvegarde, ancienEntete); err != nil {
		return err
	}

	// À partir d'ici la sauvegarde sort du registre des temporaires : elle devient
	// le seul en-tête dont on soit sûr, et un Ctrl+C ne doit surtout plus
	// l'effacer. Le prix est qu'une interruption la laisse sur le disque — voir
	// l'avertissement de révocation en tête de fichier.
	untrackTemp(sauvegarde)

	if _, err := ecrireAOctetZero(f, entete); err != nil {
		// Tentative de retour en arrière avec ce qu'on a encore en mémoire.
		//
		// Le Sync compte autant que le WriteAt : sans lui les octets ne sont que
		// dans le cache du système, et retirer la sauvegarde sur la foi d'une
		// écriture non confirmée détruirait le seul en-tête encore valide. Tant
		// que le retour en arrière n'est pas confirmé, la sauvegarde reste.
		if _, errRetour := ecrireAOctetZero(f, ancienEntete); errRetour == nil {
			if errSync := syncFichier(f); errSync == nil {
				if errRm := os.Remove(sauvegarde); errRm != nil {
					return fmt.Errorf("réécriture de l'en-tête: %w\n  le fichier a été remis dans son état d'origine ; "+
						"la sauvegarde %s n'a pas pu être retirée (%v) et peut être supprimée", err, sauvegarde, errRm)
				}
				return fmt.Errorf("réécriture de l'en-tête: %w (le fichier a été remis dans son état d'origine)", err)
			}
		}
		return fmt.Errorf("réécriture de l'en-tête: %w\n  l'en-tête d'origine est dans %s : "+
			"le remettre en place avec « dd if=%s of=%s bs=%d count=1 conv=notrunc »",
			err, sauvegarde, sauvegarde, path, headerSizeV4)
	}
	if err := syncFichier(f); err != nil {
		return fmt.Errorf("synchronisation sur disque: %w\n%s", err, conseilSauvegarde(path, sauvegarde))
	}
	ferme = false
	if err := f.Close(); err != nil {
		return fmt.Errorf("fermeture de %s: %w\n%s", path, err, conseilSauvegarde(path, sauvegarde))
	}
	// Le nouvel en-tête est sur le disque : la sauvegarde n'a plus lieu d'être.
	// C'est aussi ce qui retire du disque l'en-tête que l'ancien mot de passe
	// ouvrait, et donc la seule copie que ce changement pouvait révoquer.
	if err := os.Remove(sauvegarde); err != nil {
		return fmt.Errorf("suppression de la sauvegarde d'en-tête: %w\n  "+
			"le mot de passe est bien changé, mais %s reste sur le disque : "+
			"l'ancien mot de passe l'ouvre encore, à supprimer", err, sauvegarde)
	}
	return nil
}

// syncFichier et ecrireAOctetZero enveloppent les deux appels dont l'échec
// décide du sort du fichier. Indirections de paquet pour que les tests puissent
// simuler la panne : une clé USB retirée au bon millième de seconde ne se
// reproduit pas à la demande, et c'est précisément le chemin où une sauvegarde
// retirée trop tôt rend le fichier illisible avec les deux mots de passe.
var (
	syncFichier      = func(f *os.File) error { return f.Sync() }
	ecrireAOctetZero = func(f *os.File, b []byte) (int, error) { return f.WriteAt(b, 0) }
)

// conseilSauvegarde dit quoi faire quand le nouvel en-tête est écrit sans avoir
// été confirmé sur le disque, et que la sauvegarde est donc encore là.
//
// L'ordre des questions n'est pas indifférent : conseiller de remettre l'ancien
// en-tête sans vérifier d'abord annulerait un changement peut-être abouti, et
// ferait redemander un mot de passe que l'utilisateur croit avoir remplacé.
func conseilSauvegarde(path, sauvegarde string) string {
	return fmt.Sprintf("  l'en-tête d'origine est encore dans %s, et le nouveau est peut-être déjà en place.\n"+
		"  Vérifie d'abord lequel ouvre le fichier avec « chiffremento -mode verify -in %s » :\n"+
		"    — le nouveau mot de passe fonctionne : le changement est allé au bout, supprimer %s ;\n"+
		"    — l'ancien fonctionne : le fichier est intact, supprimer %s ;\n"+
		"    — aucun des deux : l'en-tête est incomplet, le restaurer avec\n"+
		"      « dd if=%s of=%s bs=%d count=1 conv=notrunc »",
		sauvegarde, path, sauvegarde, sauvegarde, sauvegarde, path, headerSizeV4)
}

// ecrireSauvegarde dépose l'ancien en-tête à côté du fichier, en refusant
// d'écraser une sauvegarde existante.
//
// O_EXCL fait les deux à la fois : il protège une sauvegarde laissée par un
// changement interrompu — elle contient peut-être le seul en-tête encore valide
// — et il empêche deux processus de réécrire le même fichier en même temps.
func ecrireSauvegarde(nom string, entete []byte) error {
	f, err := os.OpenFile(nom, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s existe déjà : soit un changement de mot de passe est en cours, "+
			"soit le précédent a été interrompu.\n"+
			"  Dans le second cas, vérifie lequel des deux mots de passe ouvre le fichier "+
			"(« chiffremento -mode verify ») avant d'y toucher : si c'est le nouveau, "+
			"le changement est allé au bout et ce fichier est à supprimer", nom)
	}
	if err != nil {
		return fmt.Errorf("sauvegarde de l'en-tête: %w", err)
	}
	// Suivi le temps de l'écriture seulement : ici le fichier chiffré est encore
	// intact, donc une sauvegarde à moitié écrite ne sert à rien et vaut mieux
	// nettoyée qu'abandonnée. L'appelant la sort du registre avant de toucher au
	// fichier, quand elle devient le filet.
	trackTempFile(nom, f)

	// Le Close vient avant le Remove, et non par un defer : Windows refuse de
	// supprimer un fichier encore ouvert, et l'erreur passerait inaperçue —
	// laissant derrière une sauvegarde tronquée que le message d'erreur ci-dessus
	// présenterait comme un en-tête valide.
	abandon := func(cause error) error {
		f.Close()
		if err := os.Remove(nom); err != nil {
			untrackTemp(nom)
			return fmt.Errorf("sauvegarde de l'en-tête: %w (le fichier incomplet %s n'a pas pu être retiré : "+
				"le supprimer avant de réessayer)", cause, nom)
		}
		untrackTemp(nom)
		return fmt.Errorf("sauvegarde de l'en-tête: %w", cause)
	}
	if _, err := f.Write(entete); err != nil {
		return abandon(err)
	}
	if err := syncFichier(f); err != nil {
		return abandon(err)
	}
	if err := f.Close(); err != nil {
		return abandon(err)
	}
	// Le descripteur est fermé : le registre garde le chemin, plus le descripteur.
	trackTempFile(nom, nil)
	return nil
}
