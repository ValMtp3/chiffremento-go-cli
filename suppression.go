package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"chiffremento-cli/pkg"

	"github.com/charmbracelet/huh"
)

// Suppression de ce qui vient d'être remplacé.
//
// Chiffrer puis effacer l'original, déchiffrer puis effacer le chiffré : c'est
// le geste qui suit naturellement l'opération, et le faire à la main dans un
// autre terminal fait courir plus de risques que de le proposer ici.
//
// Trois règles tiennent cette partie du code, parce que c'est la seule qui
// détruise quelque chose :
//
//   - la question vient après le résultat, jamais avant. L'utilisateur a vu le
//     ✓ et le nom de ce qui a été produit quand il décide ;
//   - « garder » est la réponse sous le curseur, toujours ;
//   - avant d'effacer un original, le chiffré est relu et authentifié en
//     entier. Une écriture atomique ne prouve pas qu'un disque rendra les mêmes
//     octets, et l'original est la seule autre copie.

// suppressionRefusee explique pourquoi la question n'est pas posée. Ce n'est pas
// une erreur : l'opération a réussi, seule la proposition est écartée.
type suppressionRefusee string

// supprimerOriginal propose d'effacer ce qui vient d'être chiffré.
//
// La vérification préalable a un coût réel — une seconde dérivation Argon2 et
// une relecture complète — et c'est délibéré : il achète la certitude que le
// fichier gardé rendra bien ce que l'original contenait.
func supprimerOriginal(source, chiffre string, password []byte, estDossier bool) error {
	if raison := suppressionPossible(source, chiffre, estDossier); raison != "" {
		fmt.Printf("  %s\n\n", styleFaint.Render(string(raison)))
		return nil
	}

	titre, detail := libelleSuppression(source, estDossier)
	ok, err := demanderSuppression(titre, detail)
	if err != nil || !ok {
		return err
	}

	if err := verifierAvantSuppression(chiffre, password); err != nil {
		// Le chiffré ne se relit pas : c'est plus grave qu'une suppression
		// manquée, et ça ne se murmure pas dans un coin de l'écran. L'original,
		// lui, est toujours là — c'est maintenant la seule copie lisible.
		return fmt.Errorf("%s ne se relit pas (%w)\n  %s n'a pas été supprimé : c'est la seule copie lisible",
			filepath.Base(chiffre), err, filepath.Base(source))
	}

	return effacer(source, estDossier)
}

// supprimerChiffre propose d'effacer le .chto une fois son contenu ressorti.
//
// Rien à vérifier ici : le déchiffrement vient de lire le fichier en entier et
// l'AEAD a authentifié chaque bloc. Le clair sur le disque est la preuve.
func supprimerChiffre(chiffre string) error {
	titre := "supprimer le fichier chiffré " + filepath.Base(chiffre) + " ?"
	detail := "son contenu vient d'en sortir, authentifié\n" + mentionSupport
	ok, err := demanderSuppression(titre, detail)
	if err != nil || !ok {
		return err
	}
	return effacer(chiffre, false)
}

// mentionSupport dit ce que « supprimer » veut dire, et surtout ce que ça ne
// veut pas dire : l'entrée disparaît du dossier, les octets restent sur le
// support jusqu'à réécriture. Sur un SSD, où le contrôleur décide seul de ce
// qu'il réécrit, aucun outil ne peut promettre mieux depuis l'espace
// utilisateur — mieux vaut le dire que de laisser croire à un effacement.
const mentionSupport = "l'entrée disparaît du dossier ; les données restent sur le support jusqu'à réécriture"

// libelleSuppression annonce précisément ce qui va disparaître. Pour un
// dossier, le nombre de fichiers est compté et affiché : « supprimer photos/ »
// et « supprimer photos/ et ses 248 fichiers » ne se lisent pas pareil.
func libelleSuppression(source string, estDossier bool) (titre, detail string) {
	nom := filepath.Base(source)
	if !estDossier {
		return "supprimer l'original " + nom + " ?",
			"le chiffré est relu et authentifié avant, puis la suppression est définitive\n" + mentionSupport
	}

	titre = "supprimer le dossier " + nom + string(os.PathSeparator) + " ?"
	if n, err := compterFichiers(source); err == nil {
		titre = fmt.Sprintf("supprimer le dossier %s%c et ses %d fichiers ?", nom, os.PathSeparator, n)
	}
	return titre, "l'arborescence entière sera effacée après relecture du chiffré, définitivement\n" + mentionSupport
}

// compterFichiers dit combien d'entrées régulières porte une arborescence. Un
// échec n'est pas fatal : l'appelant se rabat sur un libellé sans nombre.
func compterFichiers(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	return n, err
}

// suppressionPossible écarte les cas où la question ne doit pas être posée.
//
// Le seul, mais il est vicieux : chiffrer « . » ou un chemin qui remonte dépose
// le .chto *à l'intérieur* du dossier proposé à la suppression. Répondre
// « supprimer » emporterait alors le chiffré avec l'original, et il ne
// resterait rien du tout.
func suppressionPossible(source, chiffre string, estDossier bool) suppressionRefusee {
	if !estDossier {
		return ""
	}
	dedans, err := contient(source, chiffre)
	if err != nil {
		return suppressionRefusee("suppression non proposée : " + err.Error())
	}
	if dedans {
		return "le fichier chiffré est à l'intérieur du dossier : suppression non proposée"
	}
	return ""
}

// contient dit si cible se trouve dans racine, ou est racine elle-même.
func contient(racine, cible string) (bool, error) {
	r, err := filepath.Abs(racine)
	if err != nil {
		return false, err
	}
	c, err := filepath.Abs(cible)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(r, c)
	if err != nil {
		return false, err
	}
	return rel == "." || !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != "..", nil
}

// demanderSuppression pose la question, curseur sur « garder ».
func demanderSuppression(titre, detail string) (bool, error) {
	supprimer := false
	champ := questionFermee(titre, detail, "supprimer", "garder", &supprimer)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	// Pas d'ancre : l'opération est faite, il n'y a plus d'écran où revenir.
	if err := lancerEtape(form, nil); err != nil {
		return false, err
	}
	return supprimer, nil
}

// verifierAvantSuppression relit le chiffré de bout en bout avec le mot de
// passe qui vient de servir. L'écran de progression est celui de l'opération
// « vérifier » : c'est exactement le même travail.
func verifierAvantSuppression(chiffre string, password []byte) error {
	d, err := pkg.Inspect(chiffre)
	if err != nil {
		return err
	}
	info := jobInfo{
		Action:  "vérification",
		In:      chiffre,
		Out:     "(rien, contrôle avant suppression)",
		AEAD:    d.Algo,
		KDF:     d.KDF,
		Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
		Success: "chiffré relu et authentifié",
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Verify(chiffre, password, pkg.Options{Progress: p})
	})
}

// effacer retire le fichier ou l'arborescence, et le dit.
func effacer(chemin string, estDossier bool) error {
	var err error
	if estDossier {
		err = os.RemoveAll(chemin)
	} else {
		err = os.Remove(chemin)
	}
	if err != nil {
		return fmt.Errorf("suppression de %s: %w", chemin, err)
	}
	fmt.Printf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(chemin+" supprimé"))
	return nil
}
