package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Instantané de la source, pris avant le chiffrement et comparé juste avant de
// l'effacer.
//
// La relecture du chiffré prouve qu'il est intact, pas qu'il contient tout ce
// qui va disparaître. Un fichier ajouté au dossier pendant le chiffrement — ou
// pendant que l'utilisateur lit la question — n'est pas dans l'archive, et
// os.RemoveAll l'emportait avec le reste. Au moindre écart, on refuse.

// etatEntree est ce qui distingue une entrée qui a changé. Pour un dossier,
// seule la présence compte : sa date bouge dès qu'on y crée quoi que ce soit,
// et ce changement-là est déjà signalé par l'entrée ajoutée elle-même.
type etatEntree struct {
	dossier bool
	taille  int64
	modif   time.Time
}

// egal compare deux états. time.Time se compare par Equal, pas par == : deux
// dates identiques peuvent différer par leur fuseau ou leur horloge monotone.
func (e etatEntree) egal(autre etatEntree) bool {
	return e.dossier == autre.dossier && e.taille == autre.taille && e.modif.Equal(autre.modif)
}

// instantane associe chaque chemin relatif à son état.
type instantane map[string]etatEntree

// photographier relève l'état de chemin, fichier ou arborescence. Les liens
// symboliques ne sont pas suivis : ils sont refusés au chiffrement de toute
// façon, et les suivre ferait décrire autre chose que ce qui sera effacé.
func photographier(chemin string) (instantane, error) {
	photo := instantane{}
	err := filepath.WalkDir(chemin, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(chemin, p)
		if err != nil {
			return err
		}
		etat := etatEntree{dossier: d.IsDir()}
		if !etat.dossier {
			etat.taille = info.Size()
			etat.modif = info.ModTime()
		}
		photo[rel] = etat
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("relevé de %s: %w", chemin, err)
	}
	return photo, nil
}

// maxEcartsAffiches borne la liste des écarts dans le message : au-delà, le
// nombre suffit à comprendre qu'il ne faut rien effacer.
const maxEcartsAffiches = 5

// verifierInchange compare chemin à l'instantané pris avant le chiffrement, et
// nomme ce qui a changé.
func verifierInchange(avant instantane, chemin string) error {
	apres, err := photographier(chemin)
	if err != nil {
		return err
	}

	var ecarts []string
	for rel, etat := range apres {
		precedent, existait := avant[rel]
		switch {
		case !existait:
			ecarts = append(ecarts, rel+" (ajouté)")
		case !precedent.egal(etat):
			ecarts = append(ecarts, rel+" (modifié)")
		}
	}
	for rel := range avant {
		if _, existe := apres[rel]; !existe {
			ecarts = append(ecarts, rel+" (retiré)")
		}
	}
	if len(ecarts) == 0 {
		return nil
	}

	slices.Sort(ecarts)
	affiches := ecarts
	if len(affiches) > maxEcartsAffiches {
		affiches = affiches[:maxEcartsAffiches]
	}
	detail := strings.Join(affiches, ", ")
	if reste := len(ecarts) - len(affiches); reste > 0 {
		detail += fmt.Sprintf(" et %d autre(s)", reste)
	}
	return fmt.Errorf("%s a changé depuis le chiffrement : %s", filepath.Base(chemin), detail)
}
