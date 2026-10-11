package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/fs"
	"path/filepath"
)

// Instantané de la source, pris avant le chiffrement et comparé juste avant de
// l'effacer.
//
// La relecture du chiffré prouve qu'il est intact, pas qu'il contient tout ce
// qui va disparaître. Un fichier ajouté au dossier pendant le chiffrement — ou
// pendant que l'utilisateur lit la question — n'est pas dans l'archive, et
// os.RemoveAll l'emportait avec le reste. Au moindre écart, on refuse.
//
// Le relevé est une empreinte SHA-256 calculée au fil du parcours, pas une
// liste : sa taille ne dépend pas du dossier. Une liste par entrée coûtait
// ~148 octets par fichier (15 Mo pour 100 000 fichiers). La contrepartie : un
// écart se détecte, mais ne se nomme pas.

// instantane est l'empreinte d'une arborescence à un instant donné.
type instantane struct {
	empreinte [sha256.Size]byte
}

// photographier relève l'état de chemin, fichier ou arborescence : pour chaque
// entrée, son chemin relatif et son type, plus la taille et la date d'un
// fichier. Pour un dossier, seule la présence compte : sa date bouge dès qu'on
// y crée quoi que ce soit, et ce changement-là se voit déjà par l'entrée créée.
//
// WalkDir parcourt en ordre lexical : deux relevés d'une même arborescence
// hachent les mêmes octets dans le même ordre. Les liens symboliques ne sont
// pas suivis — ils sont refusés au chiffrement de toute façon.
func photographier(chemin string) (*instantane, error) {
	h := sha256.New()
	var tampon [8]byte
	ecrireEntier := func(v int64) {
		binary.BigEndian.PutUint64(tampon[:], uint64(v))
		h.Write(tampon[:])
	}

	err := filepath.WalkDir(chemin, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(chemin, p)
		if err != nil {
			return err
		}
		// La longueur précède le nom : « ab » + « c » et « a » + « bc » ne
		// doivent pas produire les mêmes octets.
		ecrireEntier(int64(len(rel)))
		h.Write([]byte(rel))
		if d.IsDir() {
			h.Write([]byte{'d'})
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h.Write([]byte{'f'})
		ecrireEntier(info.Size())
		ecrireEntier(info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("relevé de %s: %w", chemin, err)
	}

	photo := &instantane{}
	h.Sum(photo.empreinte[:0])
	return photo, nil
}

// verifierInchange compare chemin à l'instantané pris avant le chiffrement.
func verifierInchange(avant *instantane, chemin string) error {
	apres, err := photographier(chemin)
	if err != nil {
		return err
	}
	if apres.empreinte != avant.empreinte {
		return fmt.Errorf("%s a changé depuis le chiffrement : un fichier a été ajouté, retiré ou modifié",
			filepath.Base(chemin))
	}
	return nil
}
