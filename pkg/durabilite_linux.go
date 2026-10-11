//go:build linux

package pkg

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Sous Linux, un seul syncfs à la fin écrit tout ce qui est en attente sur le
// système de fichiers — contenu des fichiers et entrées de répertoire — et
// attend que ce soit fait. Pas de fsync par fichier : sur un dossier de
// milliers de petits fichiers, il multipliait les attentes du disque.

// syncExtrait ne fait rien : le syncfs de rendreDurable couvre le fichier.
func syncExtrait(*os.File) error { return nil }

// rendreDurable écrit sur le disque tout le système de fichiers de racine.
func rendreDurable(racine string) error {
	dir, err := os.Open(racine)
	if err != nil {
		return fmt.Errorf("synchronisation de l'arborescence: %w", err)
	}
	defer dir.Close()
	err = sansEINTR(func() error { return unix.Syncfs(int(dir.Fd())) })
	// Certains systèmes FUSE refusent syncfs : best effort, comme avant que
	// l'extraction ne soit synchronisée.
	if err != nil && !syncNonSupporte(err) {
		return fmt.Errorf("synchronisation de l'arborescence: %w", err)
	}
	return nil
}
