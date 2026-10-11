//go:build !darwin && !linux

package pkg

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Ailleurs (Windows, BSD) : fsync par fichier, et synchronisation des
// répertoires là où le système le permet (best effort, voir syncDir). Plus
// lent sur beaucoup de petits fichiers, mais sans primitive plus légère
// portable.

func syncExtrait(f *os.File) error { return f.Sync() }

func rendreDurable(racine string) error {
	err := filepath.WalkDir(racine, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			syncDir(p)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("synchronisation de l'arborescence: %w", err)
	}
	return nil
}
