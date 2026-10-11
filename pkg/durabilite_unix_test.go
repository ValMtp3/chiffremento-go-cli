//go:build darwin || linux

package pkg

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSyncNonSupporte : sur un volume exFAT/FAT, un partage SMB ou NFS, un
// système FUSE, F_FULLFSYNC, fsync ou syncfs peuvent être refusés. main
// n'appelait rien et l'extraction réussissait ; l'échec de la synchronisation
// ne doit donc pas faire échouer l'extraction quand le système dit seulement
// « je ne sais pas faire ». Une vraie erreur d'écriture, elle, reste fatale.
func TestSyncNonSupporte(t *testing.T) {
	cas := []struct {
		err     error
		attendu bool
	}{
		{nil, false},
		{unix.ENOTSUP, true},
		{unix.EOPNOTSUPP, true},
		{unix.ENOTTY, true},
		{unix.EINVAL, true},
		{unix.ENOSYS, true},
		{fmt.Errorf("vidage du cache disque: %w", unix.ENOTSUP), true},
		{unix.EIO, false},
		{unix.ENOSPC, false},
		{errors.New("autre"), false},
	}
	for _, c := range cas {
		if got := syncNonSupporte(c.err); got != c.attendu {
			t.Errorf("syncNonSupporte(%v) = %v, attendu %v", c.err, got, c.attendu)
		}
	}
}
