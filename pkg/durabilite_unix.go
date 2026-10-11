//go:build darwin || linux

package pkg

import (
	"errors"

	"golang.org/x/sys/unix"
)

// syncNonSupporte dit si une synchronisation a échoué parce que le volume ne
// la connaît pas (exFAT/FAT, SMB, NFS, FUSE), et non parce que l'écriture a
// raté. Dans ce cas la synchronisation est best effort : avant elle, rien
// n'était synchronisé et l'extraction réussissait ; la faire échouer serait une
// régression. EIO, ENOSPC et le reste restent fatals.
func syncNonSupporte(err error) bool {
	for _, e := range []error{unix.ENOTSUP, unix.EOPNOTSUPP, unix.ENOTTY, unix.EINVAL, unix.ENOSYS} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// sansEINTR relance un appel interrompu par un signal, comme le fait
// os.File.Sync en interne.
func sansEINTR(appel func() error) error {
	for {
		if err := appel(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// fsyncTolere fait un fsync simple, toléré sur un volume qui ne le connaît pas.
func fsyncTolere(fd int) error {
	err := sansEINTR(func() error { return unix.Fsync(fd) })
	if syncNonSupporte(err) {
		return nil
	}
	return err
}
