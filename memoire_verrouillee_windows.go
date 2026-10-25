//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// verrouillerPlateforme : VirtualLock, borné par la taille minimale de
// l'ensemble de travail du processus (quelques pages tiennent dedans).
func verrouillerPlateforme(b []byte) error {
	return windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

func deverrouillerPlateforme(b []byte) error {
	return windows.VirtualUnlock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}
