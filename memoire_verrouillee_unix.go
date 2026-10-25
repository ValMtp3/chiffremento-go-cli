//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package main

import "golang.org/x/sys/unix"

// verrouillerPlateforme : mlock, refusé au-delà de RLIMIT_MEMLOCK (une page
// tient dans la limite par défaut de macOS et Linux).
func verrouillerPlateforme(b []byte) error { return unix.Mlock(b) }

func deverrouillerPlateforme(b []byte) error { return unix.Munlock(b) }
