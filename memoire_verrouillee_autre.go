//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly || windows)

package main

import "errors"

var errVerrouillageIndisponible = errors.New("verrouillage de la mémoire indisponible sur ce système")

// Ailleurs, pas de verrouillage : la phrase est gardée dans une allocation
// ordinaire.
func verrouillerPlateforme([]byte) error { return errVerrouillageIndisponible }

func deverrouillerPlateforme([]byte) error { return nil }
