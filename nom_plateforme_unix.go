//go:build !windows

package main

// nomUtilisable rend le nom inchangé : un système POSIX n'interdit que « / » et
// l'octet nul, tous deux déjà écartés à la lecture des métadonnées.
func nomUtilisable(nom string) string { return nom }
