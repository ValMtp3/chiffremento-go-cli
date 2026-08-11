//go:build !windows

package main

// ttyDevice est le terminal de contrôle, utilisé pour demander un mot de passe
// quand l'entrée standard porte déjà les données (-in -).
// C'est une variable et non une constante pour que les tests puissent la faire
// pointer sur un pseudo-terminal.
var ttyDevice = "/dev/tty"
