//go:build windows

package main

// ttyDevice : équivalent Windows du terminal de contrôle. CONIN$ s'ouvre en
// lecture même quand l'entrée standard a été redirigée.
// Variable et non constante, comme sur les autres systèmes, pour les tests.
var ttyDevice = "CONIN$"
