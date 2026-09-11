//go:build windows

package main

import "testing"

// TestNomUtilisableAdapteSousWindows : le pendant du test Unix. Sous Windows,
// nomUtilisable doit écarter ce que Win32 refuse, sinon le renommage échoue
// après coup et l'utilisateur garde un fichier au nom de sortie sans savoir
// pourquoi.
//
// Ce test ne s'exécute que sur un runner Windows. La logique elle-même est
// vérifiée partout par TestAdapterNomReglesWindows, qui prend les règles en
// paramètres ; celui-ci garantit en plus que c'est bien cette variante qui est
// compilée sur cette plateforme.
func TestNomUtilisableAdapteSousWindows(t *testing.T) {
	cas := map[string]string{
		"rapport.pdf":       "rapport.pdf",
		"rapport 2024?.pdf": "rapport 2024_.pdf",
		"aux.txt":           "_aux.txt",
		"note.":             "note",
		`a<b>c`:             "a_b_c",
	}
	for nom, attendu := range cas {
		if got := nomUtilisable(nom); got != attendu {
			t.Errorf("nomUtilisable(%q) = %q, attendu %q", nom, got, attendu)
		}
	}
}
