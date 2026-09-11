//go:build !windows

package main

import "testing"

// TestNomUtilisableIdentiteSousUnix : hors Windows, le nom doit ressortir
// intact. Un système POSIX n'interdit que « / » et l'octet nul, tous deux déjà
// écartés à la lecture des métadonnées — adapter davantage reviendrait à
// dégrader un renommage qui fonctionnait.
//
// Le fichier porte une contrainte de compilation : sans elle, ce test tournait
// aussi sous Windows, où nomUtilisable adapte le nom à dessein. Il y échouait
// donc en annonçant un défaut du produit là où il n'y avait qu'un test écrit
// pour la mauvaise plateforme.
func TestNomUtilisableIdentiteSousUnix(t *testing.T) {
	for _, nom := range []string{"rapport.pdf", "rapport 2024?.pdf", "aux.txt", "note.", `a<b>c`} {
		if got := nomUtilisable(nom); got != nom {
			t.Errorf("nomUtilisable(%q) = %q : le nom doit rester intact hors Windows", nom, got)
		}
	}
}
