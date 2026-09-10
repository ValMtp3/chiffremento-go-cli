package main

import "testing"

// La logique d'adaptation est testée directement, avec les règles de Windows
// passées en paramètres : sans quoi elle ne serait vérifiée que sur un runner
// Windows, et c'est précisément la plateforme dont les échecs ont déjà échappé
// à la relecture trois fois dans ce projet.
func TestAdapterNomReglesWindows(t *testing.T) {
	adapte := func(nom string) string {
		return adapterNom(nom, caracteresInterditsWindows, nomsReservesWindows, true)
	}

	cas := []struct {
		nom      string
		attendu  string
		pourquoi string
	}{
		{"rapport.pdf", "rapport.pdf", "un nom ordinaire ne doit pas bouger"},
		{"rapport 2024?.pdf", "rapport 2024_.pdf", "le point d'interrogation est refusé par Win32"},
		{`fichier<1>"2"|3*.txt`, "fichier_1__2__3_.txt", "tous les caractères interdits sont remplacés"},
		{"aux.txt", "_aux.txt", "aux est un périphérique, extension comprise"},
		{"CON", "_CON", "la casse n'y change rien"},
		{"com9.log", "_com9.log", "les ports série aussi"},
		{"console.txt", "console.txt", "« console » n'est pas « con » : pas de faux positif"},
		{"note.", "note", "Windows rogne le point final de lui-même"},
		{"note   ", "note", "et les espaces de fin"},
		{"ne\x01te.txt", "ne_te.txt", "les caractères de contrôle sont illisibles et refusés"},
		{"...", "_", "un nom qui disparaît entièrement laisse un nom utilisable"},
		{"", "", "le nom vide est rendu tel quel, l'appelant décide"},
	}
	for _, c := range cas {
		if got := adapte(c.nom); got != c.attendu {
			t.Errorf("adapterNom(%q) = %q, attendu %q — %s", c.nom, got, c.attendu, c.pourquoi)
		}
	}
}

// TestAdapterNomNeTouchePasSousUnix : la variante Unix doit être l'identité,
// sinon un renommage qui marchait se mettrait à produire un autre nom.
func TestNomUtilisableIdentiteSousUnix(t *testing.T) {
	for _, nom := range []string{"rapport.pdf", "rapport 2024?.pdf", "aux.txt", "note.", `a<b>c`} {
		if got := nomUtilisable(nom); got != nom {
			t.Errorf("nomUtilisable(%q) = %q : le nom doit rester intact hors Windows", nom, got)
		}
	}
}
