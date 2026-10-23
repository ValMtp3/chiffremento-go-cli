package zxcvbn

import (
	"testing"
	"unicode/utf8"
)

// Coût d'une frappe : l'interface réévalue tout le mot de passe à chaque
// touche. Les listes sont chargées avant de chronométrer (Precharger), comme
// dans l'interface. Une variante ASCII et une variante accentuée par longueur :
// la recherche sans accent ne doit coûter que sur les morceaux accentués.
func BenchmarkFrappe(b *testing.B) {
	for _, cas := range []struct{ nom, motDePasse string }{
		{"12-ascii", "Lefevre1990!"},
		{"12-accents", "Lefèvre1990!"},
		{"64-ascii", "Helene-Dupont-Menard-lefevre-soleil-1990-Francoise-azerty-martin"},
		{"64-accents", "Hélène-Dupont-Ménard-lefèvre-soleil-1990-Françoise-azerty-martin"},
	} {
		if n := utf8.RuneCountInString(cas.motDePasse); n != 12 && n != 64 {
			b.Fatalf("%s : %d caractères", cas.nom, n)
		}
		b.Run(cas.nom, func(b *testing.B) {
			Precharger()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				PasswordStrength(cas.motDePasse, nil)
			}
		})
	}
}
