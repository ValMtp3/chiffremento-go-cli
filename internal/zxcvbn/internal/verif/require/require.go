// Package require remplace le strict nécessaire de testify/require pour les
// tests de la copie de zxcvbn : un seul contrôle, qui arrête le test.
package require

import "testing"

// NoError arrête le test tout de suite si err n'est pas nil.
func NoError(t testing.TB, err error, msgAndArgs ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("erreur inattendue : %v %v", err, msgAndArgs)
	}
}
