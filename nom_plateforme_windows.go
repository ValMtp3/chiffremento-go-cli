//go:build windows

package main

// nomUtilisable adapte le nom aux règles de Win32 : caractères interdits,
// caractères de contrôle, noms de périphériques réservés, et points ou espaces
// en fin de nom que le système rognerait de lui-même.
func nomUtilisable(nom string) string {
	return adapterNom(nom, caracteresInterditsWindows, nomsReservesWindows, true)
}
