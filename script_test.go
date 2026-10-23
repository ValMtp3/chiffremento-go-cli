package main

import (
	"os"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

// TestMain fait du binaire de test un chiffremento complet, pour deux usages :
//   - testscript installe la commande « chiffremento » dans le PATH des
//     scripts de testdata/script ;
//   - les tests de bout en bout du pty relancent ce même binaire avec
//     CHIFFREMENTO_E2E_MAIN=1.
//
// Dans les deux cas c'est le vrai main() qui tourne, drapeaux et codes de
// sortie compris : c'est le contrat que voient les scripts des utilisateurs.
func TestMain(m *testing.M) {
	if os.Getenv("CHIFFREMENTO_E2E_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	testscript.Main(m, map[string]func(){"chiffremento": main})
}

// TestScripts rejoue chaque script de testdata/script contre le vrai binaire.
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// crlf FICHIER : réécrit FICHIER avec des fins de ligne Windows. Le
			// \r n'est pas écrit dans le .txtar : git ou un éditeur peut
			// normaliser les fins de ligne.
			"crlf": func(ts *testscript.TestScript, neg bool, args []string) {
				if neg || len(args) != 1 {
					ts.Fatalf("usage: crlf FICHIER")
				}
				contenu := ts.ReadFile(args[0])
				contenu = strings.ReplaceAll(contenu, "\n", "\r\n")
				ts.Check(os.WriteFile(ts.MkAbs(args[0]), []byte(contenu), 0o600))
			},
		},
	})
}
