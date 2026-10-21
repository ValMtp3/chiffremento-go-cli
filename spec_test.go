package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// La spec ne vaut que si chaque règle est réellement vérifiée. Ce test relie
// SPEC.md au code de test : une règle sans test, ou qui cite un test disparu
// (renommé, supprimé), fait échouer la suite. C'est ce qui empêche une
// refonte de retirer une vérification sans que personne ne le voie.
var (
	motifRegle = regexp.MustCompile(`^### (R-[A-Z]+-\d{2}) — .+$`)
	// Une règle retirée est barrée, pas renumérotée : son identifiant reste
	// pris, et ses éventuelles lignes « Tests : » ne comptent plus.
	motifRegleBarree = regexp.MustCompile(`^### ~~(R-[A-Z]+-\d{2}) — .+~~$`)
	motifTests       = regexp.MustCompile(`^Tests : (.+)$`)
)

func TestSpecChaqueRegleAUnTestExistant(t *testing.T) {
	existants := testsDuDepot(t)

	f, err := os.Open("SPEC.md")
	if err != nil {
		t.Fatalf("SPEC.md illisible : %v", err)
	}
	defer f.Close()

	regles, erreurs := lireSpec(f)
	for _, e := range erreurs {
		t.Error(e)
	}
	if len(regles) == 0 {
		t.Fatal("aucune règle trouvée dans SPEC.md : le format des titres a changé ?")
	}
	for regle, tests := range regles {
		if len(tests) == 0 {
			t.Errorf("%s n'a aucun test", regle)
		}
		for _, nom := range tests {
			if !existants[nom] {
				t.Errorf("%s cite %s, qui n'existe dans aucun fichier _test.go", regle, nom)
			}
		}
	}
}

// lireSpec rend, pour chaque règle en vigueur, les noms de tests qu'elle cite,
// et les erreurs de forme (identifiant défini deux fois, lecture impossible).
// Une règle barrée n'apparaît pas dans le résultat mais garde son identifiant.
func lireSpec(r io.Reader) (regles map[string][]string, erreurs []string) {
	regles = map[string][]string{}
	vus := map[string]bool{}
	regle := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		ligne := sc.Text()
		barree := false
		m := motifRegle.FindStringSubmatch(ligne)
		if m == nil {
			m = motifRegleBarree.FindStringSubmatch(ligne)
			barree = m != nil
		}
		if m != nil {
			if vus[m[1]] {
				erreurs = append(erreurs, m[1]+" est défini deux fois")
			}
			vus[m[1]] = true
			if barree {
				regle = ""
			} else {
				regle = m[1]
				if _, ok := regles[regle]; !ok {
					regles[regle] = nil
				}
			}
			continue
		}
		m = motifTests.FindStringSubmatch(ligne)
		if m == nil || regle == "" {
			continue
		}
		for _, nom := range strings.Split(m[1], ",") {
			if nom = strings.TrimSpace(nom); nom != "" {
				regles[regle] = append(regles[regle], nom)
			}
		}
	}
	if err := sc.Err(); err != nil {
		erreurs = append(erreurs, "lecture de la spec : "+err.Error())
	}
	return regles, erreurs
}

// TestLireSpec vérifie l'analyse elle-même : si elle se trompait, la
// traçabilité passerait au vert sans rien garantir.
func TestLireSpec(t *testing.T) {
	cas := []struct {
		nom     string
		spec    string
		regles  map[string][]string
		erreurs int
	}{
		{"règle et tests", "### R-CLI-01 — a\nTests : TestA, TestB\n",
			map[string][]string{"R-CLI-01": {"TestA", "TestB"}}, 0},
		{"règle sans test", "### R-CLI-01 — a\nTests :\n",
			map[string][]string{"R-CLI-01": nil}, 0},
		{"virgule finale et espaces", "### R-CLI-01 — a\nTests : TestA, ,  TestB ,\n",
			map[string][]string{"R-CLI-01": {"TestA", "TestB"}}, 0},
		{"règle barrée : ses tests ne passent pas à la précédente",
			"### R-CLI-01 — a\nTests : TestA\n### ~~R-CLI-02 — b~~\nTests : TestB\n",
			map[string][]string{"R-CLI-01": {"TestA"}}, 0},
		{"identifiant barré puis réutilisé", "### ~~R-CLI-01 — a~~\n### R-CLI-01 — b\n",
			map[string][]string{"R-CLI-01": nil}, 1},
		{"doublon", "### R-CLI-01 — a\nTests : TestA\n### R-CLI-01 — b\nTests : TestB\n",
			map[string][]string{"R-CLI-01": {"TestA", "TestB"}}, 1},
		{"tests avant toute règle", "Tests : TestA\n", map[string][]string{}, 0},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			regles, erreurs := lireSpec(strings.NewReader(c.spec))
			if len(erreurs) != c.erreurs {
				t.Errorf("erreurs = %v, attendu %d", erreurs, c.erreurs)
			}
			if !reflect.DeepEqual(regles, c.regles) {
				t.Errorf("règles = %#v, attendu %#v", regles, c.regles)
			}
		})
	}
}

// testsDuDepot rend le nom de toutes les fonctions Test et Fuzz du dépôt,
// lues dans les sources plutôt qu'à l'exécution : une règle peut citer un
// test d'un autre paquet ou réservé à un système.
func testsDuDepot(t *testing.T) map[string]bool {
	t.Helper()
	noms := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fichier, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range fichier.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil &&
				(strings.HasPrefix(fn.Name.Name, "Test") || strings.HasPrefix(fn.Name.Name, "Fuzz")) {
				noms[fn.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return noms
}
