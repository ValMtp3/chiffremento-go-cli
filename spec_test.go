package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
	motifTests = regexp.MustCompile(`^Tests : (.+)$`)
)

func TestSpecChaqueRegleAUnTestExistant(t *testing.T) {
	existants := testsDuDepot(t)

	f, err := os.Open("SPEC.md")
	if err != nil {
		t.Fatalf("SPEC.md illisible : %v", err)
	}
	defer f.Close()

	vus := map[string]bool{}
	regle := ""
	aDesTests := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ligne := sc.Text()
		if m := motifRegle.FindStringSubmatch(ligne); m != nil {
			regle = m[1]
			if vus[regle] {
				t.Errorf("%s est défini deux fois", regle)
			}
			vus[regle] = true
			continue
		}
		m := motifTests.FindStringSubmatch(ligne)
		if m == nil || regle == "" {
			continue
		}
		for _, nom := range strings.Split(m[1], ",") {
			nom = strings.TrimSpace(nom)
			if !existants[nom] {
				t.Errorf("%s cite %s, qui n'existe dans aucun fichier _test.go", regle, nom)
			}
			aDesTests[regle] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(vus) == 0 {
		t.Fatal("aucune règle trouvée dans SPEC.md : le format des titres a changé ?")
	}
	for r := range vus {
		if !aDesTests[r] {
			t.Errorf("%s n'a aucun test", r)
		}
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
