// Commande genlistes : produit les listes de mots embarquées par le paquet
// frequency (un mot par ligne, compressées en zstd).
//
// Elle lit le littéral Go de zxcvbn v1.0.1 (frequency/lists.go) avec
// go/parser : aucun import de l'amont, le fichier n'est jamais compilé.
//
// Usage (depuis la racine du dépôt) :
//
//	go run ./internal/zxcvbn/outils/genlistes \
//	    -amont "$(go env GOMODCACHE)/github.com/trustelem/zxcvbn@v1.0.1/frequency/lists.go" \
//	    -sortie internal/zxcvbn/frequency/listes
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	nomVariableAmont = "FrequencyLists"
	suffixeSortie    = ".txt.zst"
)

func main() {
	amont := flag.String("amont", "", "chemin de frequency/lists.go de zxcvbn v1.0.1")
	sortie := flag.String("sortie", "", "dossier où écrire les fichiers .txt.zst")
	flag.Parse()

	if *amont == "" || *sortie == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := generer(*amont, *sortie); err != nil {
		fmt.Fprintln(os.Stderr, "genlistes :", err)
		os.Exit(1)
	}
}

func generer(cheminAmont, dossierSortie string) error {
	listes, err := lireListesAmont(cheminAmont)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dossierSortie, 0o755); err != nil {
		return err
	}
	encodeur, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return err
	}
	defer encodeur.Close()

	for nom, mots := range listes {
		texte, err := versTexte(nom, mots)
		if err != nil {
			return err
		}
		chemin := filepath.Join(dossierSortie, nom+suffixeSortie)
		if err := os.WriteFile(chemin, encodeur.EncodeAll(texte, nil), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s : %d mots, %d octets de texte\n", chemin, len(mots), len(texte))
	}
	return nil
}

// versTexte écrit un mot par ligne ("\n"). Un mot vide ou contenant un saut de
// ligne casserait le découpage à la lecture : on refuse.
func versTexte(nom string, mots []string) ([]byte, error) {
	var tampon bytes.Buffer
	for i, mot := range mots {
		if mot == "" || strings.ContainsAny(mot, "\r\n") {
			return nil, fmt.Errorf("liste %s, mot n°%d (%q) : vide ou avec saut de ligne", nom, i+1, mot)
		}
		tampon.WriteString(mot)
		tampon.WriteByte('\n')
	}
	return tampon.Bytes(), nil
}

// lireListesAmont extrait le littéral `var FrequencyLists = map[string][]string{...}`.
func lireListesAmont(chemin string) (map[string][]string, error) {
	fset := token.NewFileSet()
	fichier, err := parser.ParseFile(fset, chemin, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, decl := range fichier.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			valeur, ok := spec.(*ast.ValueSpec)
			if !ok || len(valeur.Names) != 1 || valeur.Names[0].Name != nomVariableAmont || len(valeur.Values) != 1 {
				continue
			}
			litteral, ok := valeur.Values[0].(*ast.CompositeLit)
			if !ok {
				return nil, errors.New(nomVariableAmont + " n'est pas un littéral")
			}
			return listesDepuisLitteral(litteral)
		}
	}
	return nil, fmt.Errorf("variable %s introuvable dans %s", nomVariableAmont, chemin)
}

func listesDepuisLitteral(litteral *ast.CompositeLit) (map[string][]string, error) {
	listes := make(map[string][]string, len(litteral.Elts))
	for _, elt := range litteral.Elts {
		paire, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return nil, errors.New("élément de map inattendu")
		}
		nom, err := chaine(paire.Key)
		if err != nil {
			return nil, err
		}
		valeurs, ok := paire.Value.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("liste %s : littéral attendu", nom)
		}
		mots := make([]string, 0, len(valeurs.Elts))
		for _, v := range valeurs.Elts {
			mot, err := chaine(v)
			if err != nil {
				return nil, fmt.Errorf("liste %s : %w", nom, err)
			}
			mots = append(mots, mot)
		}
		listes[nom] = mots
	}
	return listes, nil
}

func chaine(expr ast.Expr) (string, error) {
	basique, ok := expr.(*ast.BasicLit)
	if !ok || basique.Kind != token.STRING {
		return "", errors.New("chaîne littérale attendue")
	}
	return strconv.Unquote(basique.Value)
}
