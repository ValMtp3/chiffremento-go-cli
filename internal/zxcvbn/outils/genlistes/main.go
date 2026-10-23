// Commande genlistes : produit les listes de mots embarquées par le paquet
// frequency (un mot par ligne, compressées en zstd).
//
// Listes anglaises : elle lit le littéral Go de zxcvbn v1.0.1
// (frequency/lists.go) avec go/parser : aucun import de l'amont, le fichier
// n'est jamais compilé.
//
// Listes françaises : elle lit les fichiers nationaux de l'Insee (prénoms et
// noms de famille), téléchargés à la main et vérifiés par leur empreinte
// SHA-256 (voir insee.go).
//
// Chaque source est facultative, mais il en faut au moins une. Usage (depuis
// la racine du dépôt) :
//
//	go run ./internal/zxcvbn/outils/genlistes \
//	    -amont "$(go env GOMODCACHE)/github.com/trustelem/zxcvbn@v1.0.1/frequency/lists.go" \
//	    -prenoms prenoms-2024-nat.csv -noms noms2008nat_txt.txt \
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
	"io"
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
	prenoms := flag.String("prenoms", "", "fichier national des prénoms de l'Insee (CSV dézippé, voir urlPrenoms)")
	noms := flag.String("noms", "", "fichier national des noms de l'Insee (texte dézippé, voir urlNoms)")
	sortie := flag.String("sortie", "", "dossier où écrire les fichiers .txt.zst")
	flag.Parse()

	if (*amont == "" && *prenoms == "" && *noms == "") || *sortie == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := generer(*amont, *prenoms, *noms, *sortie); err != nil {
		fmt.Fprintln(os.Stderr, "genlistes :", err)
		os.Exit(1)
	}
}

func generer(cheminAmont, cheminPrenoms, cheminNoms, dossierSortie string) error {
	textes := make(map[string][]byte)
	if cheminAmont != "" {
		listes, err := lireListesAmont(cheminAmont)
		if err != nil {
			return err
		}
		for nom, mots := range listes {
			texte, err := versTexte(nom, mots)
			if err != nil {
				return err
			}
			textes[nom] = texte
		}
	}
	if cheminPrenoms != "" {
		texte, err := texteInsee("prenoms_fr", cheminPrenoms, shaPrenoms, classerPrenoms)
		if err != nil {
			return err
		}
		textes["prenoms_fr"] = texte
	}
	if cheminNoms != "" {
		texte, err := texteInsee("noms_fr", cheminNoms, shaNoms, classerNoms)
		if err != nil {
			return err
		}
		textes["noms_fr"] = texte
	}

	if err := os.MkdirAll(dossierSortie, 0o755); err != nil {
		return err
	}
	encodeur, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return err
	}
	defer encodeur.Close()

	for nom, texte := range textes {
		chemin := filepath.Join(dossierSortie, nom+suffixeSortie)
		if err := os.WriteFile(chemin, encodeur.EncodeAll(texte, nil), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s : %d lignes, %d octets de texte\n", chemin, bytes.Count(texte, []byte("\n")), len(texte))
	}
	return nil
}

// texteInsee lit un fichier de l'Insee, vérifie son empreinte, le classe et
// écrit les nbEntreesInsee premières lignes.
func texteInsee(nom, chemin, sha string, classer func(io.Reader) ([]effectif, error)) ([]byte, error) {
	contenu, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	if err := verifierEmpreinte(chemin, contenu, sha); err != nil {
		return nil, err
	}
	effectifs, err := classer(bytes.NewReader(contenu))
	if err != nil {
		return nil, err
	}
	lignes, err := lignesFrancais(effectifs, nbEntreesInsee)
	if err != nil {
		return nil, fmt.Errorf("liste %s : %w", nom, err)
	}
	return versTexteLignes(nom, lignes)
}

// versTexte écrit un mot par ligne ("\n"). Un mot vide ou contenant un saut de
// ligne casserait le découpage à la lecture : on refuse.
// Une tabulation est refusée aussi : elle marque les variantes sans accent
// des listes françaises (voir marqueVariante).
func versTexte(nom string, mots []string) ([]byte, error) {
	for i, mot := range mots {
		if strings.HasPrefix(mot, marqueVariante) {
			return nil, fmt.Errorf("liste %s, mot n°%d (%q) : commence par la marque de variante", nom, i+1, mot)
		}
	}
	return versTexteLignes(nom, mots)
}

// versTexteLignes écrit une ligne par élément. Les lignes françaises peuvent
// commencer par une marque de variante, mais n'en contiennent pas d'autre.
func versTexteLignes(nom string, lignes []string) ([]byte, error) {
	var tampon bytes.Buffer
	for i, ligne := range lignes {
		mot := strings.TrimPrefix(ligne, marqueVariante)
		if mot == "" || strings.ContainsAny(mot, "\r\n\t") {
			return nil, fmt.Errorf("liste %s, ligne n°%d (%q) : vide, avec saut de ligne ou tabulation", nom, i+1, ligne)
		}
		tampon.WriteString(ligne)
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
