// Paquet frequency : listes de mots de zxcvbn, stockées en texte compressé
// (un mot par ligne, zstd) et décodées au premier usage seulement.
package frequency

//go:generate go run ../outils/genlistes -amont $AMONT_LISTS_GO -sortie listes
// AMONT_LISTS_GO : chemin de frequency/lists.go de zxcvbn v1.0.1, par exemple
//   AMONT_LISTS_GO="$(go env GOMODCACHE)/github.com/trustelem/zxcvbn@v1.0.1/frequency/lists.go" go generate ./internal/zxcvbn/frequency

import (
	"embed"
	"fmt"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

//go:embed listes/*.txt.zst
var listesEmbarquees embed.FS

const suffixeFichier = ".txt.zst"

// Liste est une liste de mots classés.
// RangFixe == 0 : le rang suit l'ordre (1, 2, 3...).
// Sinon, tous les mots ont ce rang.
type Liste struct {
	Mots     []string
	RangFixe int
}

var anglais = sync.OnceValue(decoderAnglais)

// Anglais renvoie les 6 listes de zxcvbn v1.0.1, sous leurs noms d'origine.
// Le décodage se fait une seule fois, au premier appel. La map renvoyée est
// partagée : ne pas la modifier.
func Anglais() map[string]Liste {
	return anglais()
}

// decoderAnglais panique si une donnée embarquée est illisible : c'est une
// erreur de programmation (comme regexp.MustCompile), TestListesEmbarquees
// la détecte avant livraison.
func decoderAnglais() map[string]Liste {
	entrees, err := listesEmbarquees.ReadDir("listes")
	if err != nil {
		panic(fmt.Sprintf("frequency : dossier listes embarqué illisible : %v", err))
	}
	decodeur, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
	if err != nil {
		panic(fmt.Sprintf("frequency : décodeur zstd : %v", err))
	}
	defer decodeur.Close()

	listes := make(map[string]Liste, len(entrees))
	for _, entree := range entrees {
		fichier := entree.Name()
		nom, ok := strings.CutSuffix(fichier, suffixeFichier)
		if !ok {
			continue
		}
		compresse, err := listesEmbarquees.ReadFile("listes/" + fichier)
		if err != nil {
			panic(fmt.Sprintf("frequency : lecture de %s : %v", fichier, err))
		}
		texte, err := decodeur.DecodeAll(compresse, nil)
		if err != nil {
			panic(fmt.Sprintf("frequency : décodage de %s : %v", fichier, err))
		}
		listes[nom] = Liste{Mots: motsDepuisTexte(string(texte))}
	}
	return listes
}

// motsDepuisTexte découpe un mot par ligne. Les mots partagent la mémoire du
// texte décodé : pas d'allocation par mot.
func motsDepuisTexte(texte string) []string {
	texte = strings.TrimSuffix(texte, "\n")
	if texte == "" {
		return nil
	}
	return strings.Split(texte, "\n")
}
