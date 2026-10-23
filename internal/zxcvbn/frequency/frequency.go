// Paquet frequency : listes de mots de zxcvbn, stockées en texte compressé
// (un mot par ligne, zstd) et décodées au premier usage seulement.
package frequency

//go:generate go run ../outils/genlistes -amont $AMONT_LISTS_GO -prenoms $INSEE_PRENOMS -noms $INSEE_NOMS -sortie listes
// AMONT_LISTS_GO : chemin de frequency/lists.go de zxcvbn v1.0.1.
// INSEE_PRENOMS, INSEE_NOMS : fichiers de l'Insee téléchargés à la main et
// dézippés (URL et empreintes en tête de outils/genlistes/insee.go), par exemple :
//   AMONT_LISTS_GO="$(go env GOMODCACHE)/github.com/trustelem/zxcvbn@v1.0.1/frequency/lists.go" \
//   INSEE_PRENOMS=/tmp/prenoms-2024-nat.csv INSEE_NOMS=/tmp/noms2008nat_txt.txt \
//   go generate ./internal/zxcvbn/frequency

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	"chiffremento-cli/pkg"

	"github.com/klauspost/compress/zstd"
)

//go:embed listes/*.txt.zst
var listesEmbarquees embed.FS

const suffixeFichier = ".txt.zst"

// Liste est une liste de mots classés. Le rang d'un mot est, par ordre de
// priorité :
//   - RangFixe, s'il est non nul : tous les mots ont ce rang ;
//   - Rangs[i], si Rangs n'est pas nil (un rang par mot) : sert aux variantes
//     sans accent, qui partagent le rang du mot accentué ;
//   - sinon sa position (1, 2, 3...).
type Liste struct {
	Mots     []string
	RangFixe int
	Rangs    []int
}

// Les trois listes françaises, sous leurs noms de dictionnaire.
const (
	NomMotsFr    = "mots_fr"
	NomPrenomsFr = "prenoms_fr"
	NomNomsFr    = "noms_fr"
)

// rangMotsFr : les mots des phrases de passe sont tirés au hasard dans une
// liste de 7 776 mots (6^5) ; chacun vaut donc 7 776 essais, ~12,9 bits.
const rangMotsFr = 7776

var nomsAnglais = []string{
	"passwords", "english_wikipedia", "female_names", "surnames", "us_tv_and_film", "male_names",
}

var (
	anglais  = sync.OnceValue(decoderAnglais)
	francais = sync.OnceValue(decoderFrancais)
)

// Anglais renvoie les 6 listes de zxcvbn v1.0.1, sous leurs noms d'origine.
// Le décodage se fait une seule fois, au premier appel. La map renvoyée est
// partagée : ne pas la modifier.
func Anglais() map[string]Liste {
	return anglais()
}

// Francais renvoie les listes françaises : mots_fr (les mots des phrases de
// passe, tous au rang 7 776), prenoms_fr et noms_fr (10 000 entrées de
// l'Insee chacune, classées par fréquence). Même règles que Anglais : un seul
// décodage, map partagée.
func Francais() map[string]Liste {
	return francais()
}

// decoderAnglais panique si une donnée embarquée est illisible : c'est une
// erreur de programmation (comme regexp.MustCompile), TestListesEmbarquees
// la détecte avant livraison.
func decoderAnglais() map[string]Liste {
	return decoder(listesEmbarquees, nomsAnglais...)
}

// decoderFrancais : mêmes règles. Les mots de phrases viennent de pkg, qui les
// embarque déjà : pas de deuxième copie dans le binaire.
func decoderFrancais() map[string]Liste {
	listes := decoder(listesEmbarquees, NomPrenomsFr, NomNomsFr)
	mots, err := pkg.MotsPhrase()
	if err != nil {
		panic(fmt.Sprintf("frequency : mots des phrases de passe : %v", err))
	}
	listes[NomMotsFr] = Liste{Mots: mots, RangFixe: rangMotsFr}
	return listes
}

// decoder lit et décode les *.txt.zst du dossier "listes" de fsys. Sans noms,
// il les prend tous ; sinon seulement ceux-là, et panique si l'un manque.
func decoder(fsys fs.FS, noms ...string) map[string]Liste {
	entrees, err := fs.ReadDir(fsys, "listes")
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
		if !ok || (len(noms) > 0 && !slices.Contains(noms, nom)) {
			continue
		}
		compresse, err := fs.ReadFile(fsys, "listes/"+fichier)
		if err != nil {
			panic(fmt.Sprintf("frequency : lecture de %s : %v", fichier, err))
		}
		texte, err := decodeur.DecodeAll(compresse, nil)
		if err != nil {
			panic(fmt.Sprintf("frequency : décodage de %s : %v", fichier, err))
		}
		listes[nom] = listeDepuisTexte(string(texte))
	}
	for _, nom := range noms {
		if _, ok := listes[nom]; !ok {
			panic(fmt.Sprintf("frequency : liste %s absente", nom))
		}
	}
	return listes
}

// listeDepuisTexte découpe un mot par ligne. Les mots partagent la mémoire du
// texte décodé : pas d'allocation par mot. Rangs n'est rempli que si une ligne
// porte la marque de variante.
func listeDepuisTexte(texte string) Liste {
	texte = strings.TrimSuffix(texte, "\n")
	if texte == "" {
		return Liste{}
	}
	mots := strings.Split(texte, "\n")
	if !strings.Contains(texte, "\n"+MarqueVariante) {
		return Liste{Mots: mots}
	}
	rangs := make([]int, len(mots))
	rang := 0
	for i, mot := range mots {
		if variante, ok := strings.CutPrefix(mot, MarqueVariante); ok {
			mots[i] = variante
		} else {
			rang++
		}
		rangs[i] = rang
	}
	return Liste{Mots: mots, Rangs: rangs}
}
