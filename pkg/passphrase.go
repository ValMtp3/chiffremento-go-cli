package pkg

import (
	"bufio"
	"bytes"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"sync"
)

// Générateur de phrases de passe en français.
//
// La liste est celle compilée par Tango pour Tails et le Tor Project (CC0,
// diffusée avec le projet diceware : github.com/ulif/diceware). 7 776 mots de 4
// à 8 lettres, sans accent : rien de pénible à taper, sur aucun clavier. Un seul
// écart avec l'original : celui-ci contenait « internet » et « Internet », que
// les majuscules tirées au hasard rendraient indiscernables ; le second a été
// remplacé par « noisette ».
//
// Tout le hasard vient de crypto/rand, et chaque tirage passe par rand.Int, qui
// rejette les valeurs hors intervalle au lieu de prendre un modulo : aucun mot,
// séparateur ou chiffre ne sort plus souvent qu'un autre. L'entropie affichée
// est donc l'entropie réelle — à condition que l'attaquant connaisse la
// méthode, ce qu'on suppose toujours.

//go:embed mots_fr.txt
var motsFrBruts []byte

const (
	// MinMotsPhrase : 6 mots donnent environ 109 bits ; à 5, la phrase tombe
	// vers 91 bits, et le gain de mémorisation ne justifie plus la marge perdue.
	MinMotsPhrase = 6
	// MaxMotsPhrase : 12 mots font déjà environ 218 bits, bien au-delà de ce
	// qu'Argon2 et AES-256 peuvent tirer d'un secret.
	MaxMotsPhrase = 12

	// DefautMotsPhrase donne environ 128 bits.
	DefautMotsPhrase = 7

	// separateursPhrase : 16 caractères, soit 4 bits par séparateur. Aucun ne
	// casse une commande shell ni un script (`echo '…' | chiffremento`) : pas
	// de $ ! ` " ' \ & | < > * ?.
	separateursPhrase = "-_.,:;+=@#%^~/()"

	tailleListeMots = 7776
)

// Phrase est une phrase de passe générée et son entropie en bits.
type Phrase struct {
	Texte string
	Bits  float64
}

// listeMots lit la liste intégrée une seule fois, et la contrôle : sa taille
// fixe l'entropie annoncée.
var listeMots = sync.OnceValues(func() ([]string, error) {
	var mots []string
	sc := bufio.NewScanner(bytes.NewReader(motsFrBruts))
	for sc.Scan() {
		if m := strings.TrimSpace(sc.Text()); m != "" {
			mots = append(mots, m)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("lecture de la liste de mots: %w", err)
	}
	if len(mots) != tailleListeMots {
		return nil, fmt.Errorf("liste de mots corrompue : %d mots, attendu %d", len(mots), tailleListeMots)
	}
	return mots, nil
})

// EntropiePhrase dit combien de bits apporte une phrase de n mots :
// le mot, la majuscule tirée à pile ou face sur chaque mot, les séparateurs, et
// le chiffre — sa valeur et le mot auquel il est collé.
func EntropiePhrase(n int) float64 {
	mots := float64(n)
	return mots*math.Log2(tailleListeMots) +
		mots*1 +
		(mots-1)*math.Log2(float64(len(separateursPhrase))) +
		math.Log2(10) + math.Log2(mots)
}

// GenererPhrase produit une phrase de n mots, entre MinMotsPhrase et MaxMotsPhrase.
func GenererPhrase(n int) (Phrase, error) {
	return genererPhrase(rand.Reader, n)
}

// genererPhrase prend la source d'aléa en paramètre : les tests vérifient
// qu'une source défaillante fait échouer la génération, sans repli.
func genererPhrase(alea io.Reader, n int) (Phrase, error) {
	if n < MinMotsPhrase || n > MaxMotsPhrase {
		return Phrase{}, fmt.Errorf("%d mots demandés : entre %d et %d", n, MinMotsPhrase, MaxMotsPhrase)
	}
	mots, err := listeMots()
	if err != nil {
		return Phrase{}, err
	}

	tirer := func(max int) (int, error) {
		v, err := rand.Int(alea, big.NewInt(int64(max)))
		if err != nil {
			return 0, fmt.Errorf("aléa indisponible: %w", err)
		}
		return int(v.Int64()), nil
	}

	porteChiffre, err := tirer(n)
	if err != nil {
		return Phrase{}, err
	}
	chiffre, err := tirer(10)
	if err != nil {
		return Phrase{}, err
	}

	var b strings.Builder
	for i := range n {
		if i > 0 {
			s, err := tirer(len(separateursPhrase))
			if err != nil {
				return Phrase{}, err
			}
			b.WriteByte(separateursPhrase[s])
		}
		idx, err := tirer(len(mots))
		if err != nil {
			return Phrase{}, err
		}
		majuscule, err := tirer(2)
		if err != nil {
			return Phrase{}, err
		}
		mot := mots[idx]
		if majuscule == 1 {
			mot = strings.ToUpper(mot[:1]) + mot[1:]
		}
		b.WriteString(mot)
		if i == porteChiffre {
			b.WriteByte(byte('0' + chiffre))
		}
	}
	return Phrase{Texte: b.String(), Bits: EntropiePhrase(n)}, nil
}
