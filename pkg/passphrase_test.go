package pkg

import (
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

// TestListeDeMots : la liste intégrée est la liste CC0 de Tails et du Tor
// Project. Sa taille fixe l'entropie annoncée : un mot perdu ou dupliqué
// fausserait le calcul affiché à l'utilisateur.
func TestListeDeMots(t *testing.T) {
	mots, err := listeMots()
	if err != nil {
		t.Fatal(err)
	}
	if len(mots) != 7776 {
		t.Fatalf("%d mots, attendu 7776", len(mots))
	}
	vus := map[string]bool{}
	valide := regexp.MustCompile(`^[a-z]{4,8}$`)
	for _, m := range mots {
		if vus[m] {
			t.Errorf("mot en double : %q", m)
		}
		vus[m] = true
		if !valide.MatchString(m) {
			t.Errorf("mot hors format a-z de 4 à 8 lettres : %q", m)
		}
	}
}

// decouper rend les mots et les séparateurs d'une phrase générée.
func decouper(t *testing.T, phrase string) (mots []string, seps []rune) {
	t.Helper()
	courant := strings.Builder{}
	for _, r := range phrase {
		if strings.ContainsRune(separateursPhrase, r) {
			mots = append(mots, courant.String())
			courant.Reset()
			seps = append(seps, r)
			continue
		}
		courant.WriteRune(r)
	}
	return append(mots, courant.String()), seps
}

func TestPhraseStructure(t *testing.T) {
	liste, err := listeMots()
	if err != nil {
		t.Fatal(err)
	}
	connus := map[string]bool{}
	for _, m := range liste {
		connus[m] = true
	}

	for _, n := range []int{MinMotsPhrase, DefautMotsPhrase, 12} {
		p, err := GenererPhrase(n)
		if err != nil {
			t.Fatal(err)
		}
		mots, seps := decouper(t, p.Texte)
		if len(mots) != n || len(seps) != n-1 {
			t.Fatalf("%q : %d mots et %d séparateurs, attendu %d et %d", p.Texte, len(mots), len(seps), n, n-1)
		}
		chiffres := 0
		for _, m := range mots {
			// Le chiffre est collé à la fin d'un seul mot.
			if last := m[len(m)-1]; last >= '0' && last <= '9' {
				chiffres++
				m = m[:len(m)-1]
			}
			if !connus[strings.ToLower(m)] {
				t.Errorf("%q : mot %q absent de la liste", p.Texte, m)
			}
			// Seule la première lettre peut être une majuscule.
			for i, r := range m {
				if i > 0 && unicode.IsUpper(r) {
					t.Errorf("%q : majuscule ailleurs qu'en tête dans %q", p.Texte, m)
				}
			}
		}
		if chiffres != 1 {
			t.Errorf("%q : %d chiffres, attendu exactement 1", p.Texte, chiffres)
		}
	}
}

func TestPhraseTropCourteRefusee(t *testing.T) {
	if _, err := GenererPhrase(MinMotsPhrase - 1); err == nil {
		t.Errorf("une phrase de %d mots a été acceptée, minimum %d", MinMotsPhrase-1, MinMotsPhrase)
	}
}

// TestPhraseTropLongueRefusee : sans plafond, -mots 100000000 ferait tirer et
// garder en mémoire des centaines de mégaoctets pour rien.
func TestPhraseTropLongueRefusee(t *testing.T) {
	if _, err := GenererPhrase(MaxMotsPhrase); err != nil {
		t.Errorf("%d mots refusés : %v", MaxMotsPhrase, err)
	}
	if _, err := GenererPhrase(MaxMotsPhrase + 1); err == nil {
		t.Errorf("une phrase de %d mots a été acceptée, maximum %d", MaxMotsPhrase+1, MaxMotsPhrase)
	}
}

// Un aléa qui fait défaut doit faire échouer la génération, jamais produire
// une phrase prévisible en silence.
type lecteurEnPanne struct{}

func (lecteurEnPanne) Read([]byte) (int, error) { return 0, errors.New("aléa indisponible") }

func TestPhraseAleaEnPanne(t *testing.T) {
	if p, err := genererPhrase(lecteurEnPanne{}, DefautMotsPhrase); err == nil {
		t.Errorf("phrase produite sans source d'aléa : %q", p.Texte)
	}
}

// TestPhraseEntropie : la valeur affichée doit être exacte, ni gonflée ni
// arrondie à l'avantage de l'outil.
func TestPhraseEntropie(t *testing.T) {
	n := 7.0
	attendu := n*math.Log2(7776) + // mots
		n*1 + // majuscule tirée à pile ou face sur chaque mot
		(n-1)*math.Log2(16) + // séparateurs
		math.Log2(10) + math.Log2(n) // un chiffre, collé à l'un des mots
	got := EntropiePhrase(7)
	if math.Abs(got-attendu) > 1e-9 {
		t.Errorf("entropie %.4f bits, attendu %.4f", got, attendu)
	}
	if got < 127 || got > 128 {
		t.Errorf("entropie de 7 mots hors de l'ordre attendu (≈127,6) : %.2f", got)
	}
	p, err := GenererPhrase(7)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bits != got {
		t.Errorf("la phrase annonce %.2f bits, la formule %.2f", p.Bits, got)
	}
}

// TestPhraseUniformite : chaque séparateur et chaque chiffre doivent sortir
// aussi souvent les uns que les autres. Un biais (modulo mal fait, mauvais
// tirage) réduirait l'entropie réelle sous celle affichée. Seuil large :
// khi-deux bien au-delà du quantile 1e-6, donc pas de faux échec en CI.
func TestPhraseUniformite(t *testing.T) {
	if testing.Short() {
		t.Skip("test statistique")
	}
	compteSep := map[rune]int{}
	compteChiffre := map[byte]int{}
	positionChiffre := make([]int, DefautMotsPhrase)
	majuscules, total := 0, 0
	const tirages = 4000
	for range tirages {
		p, err := GenererPhrase(DefautMotsPhrase)
		if err != nil {
			t.Fatal(err)
		}
		mots, seps := decouper(t, p.Texte)
		for _, s := range seps {
			compteSep[s]++
		}
		for i, m := range mots {
			total++
			if unicode.IsUpper(rune(m[0])) {
				majuscules++
			}
			if last := m[len(m)-1]; last >= '0' && last <= '9' {
				compteChiffre[last]++
				positionChiffre[i]++
			}
		}
	}
	khiDeux := func(observe []int) float64 {
		somme := 0
		for _, o := range observe {
			somme += o
		}
		attendu := float64(somme) / float64(len(observe))
		x := 0.0
		for _, o := range observe {
			x += (float64(o) - attendu) * (float64(o) - attendu) / attendu
		}
		return x
	}
	var seps []int
	for _, r := range separateursPhrase {
		seps = append(seps, compteSep[r])
	}
	// 15 degrés de liberté : quantile 1e-6 ≈ 54.
	if x := khiDeux(seps); x > 60 {
		t.Errorf("séparateurs non uniformes : khi-deux %.1f, %v", x, seps)
	}
	var chiffres []int
	for c := byte('0'); c <= '9'; c++ {
		chiffres = append(chiffres, compteChiffre[c])
	}
	// 9 degrés de liberté : quantile 1e-6 ≈ 42.
	if x := khiDeux(chiffres); x > 48 {
		t.Errorf("chiffres non uniformes : khi-deux %.1f, %v", x, chiffres)
	}
	// Le mot qui porte le chiffre compte dans l'entropie (log2 n) : sa
	// position doit être uniforme elle aussi. 6 degrés de liberté : ≈ 33.
	if x := khiDeux(positionChiffre); x > 38 {
		t.Errorf("position du chiffre non uniforme : khi-deux %.1f, %v", x, positionChiffre)
	}
	// 1 degré de liberté : quantile 1e-6 ≈ 24.
	if x := khiDeux([]int{majuscules, total - majuscules}); x > 28 {
		t.Errorf("majuscules non équilibrées : %d sur %d", majuscules, total)
	}
}

// MotsPhrase rend une copie : la modifier ne touche pas la liste du générateur.
func TestMotsPhraseRendUneCopie(t *testing.T) {
	mots, err := MotsPhrase()
	if err != nil {
		t.Fatalf("MotsPhrase : %v", err)
	}
	if len(mots) != 7776 {
		t.Fatalf("%d mots, 7776 attendus", len(mots))
	}
	premier := mots[0]
	mots[0] = "modifie"

	interne, err := listeMots()
	if err != nil {
		t.Fatalf("listeMots : %v", err)
	}
	if interne[0] != premier {
		t.Errorf("la liste interne a changé : %q au lieu de %q", interne[0], premier)
	}
	autre, _ := MotsPhrase()
	if autre[0] != premier {
		t.Errorf("la copie suivante a changé : %q au lieu de %q", autre[0], premier)
	}
}
