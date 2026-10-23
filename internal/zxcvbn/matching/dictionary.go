package matching

import (
	"strings"
	"unicode/utf8"

	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
)

type dictionaryMatch struct {
	rankedDictionaries map[string]rankedDictionnary
}

// Matches cherche chaque morceau de password dans chaque dictionnaire. Pour les
// listes françaises, un morceau accentué absent est aussi cherché recomposé
// (une saisie collée depuis le Finder est décomposée, NFD) puis sans accent (le
// fichier des noms de l'Insee n'en a pas) ; seule la clé de recherche change :
// positions et jeton restent ceux de la saisie.
func (dm dictionaryMatch) Matches(password string) []*match.Match {
	var results []*match.Match
	saisieAccentuee := strings.ContainsFunc(password, func(r rune) bool { return r >= utf8.RuneSelf })

	// Une tranche plutôt que la map : parcourir une map coûte une mise en
	// route à chaque fois, et la boucle ci-dessous la parcourt par morceau.
	type dictionnaire struct {
		nom              string
		rangs            rankedDictionnary
		sansAccentPermis bool
	}
	dictionnaires := make([]dictionnaire, 0, len(dm.rankedDictionaries))
	for nom, rangs := range dm.rankedDictionaries {
		dictionnaires = append(dictionnaires, dictionnaire{nom, rangs, saisieAccentuee && chercheSansAccent(nom)})
	}

	// Morceau par morceau, puis dictionnaire par dictionnaire : la mise en
	// minuscules et les autres formes d'un morceau ne se calculent qu'une
	// fois, pas une fois par dictionnaire. L'ordre final ne change pas :
	// match.Sort trie par positions.
	for i := range password {
		for delta := range password[i:] {
			j := i + delta
			token := password[i : j+1]
			word := strings.ToLower(token)
			var formes *autresFormes
			for _, d := range dictionnaires {
				cle := word
				val, ok := d.rangs[word]
				if !ok && d.sansAccentPermis {
					if formes == nil {
						formes = autresFormesDe(word)
					}
					cle, val, ok = formes.chercher(d.rangs)
				}
				if ok {
					results = append(results, &match.Match{
						Pattern:        "dictionary",
						I:              i,
						J:              j,
						Token:          token,
						MatchedWord:    cle,
						Rank:           val,
						DictionaryName: d.nom,
					})
				}
			}
		}
	}

	match.Sort(results)
	return results
}

// autresFormes garde les clés de repli d'un morceau accentué : sa forme
// recomposée (saisie NFD) puis sa forme sans accent, sans doublon ni la forme
// d'origine.
type autresFormes struct {
	cles [2]string
	nb   int
}

func autresFormesDe(word string) *autresFormes {
	f := &autresFormes{}
	for _, cle := range [...]string{frequency.Recomposer(word), frequency.SansAccent(word)} {
		if cle != word && (f.nb == 0 || f.cles[0] != cle) {
			f.cles[f.nb] = cle
			f.nb++
		}
	}
	return f
}

// chercher rend la première clé de repli présente dans le dictionnaire.
func (f *autresFormes) chercher(rankedDict rankedDictionnary) (string, int, bool) {
	for _, cle := range f.cles[:f.nb] {
		if val, ok := rankedDict[cle]; ok {
			return cle, val, true
		}
	}
	return "", 0, false
}

// chercheSansAccent dit si le dictionnaire accepte la forme sans accent d'un
// morceau : les listes françaises seulement. Les listes anglaises gardent le
// comportement de zxcvbn v1.0.1 (TestPariteAvecV101).
func chercheSansAccent(nom string) bool {
	switch nom {
	case frequency.NomMotsFr, frequency.NomPrenomsFr, frequency.NomNomsFr:
		return true
	}
	return false
}

func (dm dictionaryMatch) withDict(name string, d rankedDictionnary) dictionaryMatch {
	rd2 := make(map[string]rankedDictionnary, len(dm.rankedDictionaries)+1)
	for k, v := range dm.rankedDictionaries {
		rd2[k] = v
	}
	rd2[name] = d
	return dictionaryMatch{rankedDictionaries: rd2}
}

type rankedDictionnary map[string]int

// buildRankedDictListe classe une liste : RangFixe pour tous les mots si la
// liste en impose un, sinon Rangs[i] s'il existe, sinon la position (à partir
// de 1).
func buildRankedDictListe(liste frequency.Liste) rankedDictionnary {
	result := make(rankedDictionnary, len(liste.Mots))
	for i, v := range liste.Mots {
		rang := i + 1
		switch {
		case liste.RangFixe != 0:
			rang = liste.RangFixe
		case liste.Rangs != nil:
			rang = liste.Rangs[i]
		}
		result[strings.ToLower(v)] = rang
	}
	return result
}

func buildRankedDict(unrankedList []string) rankedDictionnary {
	result := make(rankedDictionnary)

	for i, v := range unrankedList {
		result[strings.ToLower(v)] = i + 1
	}

	return result
}
