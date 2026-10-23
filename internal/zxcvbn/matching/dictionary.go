package matching

import (
	"strings"

	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
)

type dictionaryMatch struct {
	rankedDictionaries map[string]rankedDictionnary
}

func (dm dictionaryMatch) Matches(password string) []*match.Match {
	var results []*match.Match

	for dictionaryName, rankedDict := range dm.rankedDictionaries {
		for i := range password {
			for delta := range password[i:] {
				j := i + delta
				word := strings.ToLower(password[i : j+1])
				if val, ok := rankedDict[word]; ok {
					matchDic := &match.Match{
						Pattern:        "dictionary",
						I:              i,
						J:              j,
						Token:          password[i : j+1],
						MatchedWord:    word,
						Rank:           val,
						DictionaryName: dictionaryName,
					}

					results = append(results, matchDic)
				}
			}
		}
	}

	match.Sort(results)
	return results
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
