package matching

import (
	"unicode/utf8"

	"chiffremento-cli/internal/zxcvbn/match"
	"chiffremento-cli/internal/zxcvbn/scoring"
	"github.com/dlclark/regexp2"
)

// repeatMatch note le motif répété avec les mêmes listes que le reste ; sans
// listes (valeur zéro), il prend les listes anglaises.
type repeatMatch struct {
	dm dictionaryMatch
}

var greedy = regexp2.MustCompile(`(.+)\1+`, 0)
var lazy = regexp2.MustCompile(`(.+?)\1+`, 0)
var lazyAnchored = regexp2.MustCompile(`^(.+?)\1+$`, 0)

func runeToStringIndex(index int, password string) int {
	runes := 0
	for i := range password {
		if runes == index {
			return i
		}
		runes++
	}
	//shouldn't really get here
	return len(password)
}

func (r repeatMatch) dictionnaires() dictionaryMatch {
	if r.dm.rankedDictionaries == nil {
		return dictionnairesParDefaut()
	}
	return r.dm
}

func (r repeatMatch) Matches(password string) []*match.Match {
	var matches []*match.Match

	lastIndex := 0
	for lastIndex < len(password) {
		greedyMatch, err := greedy.FindStringMatchStartingAt(password, lastIndex)
		if err != nil || greedyMatch == nil {
			break
		}
		lazyMatch, _ := lazy.FindStringMatchStartingAt(password, lastIndex)

		var rmatch *regexp2.Match
		var baseToken string
		if greedyMatch.Captures[0].Length > lazyMatch.Captures[0].Length {
			// greedy beats lazy for 'aabaab'
			//   greedy: [aabaab, aab]
			//   lazy:   [aa,     a]
			rmatch = greedyMatch
			// greedy's repeated string might itself be repeated, eg.
			// aabaab in aabaabaabaab.
			// run an anchored lazy match on greedy's repeated string
			// to find the shortest repeated string
			if m, err := lazyAnchored.FindStringMatch(rmatch.Captures[0].String()); err == nil {
				baseToken = m.GroupByNumber(1).String()
			}
		} else {
			// lazy beats greedy for 'aaaaa'
			//   greedy: [aaaa,  aa]
			//   lazy:   [aaaaa, a]
			rmatch = lazyMatch
			baseToken = rmatch.GroupByNumber(1).String()
		}
		// FindStringMatchStartingAt takes an index into the string (basically an offset
		// into a byte array). rmatch indices will be rune offsets and so need to be converted
		// to string offsets
		//
		// Même convention que dictionaryMatch : J est le DERNIER octet du
		// motif, donc l'octet qui précède le caractère suivant. La v1.0.1
		// prenait le début du dernier caractère : avec « é » (2 octets), le
		// motif perdait son dernier octet et la recherche reprenait en plein
		// caractère (erreur de regexp2, répétitions suivantes ignorées).
		i := runeToStringIndex(rmatch.Index, password)
		j := runeToStringIndex(rmatch.Index+rmatch.Captures[0].Length, password) - 1

		// recursively match and score the base string
		baseAnalysis := scoring.MostGuessableMatchSequence(
			baseToken,
			omnimatch(baseToken, nil, r.dictionnaires()),
			false,
		)
		matches = append(matches, &match.Match{
			Pattern:     "repeat",
			I:           i,
			J:           j,
			Token:       rmatch.Captures[0].String(),
			BaseToken:   baseToken,
			BaseGuesses: baseAnalysis.Guesses,
			BaseMatches: baseAnalysis.Sequence,
			// Length compte des caractères : la base aussi (len compterait
			// des octets, « ééé » ferait 1 répétition au lieu de 3).
			RepeatCount: rmatch.Captures[0].Length / utf8.RuneCountInString(baseToken),
		})
		lastIndex = j + 1

	}
	return matches
}
