package matching

import (
	"chiffremento-cli/internal/zxcvbn/adjacency"
	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
	"regexp"
	"sync"
)

func Omnimatch(password string, userInputs []string) (matches []*match.Match) {
	dictMatcher := dictionnairesParDefaut().withDict("user_inputs", buildRankedDict(userInputs))

	matchers := []match.Matcher{
		dictMatcher,
		reverseDictionnaryMatch{dm: dictMatcher},
		l33tMatch{dm: dictMatcher, table: l33tTable},
		spatialMatch{graphs: graphesParDefaut()},
		repeatMatch{},
		sequenceMatch{},
		regexpMatch{regexes: defaultRegexpMatch},
		dateMatch{},
	}

	for _, m := range matchers {
		matches = append(matches, m.Matches(password)...)
	}
	match.Sort(matches)
	return matches
}

var (
	defaultRegexpMatch = []struct {
		Name   string
		Regexp *regexp.Regexp
	}{
		{
			Name:   "recent_year",
			Regexp: regexp.MustCompile(`19\d\d|200\d|201\d`),
		},
	}
	l33tTable = map[string][]string{
		"a": {"4", "@"},
		"b": {"8"},
		"c": {"(", "{", "[", "<"},
		"e": {"3"},
		"g": {"6", "9"},
		"i": {"1", "!", "|"},
		"l": {"1", "|", "7"},
		"o": {"0"},
		"s": {"$", "5"},
		"t": {"+", "7"},
		"x": {"%"},
		"z": {"2"},
	}
)

// defauts regroupe ce qui coûte à construire : les dictionnaires classés et
// les graphes de claviers. Rien n'est construit avant le premier usage.
type defauts struct {
	dictionnaires dictionaryMatch
	graphes       []*adjacency.Graph
}

var chargerDefauts = sync.OnceValue(func() defauts {
	return defauts{
		dictionnaires: loadDefaultDictionnaries(frequency.Anglais()),
		graphes:       loadDefaultAdjacencyGraphs(),
	}
})

// Precharger construit les dictionnaires et les graphes s'ils ne le sont pas
// déjà. Sans effet ensuite ; sûr depuis plusieurs goroutines.
func Precharger() {
	chargerDefauts()
}

func dictionnairesParDefaut() dictionaryMatch { return chargerDefauts().dictionnaires }

func graphesParDefaut() []*adjacency.Graph { return chargerDefauts().graphes }

func loadDefaultDictionnaries(listes map[string]frequency.Liste) dictionaryMatch {
	rd := make(map[string]rankedDictionnary, len(listes))
	for nom, liste := range listes {
		rd[nom] = buildRankedDictListe(liste)
	}
	return dictionaryMatch{
		rankedDictionaries: rd,
	}
}

func loadDefaultAdjacencyGraphs() []*adjacency.Graph {
	return []*adjacency.Graph{
		adjacency.Graphe("qwerty"),
		adjacency.Graphe("dvorak"),
		adjacency.Graphe("keypad"),
		adjacency.Graphe("mac_keypad"),
	}
}
