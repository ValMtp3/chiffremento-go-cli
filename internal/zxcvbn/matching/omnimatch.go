package matching

import (
	"chiffremento-cli/internal/zxcvbn/adjacency"
	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
	"regexp"
	"sync"
)

// Omnimatch cherche tous les motifs avec les listes anglaises de zxcvbn.
func Omnimatch(password string, userInputs []string) (matches []*match.Match) {
	return omnimatch(password, userInputs, dictionnairesParDefaut())
}

// Classement est un jeu de listes déjà classées (mot -> rang), construit une
// fois par Classer puis réutilisé à chaque mot de passe.
type Classement struct {
	dictionnaires dictionaryMatch
}

// Classer construit le classement de ces listes. Coûteux : à faire une fois.
func Classer(listes map[string]frequency.Liste) Classement {
	return Classement{dictionnaires: loadDefaultDictionnaries(listes)}
}

// OmnimatchAvec est Omnimatch avec un autre jeu de listes.
func OmnimatchAvec(password string, userInputs []string, classement Classement) []*match.Match {
	return omnimatch(password, userInputs, classement.dictionnaires)
}

func omnimatch(password string, userInputs []string, dictionnaires dictionaryMatch) (matches []*match.Match) {
	dictMatcher := dictionnaires.withDict("user_inputs", buildRankedDict(userInputs))

	matchers := []match.Matcher{
		dictMatcher,
		reverseDictionnaryMatch{dm: dictMatcher},
		l33tMatch{dm: dictMatcher, table: l33tTable},
		spatialMatch{graphs: graphesParDefaut()},
		repeatMatch{dm: dictionnaires},
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

// Rien ne se construit avant le premier usage : ni les graphes de claviers, ni
// le classement des listes anglaises (utilisé par Omnimatch seul, donc surtout
// par les tests).
var (
	graphesChargesUneFois = sync.OnceValue(loadDefaultAdjacencyGraphs)
	anglaisClasse         = sync.OnceValue(func() dictionaryMatch {
		return loadDefaultDictionnaries(frequency.Anglais())
	})
)

// Precharger construit les graphes de claviers s'ils ne le sont pas déjà. Sans
// effet ensuite ; sûr depuis plusieurs goroutines. Les listes se préparent
// avec Classer.
func Precharger() {
	graphesChargesUneFois()
}

func dictionnairesParDefaut() dictionaryMatch { return anglaisClasse() }

func graphesParDefaut() []*adjacency.Graph { return graphesChargesUneFois() }

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
