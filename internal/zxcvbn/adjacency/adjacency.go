package adjacency

import "sync"

type Graph struct {
	Graph         map[string][]string
	Name          string
	AverageDegree float64
}

// graphes construit chaque graphe une seule fois, au premier appel de Graphe.
var graphes = map[string]func() *Graph{
	"qwerty":     sync.OnceValue(func() *Graph { return construireGraphe("qwerty", adjacencyGraphQwerty) }),
	"dvorak":     sync.OnceValue(func() *Graph { return construireGraphe("dvorak", adjacencyGraphDvorak) }),
	"keypad":     sync.OnceValue(func() *Graph { return construireGraphe("keypad", adjacencyGraphKeypad) }),
	"mac_keypad": sync.OnceValue(func() *Graph { return construireGraphe("mac_keypad", adjacencyGraphMacKeypad) }),
}

// Graphe renvoie le graphe d'adjacence de ce nom (qwerty, dvorak, keypad,
// mac_keypad), ou nil s'il n'existe pas. Le graphe est construit au premier
// appel, une seule fois, et peut être demandé depuis plusieurs goroutines.
func Graphe(nom string) *Graph {
	construire, ok := graphes[nom]
	if !ok {
		return nil
	}
	return construire()
}

func construireGraphe(name string, data map[string][]string) *Graph {
	return &Graph{
		Name:          name,
		Graph:         data,
		AverageDegree: calculateAvgDegree(data),
	}
}

func calculateAvgDegree(g map[string][]string) float64 {
	var avg float64
	for _, value := range g {
		for _, chars := range value {
			if chars != "" {
				avg += float64(1)
			}
		}

	}

	return avg / float64(len(g))
}
