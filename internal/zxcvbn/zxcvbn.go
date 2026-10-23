// Copie interne de github.com/trustelem/zxcvbn v1.0.1 (voir le fichier AMONT).
// Licence MIT, Copyright (c) 2018 Vincent Vanackere and Trustelem : voir LICENSE.txt.
package zxcvbn

import (
	"chiffremento-cli/internal/zxcvbn/frequency"
	"chiffremento-cli/internal/zxcvbn/match"
	"maps"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"chiffremento-cli/internal/zxcvbn/matching"
	"chiffremento-cli/internal/zxcvbn/scoring"
)

type Result struct {
	Guesses  float64
	Sequence []*match.Match
	Score    int
	CalcTime float64
}

// nbChargements compte les constructions des listes, du classement et des
// graphes. Les tests vérifient qu'il reste à 0 au démarrage puis à 1.
var nbChargements atomic.Int32

// charger construit tout ce qui coûte : le classement des listes anglaises et
// françaises, et les graphes de claviers (scoring en réutilise deux).
// sync.OnceValue : une seule exécution, même si le préchargement et la
// première frappe arrivent en même temps ; les autres appels attendent la fin.
var charger = sync.OnceValue(func() matching.Classement {
	nbChargements.Add(1)
	matching.Precharger()
	return matching.Classer(listesParDefaut())
})

// listesParDefaut réunit les listes anglaises (zxcvbn v1.0.1) et françaises
// (mots des phrases de passe, prénoms et noms de l'Insee).
func listesParDefaut() map[string]frequency.Liste {
	anglais, francais := frequency.Anglais(), frequency.Francais()
	listes := make(map[string]frequency.Liste, len(anglais)+len(francais))
	maps.Copy(listes, anglais)
	maps.Copy(listes, francais)
	return listes
}

// Precharger force le chargement des listes (une dizaine de millisecondes) pour
// que le premier PasswordStrength soit rapide. Sans effet s'il est déjà fait ;
// sûr depuis plusieurs goroutines.
func Precharger() {
	charger()
}

// PasswordStrength évalue le mot de passe avec les listes anglaises et
// françaises, classées une seule fois.
func PasswordStrength(password string, userInputs []string) Result {
	if !utf8.ValidString(password) {
		return Result{}
	}
	return evaluer(password, userInputs, charger())
}

// passwordStrength classe les listes données à chaque appel : réservé aux
// tests, qui comparent à la v1.0.1 avec les seules listes anglaises.
func passwordStrength(password string, userInputs []string, listes map[string]frequency.Liste) Result {
	if !utf8.ValidString(password) {
		return Result{}
	}
	return evaluer(password, userInputs, matching.Classer(listes))
}

func evaluer(password string, userInputs []string, classement matching.Classement) Result {
	start := time.Now()
	var result Result
	matches := matching.OmnimatchAvec(password, userInputs, classement)
	seq := scoring.MostGuessableMatchSequence(password, matches, false)
	end := time.Now()
	calcTime := end.Nanosecond() - start.Nanosecond()
	result.CalcTime = round(float64(calcTime)*time.Nanosecond.Seconds(), .5, 3)
	result.Sequence = seq.Sequence
	result.Guesses = seq.Guesses
	result.Score = guessesToScore(seq.Guesses)
	return result
}
