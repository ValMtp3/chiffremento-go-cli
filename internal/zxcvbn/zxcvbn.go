// Copie interne de github.com/trustelem/zxcvbn v1.0.1 (voir le fichier AMONT).
// Licence MIT, Copyright (c) 2018 Vincent Vanackere and Trustelem : voir LICENSE.txt.
package zxcvbn

import (
	"chiffremento-cli/internal/zxcvbn/match"
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

// charger construit tout ce qui coûte (listes de mots, classement, graphes de
// claviers : matching.Precharger les construit tous, scoring en réutilise deux). sync.OnceFunc : une seule exécution, même si le préchargement et
// la première frappe arrivent en même temps ; les autres appels attendent la fin.
var charger = sync.OnceFunc(func() {
	nbChargements.Add(1)
	matching.Precharger()
})

// Precharger force le chargement des listes (une dizaine de millisecondes) pour
// que le premier PasswordStrength soit rapide. Sans effet s'il est déjà fait ;
// sûr depuis plusieurs goroutines.
func Precharger() {
	charger()
}

func PasswordStrength(password string, userInputs []string) Result {
	start := time.Now()
	var result Result
	if !utf8.ValidString(password) {
		// Do not evaluate passwords containing invalid utf8
		// => those will be reported as weak passwords
		return result
	}
	charger()
	matches := matching.Omnimatch(password, userInputs)
	seq := scoring.MostGuessableMatchSequence(password, matches, false)
	end := time.Now()
	calcTime := end.Nanosecond() - start.Nanosecond()
	result.CalcTime = round(float64(calcTime)*time.Nanosecond.Seconds(), .5, 3)
	result.Sequence = seq.Sequence
	result.Guesses = seq.Guesses
	result.Score = guessesToScore(seq.Guesses)
	return result
}
