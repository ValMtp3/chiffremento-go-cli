//go:build race

package pkg

// raceEnabled indique que le binaire de test est instrumenté par le détecteur
// de courses. Sert à écarter les mesures de durée, qui n'ont aucun sens sous
// instrumentation, et dont le coût est multiplié par plusieurs.
const raceEnabled = true
