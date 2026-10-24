package main

import (
	"fmt"
	"io"
	"sync"
)

// Session du plein écran : ce qui vit d'une opération à l'autre, du premier
// menu jusqu'à la sortie.
//
// Le parcours écrit dans la session depuis sa goroutine, et runTUI la lit une
// fois le programme sorti. Après un Ctrl+C, le parcours peut encore tourner
// pendant cette lecture (une dérivation Argon2 ne s'interrompt pas) : d'où le
// verrou.
type session struct {
	mu sync.Mutex
	// echecs compte les opérations ratées : une seule suffit pour sortir en 1.
	echecs int
	// resumes sont les textes qu'une opération imprimait à la fin (✓, nom
	// d'origine, suppression…). Écrits pendant l'écran alternatif, ils
	// disparaîtraient avec lui : on les garde pour les imprimer à la sortie.
	resumes []string
}

// sessionCourante est la session du plein écran, nil en dehors. Posée avant
// le lancement du parcours et jamais remise à nil ensuite : un parcours
// encore en vie après Ctrl+C la lit sans verrou, et le processus sort juste
// après.
var sessionCourante *session

func (s *session) noterEchec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.echecs++
}

func (s *session) noter(resume string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resumes = append(s.resumes, resume)
}

// codeSortie : 0 si tout a réussi, 1 si au moins une opération a échoué. Le
// 130 de Ctrl+C ne passe pas par ici : la session n'a pas fini normalement.
func (s *session) codeSortie() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.echecs > 0 {
		return 1
	}
	return 0
}

// imprimer écrit les résumés recueillis, dans l'ordre, tels qu'ils auraient
// été imprimés sans plein écran.
func (s *session) imprimer(w io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.resumes {
		fmt.Fprint(w, r)
	}
}

// annoncer imprime un résumé d'opération sur w, ou le confie à la session en
// plein écran. Les résumés recueillis sortent tous sur stdout à la fin, même
// ceux qui visaient stderr : à ce moment-là, les deux sont le même terminal.
func annoncer(w io.Writer, format string, args ...any) {
	texte := fmt.Sprintf(format, args...)
	if s := sessionCourante; s != nil {
		s.noter(texte)
		return
	}
	fmt.Fprint(w, texte)
}
