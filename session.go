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
	// debut est l'indice, dans resumes, du premier résumé de l'opération en
	// cours : la carte résultat ne montre que les siens.
	debut int
	// ecritAvantInterruption annonce une sortie déjà posée sur le disque
	// alors que son ✓ n'est pas encore noté : l'opération a fini, mais
	// l'animation continue (au moins 4 s). Ctrl+C à ce moment-là sort sans ✓ ;
	// cette ligne dit au moins que le fichier existe.
	ecritAvantInterruption string
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

// ouvrirOperation marque le début d'une opération : ses résumés seront ceux
// que montre la carte.
func (s *session) ouvrirOperation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.debut = len(s.resumes)
}

// resumesOperation rend une copie des résumés de l'opération en cours. Sans
// session (TERM=dumb, tests), il n'y en a aucun.
func (s *session) resumesOperation() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.resumes[s.debut:]...)
}

// noterEcritAvantInterruption est appelée par la goroutine de l'opération
// dès que la sortie est posée ; confirmerEcrit l'efface quand le ✓ ordinaire
// prend le relais. Seule cette goroutine-là sait l'instant exact : runTUI
// n'attend pas le parcours avant d'imprimer.
func (s *session) noterEcritAvantInterruption(texte string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ecritAvantInterruption = texte
}

func (s *session) confirmerEcrit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ecritAvantInterruption = ""
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
	fmt.Fprint(w, s.ecritAvantInterruption)
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
