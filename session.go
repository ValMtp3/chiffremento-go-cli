package main

import (
	"fmt"
	"io"
	"sync"
	"time"
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
	// phrase est la phrase gardée pour la session, si l'utilisateur l'a
	// voulu. Elle a son propre verrou : l'interface la lit à chaque image.
	phrase phraseSession
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

// Phrase gardée pour la session.
//
// Après une opération réussie, l'utilisateur peut garder la phrase qu'il vient
// de saisir : elle lui est proposée à la saisie suivante, comme un trousseau
// qu'on laisse sur la table le temps de ranger la maison, et qu'on reprend dès
// qu'on s'absente. Elle est oubliée — octets mis à zéro — après delaiOubli
// sans aucune touche, par la touche o, et à la sortie.
//
// Seule la phrase est gardée, jamais la clé qui en dérive : Argon2 tourne à
// chaque opération, et une clé n'ouvrirait de toute façon qu'un seul fichier,
// chacun ayant son sel.
//
// Deux goroutines s'en servent : le parcours garde et prend, l'interface
// repousse l'échéance et oublie. D'où le verrou, tenu le temps d'une copie au
// plus.

// delaiOubli : sans touche pendant ce délai, la phrase est oubliée.
const delaiOubli = 5 * time.Minute

type phraseSession struct {
	mu       sync.Mutex
	octets   []byte
	echeance time.Time
	// fermee : la session est finie, plus rien ne sera gardé. Un parcours
	// encore en vie après Ctrl+C ne doit pas reposer une phrase après
	// l'oubli de la sortie.
	fermee bool
	// horloge rend l'heure : time.Now en vrai, une horloge de test sinon.
	horloge func() time.Time
}

// maintenant rend l'heure murale, sans lecture monotone (Round(0)). Sous
// macOS, l'horloge monotone de Go s'arrête pendant la veille : avec elle, une
// heure de capot fermé ne compterait pas, et la phrase survivrait bien
// au-delà des 5 minutes annoncées. L'heure murale, elle, avance.
func (p *phraseSession) maintenant() time.Time {
	if p.horloge != nil {
		return p.horloge().Round(0)
	}
	return time.Now().Round(0)
}

// garder remplace la phrase gardée par une copie de secret : l'appelant reste
// libre d'effacer la sienne. L'ancienne est mise à zéro avant d'être lâchée.
func (p *phraseSession) garder(secret []byte) {
	if p == nil || len(secret) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fermee {
		return
	}
	zero(p.octets)
	p.octets = append(make([]byte, 0, len(secret)), secret...)
	p.echeance = p.maintenant().Add(delaiOubli)
}

// prendre rend une copie neuve de la phrase, que l'appelant met à zéro après
// usage : celle de la session peut être oubliée pendant qu'il s'en sert.
func (p *phraseSession) prendre() ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.activeVerrouillee() {
		return nil, false
	}
	return append(make([]byte, 0, len(p.octets)), p.octets...), true
}

// oublier met la phrase à zéro. Sans effet s'il n'y en a pas.
func (p *phraseSession) oublier() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.oublierVerrouillee()
}

// fermer oublie la phrase pour de bon : plus rien ne sera gardé ensuite.
func (p *phraseSession) fermer() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.oublierVerrouillee()
	p.fermee = true
}

func (p *phraseSession) oublierVerrouillee() {
	zero(p.octets)
	p.octets, p.echeance = nil, time.Time{}
}

// active dit si une phrase est gardée. Une phrase dont l'échéance est passée
// ne l'est plus, même si le minuteur ne l'a pas encore effacée : elle ne doit
// plus servir.
func (p *phraseSession) active() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.activeVerrouillee()
}

func (p *phraseSession) activeVerrouillee() bool {
	return len(p.octets) > 0 && p.maintenant().Before(p.echeance)
}

// repousser : une touche vient d'être pressée, l'échéance recule d'autant.
// Une phrase déjà échue n'est pas ranimée : elle est effacée sur-le-champ.
// C'est le cas au réveil d'une mise en veille, où le minuteur, compté sur
// l'horloge monotone, arrive en retard.
func (p *phraseSession) repousser() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activeVerrouillee() {
		p.echeance = p.maintenant().Add(delaiOubli)
		return
	}
	p.oublierVerrouillee()
}

// restant dit combien de temps la phrase a encore à vivre. Une phrase dont
// l'échéance est atteinte est oubliée sur-le-champ, et restant rend false :
// il n'y a plus rien à attendre.
func (p *phraseSession) restant() (time.Duration, bool) {
	if p == nil {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.activeVerrouillee() {
		p.oublierVerrouillee()
		return 0, false
	}
	return p.echeance.Sub(p.maintenant()), true
}
