package main

import (
	"errors"
	"io/fs"
	"strings"
	"time"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Fin d'opération dans le cadre : la carte résultat (✓, fichier produit,
// détails), l'écran d'erreur (cause, puis quoi faire), et l'écran « en
// cours » des travaux qui n'ont pas de progression à montrer.
//
// Les textes de la carte sont les résumés que l'opération imprimait avant le
// plein écran, recueillis par la session (annoncer) : ils sont réimprimés
// tels quels à la sortie de l'écran alternatif.

// touchesResultat est la barre du bas de la carte et de l'écran d'erreur.
const touchesResultat = "⏎ revenir au menu"

// ecranResultat affiche un texte fixe ; ⏎ le referme. Échap aussi, par
// l'hôte : les deux mènent au menu.
type ecranResultat struct {
	titre string
	corps string
	// erreur est le bloc de l'échec (cause, quoi faire), sans retrait :
	// View le replie avec un retrait de deux colonnes, que chaque ligne
	// repliée garde.
	erreur  string
	largeur int
}

// carteResultat montre les résumés d'une opération réussie.
func carteResultat(lignes []string) sousEcran {
	return &ecranResultat{titre: "résultat", corps: corpsCarte(lignes)}
}

// ecranErreurApres montre la cause d'un échec, puis quoi faire quand un
// conseil existe : celui de l'erreur elle-même — les lignes qui suivent sa
// cause —, ou celui d'une erreur courante (conseilCourant). Les résumés déjà
// notés par l'opération passent avant (nil s'il n'y en a pas) : un
// chiffrement réussi dont la suppression échoue doit encore montrer son ✓.
func ecranErreurApres(lignes []string, err error) sousEcran {
	cause, conseil := causeEtConseil(err)
	var b strings.Builder
	b.WriteString(styleError.Render("échec :") + " " + styleText.Render(cause))
	if conseil != "" {
		b.WriteString("\n\n" + styleDim.Render("quoi faire"))
		for _, ligne := range strings.Split(conseil, "\n") {
			b.WriteString("\n" + styleText.Render(ligne))
		}
	}
	return &ecranResultat{titre: "erreur", corps: corpsCarte(lignes), erreur: b.String()}
}

// Conseils courts des erreurs courantes, quand l'erreur n'en porte pas.
const (
	conseilDestinationApparue = "la destination vient d'apparaître : déplace-la ou renomme-la, puis réessaie"
	conseilMauvaisePhrase     = "vérifie la phrase (majuscules, séparateurs, disposition du clavier), puis réessaie"
	conseilFichierAbime       = "le fichier est abîmé ou n'est pas un fichier chiffremento : repars d'une copie intacte"
	conseilAncienFormat       = "sur un fichier d'ancien format, une mauvaise phrase donne la même erreur : vérifie-la aussi"
	conseilPermission         = "vérifie les droits sur le fichier ou le dossier, ou choisis un autre emplacement"
)

// causeEtConseil sépare la première ligne d'une erreur, sa cause, des
// suivantes, qui disent quoi faire (conseilSauvegarde, suppression refusée…).
//
// Le conseil porté par l'erreur passe toujours en premier, et seul : il
// connaît la situation (« x n'a pas été supprimé… »). Sans lui, les erreurs
// courantes reçoivent un conseil court (conseilCourant).
//
// Les lignes du conseil perdent leur retrait commun de deux espaces, pas
// leur retrait relatif : les sous-cas de conseilSauvegarde restent décalés.
func causeEtConseil(err error) (cause, conseil string) {
	cause, reste, _ := strings.Cut(err.Error(), "\n")
	var lignes []string
	for _, l := range strings.Split(reste, "\n") {
		if strings.TrimSpace(l) != "" {
			lignes = append(lignes, strings.TrimPrefix(l, "  "))
		}
	}
	if len(lignes) == 0 {
		return cause, conseilCourant(err)
	}
	return cause, strings.Join(lignes, "\n")
}

// conseilCourant rend le conseil d'une erreur courante, "" sinon.
//
// Une destination déjà prise n'arrive ici que si elle est apparue entre la
// question de l'écrasement et l'écriture : l'interface n'a pas de -force, le
// conseil d'indiceForce n'y aurait pas de sens.
func conseilCourant(err error) string {
	switch {
	case errors.Is(err, pkg.ErrDestinationExistante):
		return conseilDestinationApparue
	case errors.Is(err, pkg.ErrBadPassword):
		return conseilMauvaisePhrase
	case pkg.ContenuNonAuthentifie(err):
		return conseilFichierAbime + "\n" + conseilAncienFormat
	case pkg.FichierAbime(err):
		return conseilFichierAbime
	case errors.Is(err, fs.ErrPermission):
		return conseilPermission
	}
	return ""
}

// corpsCarte assemble les résumés comme ils s'imprimeraient, sans les lignes
// vides de la fin.
func corpsCarte(lignes []string) string {
	return strings.TrimRight(strings.Join(lignes, ""), "\n")
}

func (e *ecranResultat) Init() tea.Cmd { return nil }

func (e *ecranResultat) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		e.largeur = msg.Width
	case tea.KeyMsg:
		if msg.Type == tea.KeyEnter {
			return e, tea.Quit
		}
	}
	return e, nil
}

// View replie le texte au mot près à la largeur du cadre plutôt que de le
// laisser couper : un chemin long reste lisible en entier.
func (e *ecranResultat) View() string {
	vue := replier(e.corps, e.largeur)
	if e.erreur == "" {
		return vue
	}
	if vue != "" {
		vue += "\n\n"
	}
	return vue + replierEnRetrait(e.erreur, e.largeur)
}

// retraitErreur : même retrait de deux colonnes que les résumés (« ✓ ») —
// tout s'aligne quand l'erreur suit un résumé.
const retraitErreur = 2

// replierEnRetrait replie texte à largeur colonnes, retrait compris : chaque
// ligne, repliée ou non, commence par retraitErreur espaces. Le retrait
// relatif d'une ligne (un sous-cas décalé) est gardé.
func replierEnRetrait(texte string, largeur int) string {
	if largeur <= retraitErreur {
		marge := strings.Repeat(" ", retraitErreur)
		return marge + strings.ReplaceAll(texte, "\n", "\n"+marge)
	}
	return lipgloss.NewStyle().PaddingLeft(retraitErreur).Width(largeur).Render(texte)
}

func (e *ecranResultat) Titre() string   { return e.titre }
func (e *ecranResultat) Touches() string { return touchesResultat }

// replier coupe le texte au mot près à largeur colonnes ; sans largeur
// connue, il le rend tel quel.
func replier(texte string, largeur int) string {
	if largeur <= 0 {
		return texte
	}
	return lipgloss.NewStyle().Width(largeur).Render(texte)
}

// ecranEnCours occupe le cadre pendant un travail sans progression. Il se
// ferme de lui-même à la fin du travail : aucun minuteur, Init attend
// simplement le signal.
type ecranEnCours struct {
	titre, texte string
	fini         <-chan struct{}
}

func (e *ecranEnCours) Init() tea.Cmd {
	return func() tea.Msg {
		<-e.fini
		return tea.QuitMsg{}
	}
}

func (e *ecranEnCours) Update(tea.Msg) (tea.Model, tea.Cmd) { return e, nil }
func (e *ecranEnCours) View() string                        { return styleDim.Render(e.texte) }
func (e *ecranEnCours) Titre() string                       { return e.titre }
func (e *ecranEnCours) Touches() string                     { return "" }

// gardeEchap : le travail est lancé, il ne s'abandonne plus — un en-tête à
// moitié réécrit serait pire qu'une attente.
func (e *ecranEnCours) gardeEchap() bool { return true }

// seuilEcranEnCours : en deçà, un travail se fait sans écran « en cours ».
// Une image dure 33 ms à 30 images/s ; 100 ms, c'est en dessous de ce que
// l'œil attend d'une réponse, et au-dessus d'une lecture d'en-tête.
const seuilEcranEnCours = 100 * time.Millisecond

// enCours mène travail en montrant texte dans le cadre. Hors plein écran,
// elle se contente de le mener.
//
// Comme runJobDansHote, elle ne rend la main qu'une fois le travail fini,
// même après Ctrl+C : l'appelant efface ensuite les mots de passe, que le
// travail lit peut-être encore.
func enCours(titre, texte string, travail func() error) error {
	h := hoteDuCadre()
	if h == nil {
		return travail()
	}
	// Ctrl+C a pu fermer l'hôte juste avant : rien ne doit commencer pendant
	// que le processus sort.
	select {
	case <-h.termine:
		return huh.ErrUserAborted
	default:
	}
	fini := make(chan struct{})
	var err error
	go func() {
		defer close(fini)
		err = travail()
	}()
	// Un travail bref (la lecture d'un en-tête) finit avant le seuil : aucun
	// écran, il ne ferait que clignoter une image. Le minuteur n'existe que
	// pendant le travail.
	seuil := time.NewTimer(seuilEcranEnCours)
	defer seuil.Stop()
	select {
	case <-fini:
		return err
	case <-seuil.C:
	}
	_, errEcran := h.afficher(&ecranEnCours{titre: titre, texte: texte, fini: fini})
	<-fini
	if errEcran != nil {
		return errEcran
	}
	return err
}
