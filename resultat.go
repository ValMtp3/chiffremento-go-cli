package main

import (
	"errors"
	"os"
	"strings"

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
	titre   string
	corps   string
	largeur int
}

// carteResultat montre les résumés d'une opération réussie.
func carteResultat(lignes []string) sousEcran {
	return &ecranResultat{titre: "résultat", corps: corpsCarte(lignes)}
}

// ecranErreur montre la cause d'un échec, puis quoi faire quand un conseil
// existe. Aucun texte n'est inventé ici : le conseil vient de l'erreur
// elle-même — les lignes qui suivent sa cause — ou d'indiceForce.
func ecranErreur(err error) sousEcran {
	return ecranErreurApres(nil, err)
}

// ecranErreurApres est ecranErreur précédé des résumés déjà notés par
// l'opération : un chiffrement réussi dont la suppression échoue doit encore
// montrer son ✓.
func ecranErreurApres(lignes []string, err error) sousEcran {
	cause, conseil := causeEtConseil(err)
	var b strings.Builder
	if avant := corpsCarte(lignes); avant != "" {
		b.WriteString(avant)
		b.WriteString("\n\n")
	}
	// Même retrait de deux colonnes que les résumés (« ✓ ») : tout s'aligne
	// quand l'erreur suit un résumé.
	b.WriteString("  " + styleError.Render("échec :") + " " + styleText.Render(cause))
	if conseil != "" {
		b.WriteString("\n\n  " + styleDim.Render("quoi faire"))
		for _, ligne := range strings.Split(conseil, "\n") {
			b.WriteString("\n  " + styleText.Render(ligne))
		}
	}
	return &ecranResultat{titre: "erreur", corps: b.String()}
}

// causeEtConseil sépare la première ligne d'une erreur, sa cause, des
// suivantes, qui disent quoi faire (conseilSauvegarde, suppression refusée…).
//
// Seul le conseil d'indiceForce vit hors de l'erreur : il est repris tel
// quel. Son « relance avec -force » ne parle pas à l'interface, mais c'est le
// message existant, et une destination déjà prise n'arrive ici que si elle
// est apparue entre la question de l'écrasement et l'écriture.
//
// Les lignes du conseil perdent leur retrait commun de deux espaces, pas
// leur retrait relatif : les sous-cas de conseilSauvegarde restent décalés.
func causeEtConseil(err error) (cause, conseil string) {
	cause, reste, _ := strings.Cut(err.Error(), "\n")
	if errors.Is(err, pkg.ErrDestinationExistante) {
		// indiceForce ajoute son conseil après « <erreur> : ».
		reste = strings.TrimPrefix(indiceForce(err).Error(), err.Error()+" : ") + "\n" + reste
	}
	var lignes []string
	for _, l := range strings.Split(reste, "\n") {
		if strings.TrimSpace(l) != "" {
			lignes = append(lignes, strings.TrimPrefix(l, "  "))
		}
	}
	return cause, strings.Join(lignes, "\n")
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
func (e *ecranResultat) View() string { return replier(e.corps, e.largeur) }

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

// enCours mène travail en montrant texte dans le cadre. Hors plein écran,
// elle se contente de le mener.
//
// Comme runJobDansHote, elle ne rend la main qu'une fois le travail fini,
// même après Ctrl+C : l'appelant efface ensuite les mots de passe, que le
// travail lit peut-être encore.
func enCours(titre, texte string, travail func() error) error {
	h := hoteCourant
	if h == nil || os.Getenv("TERM") == "dumb" {
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
	_, errEcran := h.afficher(&ecranEnCours{titre: titre, texte: texte, fini: fini})
	<-fini
	if errEcran != nil {
		return errEcran
	}
	return err
}
