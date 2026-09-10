package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/huh"
)

// Banc d'essai de la grammaire de navigation, écran par écran.
//
// Le README promet la même grammaire partout : ↑↓ parcourent les réponses, →
// (ou entrée) valide, ← revient à la décision précédente — sauf dans un champ
// texte et dans l'explorateur, où ← appartient au curseur et où le retour se
// fait avec shift+tab.
//
// Ces tests existent parce qu'un écart y est passé inaperçu : → ne validait pas
// la dernière question d'un écran, ce qui rendait l'explorateur inatteignable.
// L'écart venait de huh, pas du code appelant, donc seule une vérification
// écran par écran pouvait le voir.

// ecranTeste décrit un écran et ce que sa dernière question doit accepter.
type ecranTeste struct {
	nom string
	// monter construit l'écran et rend son formulaire, l'ancre du retour, et
	// les touches à envoyer pour atteindre la dernière question.
	monter func(t *testing.T) (*huh.Form, huh.Field, []string)
	// toucheRetour est celle qui doit ramener à l'écran précédent.
	toucheRetour string
	// valideAuClavier dit si la dernière question se valide par → et entrée.
	// Faux pour l'explorateur, où → ouvre un dossier : exception documentée.
	valideAuClavier bool
}

func ecransDeLInterface() []ecranTeste {
	return []ecranTeste{
		{
			nom: "choix de l'opération et de la cible",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				action, mode := "enc", "saisie"
				return choixForm(&action, &mode), nil, []string{"right"}
			},
			toucheRetour:    "",
			valideAuClavier: true,
		},
		{
			nom: "cible par saisie du chemin",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				path := ""
				form, ancre := cibleForm("enc", "saisie", &path)
				return form, ancre, nil
			},
			toucheRetour:    "shift+tab",
			valideAuClavier: false, // un chemin vide est refusé par la validation
		},
		{
			nom: "cible par l'explorateur",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				path := ""
				form, ancre := cibleForm("enc", "parcourir", &path)
				return form, ancre, nil
			},
			toucheRetour:    "shift+tab",
			valideAuClavier: false, // → ouvre un dossier, entrée choisit
		},
		{
			nom: "options de chiffrement",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				o := optionsChiffrement{}
				appliquerDefauts(&o, false)
				form, ancre := encryptForm(&o, false, 1024)
				return form, ancre, nil
			},
			toucheRetour:    "left",
			valideAuClavier: false, // se termine par les saisies de mot de passe
		},
		{
			nom: "mot de passe au déchiffrement",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				password := ""
				form, ancre := passwordForm("format v4 · aes-256-gcm", &password)
				return form, ancre, nil
			},
			toucheRetour:    "shift+tab",
			valideAuClavier: false, // un mot de passe vide est refusé
		},
		{
			nom: "question fermée : écrasement",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				var rep bool
				champ := questionFermee("écraser la destination ?", "elle existe déjà",
					"écraser", "annuler", &rep)
				return formulaireQuestion(champ), champ, nil
			},
			toucheRetour:    "left",
			valideAuClavier: true,
		},
		{
			nom: "question fermée : suppression après coup",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				var rep bool
				champ := questionFermee("supprimer l'original ?", "il vient d'être chiffré",
					"supprimer", "garder", &rep)
				return formulaireQuestion(champ), champ, nil
			},
			toucheRetour:    "left",
			valideAuClavier: true,
		},
		{
			nom: "question fermée : restitution du nom",
			monter: func(t *testing.T) (*huh.Form, huh.Field, []string) {
				var rep bool
				champ := questionFermee("lui rendre son nom ?", "il est enregistré sous a3f9.chto",
					"renommer", "garder", &rep)
				return formulaireQuestion(champ), champ, nil
			},
			toucheRetour:    "left",
			valideAuClavier: true,
		},
	}
}

// formulaireQuestion monte un écran à question unique comme le fait l'interface.
func formulaireQuestion(champ huh.Field) *huh.Form {
	return huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
}

// TestAuditValidationAuClavier : sur chaque écran dont la dernière question est
// une liste, → et entrée doivent tous deux valider. C'est la promesse du
// README, et c'est elle qui manquait.
func TestAuditValidationAuClavier(t *testing.T) {
	for _, ecran := range ecransDeLInterface() {
		if !ecran.valideAuClavier {
			continue
		}
		for _, validation := range []string{"right", "enter"} {
			t.Run(ecran.nom+" / "+validation, func(t *testing.T) {
				form, ancre, chemin := ecran.monter(t)
				m := ouvrirEtape(t, form, ancre)
				for _, k := range chemin {
					envoyerEtape(t, m, touche(k))
				}
				envoyerEtape(t, m, touche(validation))
				if m.form.State != huh.StateCompleted {
					t.Errorf("« %s » ne valide pas avec %s", ecran.nom, validation)
				}
			})
		}
	}
}

// TestAuditRetourEnArriere : chaque écran qui a un précédent doit y revenir, et
// avec la touche que l'interface annonce — ← en général, shift+tab là où ←
// appartient déjà au curseur ou à l'explorateur.
func TestAuditRetourEnArriere(t *testing.T) {
	for _, ecran := range ecransDeLInterface() {
		if ecran.toucheRetour == "" {
			continue
		}
		t.Run(ecran.nom, func(t *testing.T) {
			form, ancre, chemin := ecran.monter(t)
			m := ouvrirEtape(t, form, ancre)
			for _, k := range chemin {
				envoyerEtape(t, m, touche(k))
			}
			envoyerEtape(t, m, touche(ecran.toucheRetour))
			if !m.retour {
				t.Errorf("« %s » : %s ne revient pas à l'écran précédent", ecran.nom, ecran.toucheRetour)
			}
		})
	}
}

// TestAuditDeplacementDansLesListes : ↑↓ doivent parcourir les réponses de tout
// écran qui en propose. Une liste bloquée renverrait l'utilisateur à la souris,
// qui n'existe pas ici.
func TestAuditDeplacementDansLesListes(t *testing.T) {
	var rep bool
	champ := questionFermee("supprimer l'original ?", "il vient d'être chiffré",
		"supprimer", "garder", &rep)
	m := ouvrirEtape(t, formulaireQuestion(champ), champ)

	// « garder » est la réponse sous le curseur : ↑ doit atteindre « supprimer ».
	envoyerEtape(t, m, touche("up"))
	envoyerEtape(t, m, touche("enter"))
	if !rep {
		t.Error("↑ puis entrée ne sélectionne pas la première réponse")
	}
}

// TestAuditExplorateurFleches : dans l'explorateur, ↑↓ se déplacent, → entre
// dans un dossier et ← en ressort. C'est l'écran où le bug se voyait.
func TestAuditExplorateurFleches(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sous_dossier"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sous_dossier", "dedans.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a_la_racine.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	precedent, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(precedent)

	path := ""
	form, ancre := cibleForm("enc", "parcourir", &path)
	m := ouvrirEtape(t, form, ancre)

	if vue := m.form.View(); !strings.Contains(vue, "sous_dossier") || !strings.Contains(vue, "a_la_racine.txt") {
		t.Fatalf("l'explorateur n'ouvre pas sur le dossier courant:\n%s", vue)
	}
	// → entre dans le dossier sous le curseur.
	envoyerEtape(t, m, touche("right"))
	if vue := m.form.View(); !strings.Contains(vue, "dedans.txt") {
		t.Errorf("→ n'entre pas dans le dossier:\n%s", vue)
	}
	// ← en ressort.
	envoyerEtape(t, m, touche("left"))
	if vue := m.form.View(); !strings.Contains(vue, "a_la_racine.txt") {
		t.Errorf("← ne remonte pas d'un dossier:\n%s", vue)
	}
	if m.retour {
		t.Error("← a quitté l'écran au lieu de remonter d'un dossier")
	}
}
