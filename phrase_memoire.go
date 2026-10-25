package main

import (
	"errors"

	"github.com/charmbracelet/huh"
)

// Écrans de la phrase gardée pour la session (R-TUI-12) : la question qui la
// garde après une opération réussie, et celle qui la propose à la saisie
// suivante. L'état lui-même vit dans session.go (phraseSession).

// Libellés des deux questions.
const (
	titreGarder        = "garder cette phrase pour la session ?"
	reponseGarder      = "la garder"
	reponseNePasGarder = "ne pas la garder"

	titreUtiliser    = "utiliser la phrase en mémoire ?"
	reponseUtiliser  = "utiliser la phrase en mémoire"
	reponseLaSaisir  = "la saisir"
	descriptionGarde = "proposée à la prochaine saisie ; oubliée après 5 min sans touche, par la touche o, et à la sortie"
)

// phraseCourante rend la phrase de session du plein écran, nil en dehors
// (TERM=dumb, tests sans hôte) : on n'y garde alors jamais rien.
func phraseCourante() *phraseSession {
	s := sessionCourante
	if s == nil || hoteCourant == nil {
		return nil
	}
	return &s.phrase
}

// proposerDeGarder pose, sous la carte de l'opération réussie, la question
// « garder cette phrase pour la session ? ». Le curseur part sur « ne pas la
// garder » : garder un secret en mémoire doit être un choix, jamais un
// réflexe d'entrée. Échap vaut non.
//
// secret n'est que lu : la session en garde sa propre copie, et l'appelant
// efface la sienne comme d'habitude.
func proposerDeGarder(secret []byte) error {
	p := phraseCourante()
	if p == nil || len(secret) == 0 {
		return nil
	}
	garder := false
	champ := questionFermee(titreGarder, descriptionGarde, reponseGarder, reponseNePasGarder, &garder)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	err := lancerQuestionApresResultat("phrase", form)
	if errors.Is(err, errMenu) {
		return nil
	}
	if err != nil {
		return err
	}
	if garder {
		p.garder(secret)
		hoteCourant.signalerPhraseGardee()
	}
	return nil
}

// questionMemoire demande s'il faut utiliser la phrase gardée. saisir vaut
// false par défaut, donc le curseur part sur « utiliser » : la phrase a été
// gardée pour servir. L'accesseur ne dépend pas de l'ordre des options, ce
// qui permet de montrer « utiliser » en premier.
//
// force, s'il n'est pas vide, s'ajoute sous la description : au chiffrement,
// c'est le verdict habituel de l'indicateur (forcePhrase). Déchiffrer ou
// vérifier passe "" : la force n'y changerait rien.
func questionMemoire(saisir *bool, force string) huh.Field {
	description := "gardée pour cette session ; entrée pour l'utiliser"
	if force != "" {
		description += "\n" + force
	}
	return huh.NewSelect[string]().
		Title(titreUtiliser).
		Description(description).
		Options(huh.NewOption(reponseUtiliser, reponseUtiliser), huh.NewOption(reponseLaSaisir, reponseLaSaisir)).
		Accessor(reponseAccessor{valeur: saisir, siOui: reponseLaSaisir, siNon: reponseUtiliser})
}

// passwordFormMemoire est passwordForm précédé de la question de la phrase en
// mémoire. Le champ n'apparaît que sur « la saisir ». La question est l'ancre
// du retour vers le choix de la cible.
func passwordFormMemoire(details string, password *string, saisir *bool) (*huh.Form, huh.Field) {
	question := questionMemoire(saisir, "")
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			question,
		),
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			champMotDePasse(password),
		).WithHideFunc(func() bool { return !*saisir }),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	return form, question
}

// formulaireMotDePasse choisit l'écran du mot de passe : avec la question de
// la phrase en mémoire s'il y en a une, l'écran habituel sinon. Rend aussi si
// la question a été posée.
func formulaireMotDePasse(details string, password *string, saisir *bool) (*huh.Form, huh.Field, bool) {
	if phraseCourante().active() {
		form, ancre := passwordFormMemoire(details, password, saisir)
		return form, ancre, true
	}
	form, ancre := passwordForm(details, password)
	return form, ancre, false
}

// forcePhrase rend le verdict de strengthHint pour la phrase gardée, "" s'il
// n'y en a pas (ou plus).
//
// Le calcul se fait sur une copie prise, mise à zéro aussitôt. zxcvbn ne lit
// que des chaînes : une conversion en string reste inévitable — une seule
// ici, plus les découpes que zxcvbn fait lui-même. Comme toute string Go,
// elles ne s'effacent pas et vivent jusqu'au passage du ramasse-miettes,
// exactement comme le mot de passe saisi (o.password).
func forcePhrase(p *phraseSession) string {
	copie, ok := p.prendre()
	if !ok {
		return ""
	}
	defer zero(copie)
	return strengthHint(string(copie))
}

// secretPourOperation rend la copie effaçable du secret de l'opération, que
// l'appelant met à zéro : celle de la session si l'utilisateur l'a choisie,
// la saisie sinon. ok vaut false si la phrase choisie a été oubliée entre la
// question et ce moment (délai, touche o) : il faut alors redemander.
func secretPourOperation(depuisSession bool, saisie string) (secret []byte, ok bool) {
	if depuisSession {
		return phraseCourante().prendre()
	}
	return []byte(saisie), true
}

// depuisLaSession dit si le chiffrement utilisera la phrase en mémoire : elle
// était proposée, et l'utilisateur ne l'a pas écartée.
func depuisLaSession(o *optionsChiffrement) bool {
	return o.memoire && !o.saisirMalgreMemoire
}
