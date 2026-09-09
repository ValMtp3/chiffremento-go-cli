package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"chiffremento-cli/pkg"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/trustelem/zxcvbn"
	"golang.org/x/term"
)

// isInteractive n'autorise la TUI que si les deux extrémités sont un
// terminal. Sinon on tomberait en marche dans un pipe ou un job de CI.
func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// runTUI enchaîne les formulaires puis l'écran de progression.
//
// Deux formulaires successifs et non un seul à groupes masqués : le second est
// donc construit *après* que l'opération et le mode de saisie sont connus. Ça
// évite tout un nid de guêpes — un champ dont la configuration dépend d'un choix
// pas encore fait, et un explorateur que huh replie dès qu'on tente de revenir
// en arrière, laissant l'utilisateur devant une liste disparue.
//
// Le prix de ce découpage, c'est que la marche arrière est à notre charge :
// huh ne recule qu'à l'intérieur d'un formulaire. D'où les deux boucles — un
// écran qui rend errRetour renvoie à celui d'avant, et les réponses déjà
// données restent dans les variables, donc à l'écran.
func runTUI() error {
	action := "enc"
	mode := "saisie"
	path := ""
	// Les options de chiffrement vivent ici, et non dans tuiEncrypt : un « ← » de
	// trop sur la première question repasse par la boucle ci-dessous, et des
	// options déclarées plus bas seraient reconstruites à zéro — les neuf
	// réponses déjà données, mot de passe compris, disparaîtraient alors que la
	// grammaire de navigation promet le contraire.
	//
	// Elles sont en revanche remises à neuf quand la cible change : le choix de
	// compresser suit le fait que ce soit un dossier ou un fichier, et le nom du
	// fichier a pu peser sur les autres réponses.
	var options optionsChiffrement
	optionsPour := ""
	for {
		// Premier écran : rien derrière lui, donc aucune ancre de retour.
		if err := lancerEtape(choixForm(&action, &mode), nil); err != nil {
			return err
		}

		for {
			err := etapeCible(action, mode, &path)
			if errors.Is(err, errRetour) {
				break // retour au choix de l'opération
			}
			if err != nil {
				return err
			}

			switch action {
			case "dec":
				err = tuiDecrypt(path)
			case "verify":
				err = tuiVerify(path)
			case "passwd":
				err = tuiPasswd(path)
			default:
				if path != optionsPour {
					options, optionsPour = optionsChiffrement{}, path
				}
				err = tuiEncrypt(path, &options)
			}
			if errors.Is(err, errRetour) {
				continue // retour au choix de la cible
			}
			return err
		}
	}
}

// etapeCible demande la cible jusqu'à en obtenir une.
//
// La boucle est là parce que l'explorateur tolère une sélection vide pour ne
// pas bloquer la navigation : le formulaire se termine donc parfois sans rien
// proposer, et on le réaffiche au lieu de laisser filer un chemin vide vers une
// erreur obscure plus loin.
func etapeCible(action, mode string, path *string) error {
	for {
		form, ancre := cibleForm(action, mode, path)
		if err := lancerEtape(form, ancre); err != nil {
			return err
		}
		*path = trimTrailingSeparator(strings.TrimSpace(expandHome(devirerGuillemets(*path))))
		if *path != "" {
			return nil
		}
	}
}

// choixForm demande l'opération et la façon de désigner la cible.
func choixForm(action *string, mode *string) *huh.Form {
	return huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Key("action").
				Title("opération").
				Options(
					huh.NewOption("chiffrer un fichier ou un dossier", "enc"),
					huh.NewOption("déchiffrer un "+extension+"  (fichier ou dossier)", "dec"),
					huh.NewOption("vérifier un "+extension+"  (sans rien écrire)", "verify"),
					huh.NewOption("changer le mot de passe d'un "+extension, "passwd"),
				).
				Value(action),

			huh.NewSelect[string]().
				Key("mode").
				Title("désigner la cible").
				Options(
					huh.NewOption("saisir un chemin  (ou glisser-déposer)", "saisie"),
					huh.NewOption("parcourir les fichiers", "parcourir"),
				).
				Value(mode),
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
}

// cibleForm demande la cible, au clavier ou en naviguant. L'opération est déjà
// connue : le champ peut donc s'annoncer précisément.
//
// Le champ est rendu avec le formulaire : c'est l'ancre du retour en arrière,
// et lancerEtape a besoin de le reconnaître pour savoir qu'on est bien au
// premier champ de l'écran.
func cibleForm(action, mode string, path *string) (*huh.Form, huh.Field) {
	var champ huh.Field
	if mode == "parcourir" {
		champ = filePickerField(action, path)
	} else {
		champ = huh.NewInput().
			Key("path").
			Title(cibleTitre(action)).
			Placeholder(ciblePlaceholder(action)).
			Value(path).
			Validate(func(s string) error { return validateTarget(s, action) })
	}
	form := huh.NewForm(huh.NewGroup(champ)).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	return form, champ
}

// filePickerField construit l'explorateur. Il vient de huh, donc de bubbles :
// aucune dépendance nouvelle.
//
// Picking(true) est essentiel : sans lui, le champ affiche « No file selected. »
// et il faut appuyer sur une touche pour ouvrir l'arborescence. On veut la liste
// tout de suite — c'est la raison d'être du mode « parcourir ».
//
// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à choisir
// un fichier et vole la place du nom. La taille, elle, sert. Les fichiers cachés
// sont visibles parce que c'est précisément le genre de fichier qu'on chiffre —
// une clé dans ~/.ssh, un fichier de configuration.
//
// Les dossiers ne sont sélectionnables qu'au chiffrement : ailleurs, seul un
// .chto a un sens. `validateTarget` reste l'autorité sur le reste, avec ses
// messages en français — `AllowedTypes` afficherait les siens en anglais et
// ferait exister deux règles là où il n'en faut qu'une.
func filePickerField(action string, path *string) huh.Field {
	// L'ordre des appels compte, et c'est un vrai piège de huh.
	//
	// NewFilePicker lit déjà le dossier à la construction. ShowHidden et Height
	// doivent donc venir en premier : posés plus loin dans la chaîne, le premier
	// n'a aucun effet — les fichiers cachés restent invisibles — et le second
	// soustrait la hauteur d'un titre rendu sans thème, ce qui ne laisse qu'une
	// seule ligne de liste. Dans les deux cas, rien ne plante : l'explorateur est
	// simplement inutilisable. TestCibleFormExplorateurListeAssezDEntrees garde
	// ces deux propriétés.
	//
	// Les fichiers cachés sont montrés parce que c'est précisément le genre de
	// fichier qu'on chiffre : une clé dans ~/.ssh, un fichier de configuration.
	return huh.NewFilePicker().
		ShowHidden(true).
		Height(16).
		Key("picker").
		Title(cibleTitre(action)).
		Description("↑↓ se déplacer · → ouvrir un dossier · ← remonter · entrée choisir").
		CurrentDirectory(".").
		// Picking : sans lui, le champ affiche « No file selected. » et il faut
		// appuyer sur une touche pour déplier l'arborescence. On veut la liste
		// tout de suite — c'est la raison d'être du mode « parcourir ».
		Picking(true).
		// Un dossier n'est une cible qu'au chiffrement ; ailleurs, seul un .chto
		// a un sens.
		DirAllowed(action == "enc").
		FileAllowed(true).
		// Les permissions ne sont pas affichées : `drwxr-xr-x` n'aide personne à
		// choisir un fichier et vole la place du nom. La taille, elle, sert.
		ShowSize(true).
		ShowPermissions(false).
		Value(path).
		// Une sélection vide ne bloque pas la navigation : sinon huh refuse de
		// quitter le champ tout en repliant la liste, et l'utilisateur se
		// retrouve devant un écran vide sans comprendre pourquoi. Le reste est
		// tranché par validateTarget, avec ses messages en français.
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return nil
			}
			return validateTarget(s, action)
		})
}

// cibleTitre nomme ce qu'on attend selon l'opération.
func cibleTitre(action string) string {
	switch action {
	case "enc":
		return "fichier ou dossier à chiffrer"
	case "passwd":
		return "fichier " + extension + " dont changer le mot de passe"
	default:
		return "fichier " + extension + " à lire"
	}
}

func ciblePlaceholder(action string) string {
	if action == "enc" {
		return "chemin, ou glisser-déposer le fichier ou le dossier"
	}
	return "chemin du fichier " + extension + ", ou glisser-déposer"
}

// validateTarget refuse tout de suite les cas qui échoueraient plus loin :
// chemin absent, dossier là où seul un .chto a du sens, ou extension
// incohérente avec l'opération.
func validateTarget(s, action string) error {
	s = trimTrailingSeparator(strings.TrimSpace(expandHome(s)))
	if s == "" {
		return errors.New("indique un fichier ou un dossier")
	}
	info, err := os.Stat(s)
	if err != nil {
		return errors.New("chemin introuvable")
	}
	if info.IsDir() && action != "enc" {
		return errors.New("c'est un dossier : seul un fichier " + extension + " peut être déchiffré ou vérifié")
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return errors.New("ce n'est ni un fichier régulier ni un dossier")
	}
	if action != "enc" && !strings.HasSuffix(s, extension) {
		return errors.New("ce fichier doit porter l'extension " + extension)
	}
	if action == "enc" && strings.HasSuffix(s, extension) {
		return errors.New("ce fichier est déjà chiffré")
	}
	return nil
}

// optionsChiffrement porte les réponses de l'écran des options. Un struct et
// non sept variables locales : l'écran est reconstruit à l'identique quand on y
// revient depuis la confirmation d'écrasement, et il doit alors rouvrir sur les
// réponses déjà données.
type optionsChiffrement struct {
	algo       byte
	kdf        pkg.KDFProfile
	compresser bool
	pad        bool
	padNiveau  pkg.PadProfile
	garderMeta bool
	brouiller  bool
	password   string
	confirm    string
}

// encryptForm construit l'écran des options. Il rend aussi son premier champ :
// c'est l'ancre du retour vers le choix de la cible.
func encryptForm(o *optionsChiffrement, estDossier bool, tailleClair int64) (*huh.Form, huh.Field) {
	algoChamp := huh.NewSelect[byte]().
		Title("algorithme").
		Options(
			huh.NewOption("aes-256-gcm  (défaut)", pkg.AlgoAES),
			huh.NewOption("chacha20-poly1305", pkg.AlgoChaCha),
			huh.NewOption("cascade  chacha20 + aes  (parano)", pkg.AlgoCascade),
		).
		Value(&o.algo)

	form := huh.NewForm(
		huh.NewGroup(
			algoChamp,

			// La description montre la mémoire exigée, parce qu'elle le sera
			// aussi au déchiffrement : un fichier scellé en « maximum » ici sera
			// illisible sur une machine qui n'a pas 1 Gio à y consacrer.
			huh.NewSelect[pkg.KDFProfile]().
				Title("coût de la dérivation de clé").
				DescriptionFunc(func() string { return kdfHint(o.kdf) }, &o.kdf).
				Options(
					huh.NewOption("standard  (défaut)", pkg.KDFStandard),
					huh.NewOption("fort", pkg.KDFFort),
					huh.NewOption("maximum", pkg.KDFMaximum),
				).
				Value(&o.kdf),

			ouiNon("compresser avant chiffrement  (zstd)", compressHint(estDossier), &o.compresser),
		),

		// Le masquage de taille vit dans son propre groupe, escamoté dès qu'une
		// compression est choisie : proposer une option pour la refuser ensuite
		// est une impasse, autant ne pas la montrer. Un groupe masqué est aussi
		// sauté à la navigation, donc l'utilisateur passe directement au mot de
		// passe.
		huh.NewGroup(
			ouiNon("masquer la taille réelle",
				"arrondit la taille au palier supérieur (jusqu'à ~12 % de disque en plus)",
				&o.pad),
		).WithHideFunc(func() bool { return o.compresser }),

		// La largeur du palier est le seul réglage qui compte : elle décide
		// combien de fichiers sortent à la même taille, et ce que ça coûte. La
		// description l'exprime sur *ce* fichier — un pourcentage abstrait ne
		// dit rien, « 7,3 Mio → 8,0 Mio » se lit tout de suite.
		huh.NewGroup(
			huh.NewSelect[pkg.PadProfile]().
				Title("largeur du palier").
				DescriptionFunc(func() string { return padHint(tailleClair, o.padNiveau) }, &o.padNiveau).
				Options(
					huh.NewOption("standard  (défaut)", pkg.PadStandard),
					huh.NewOption("fort", pkg.PadFort),
					huh.NewOption("maximum  (puissance de deux)", pkg.PadMaximum),
				).
				Value(&o.padNiveau),
		).WithHideFunc(func() bool { return o.compresser || !o.pad }),

		huh.NewGroup(
			ouiNon("conserver le nom et la date d'origine",
				"stockés à l'intérieur du chiffré, donc restituables même sous un nom neutre",
				&o.garderMeta),
		).WithHideFunc(func() bool { return estDossier }),

		// Le brouillage dépend de la réponse précédente, d'où son propre groupe :
		// sans le nom gardé à l'intérieur, un nom tiré au hasard serait une perte
		// sèche. La question n'apparaît donc qu'une fois les métadonnées
		// conservées — et jamais pour un dossier, qui n'en porte pas.
		huh.NewGroup(
			ouiNon("brouiller le nom et la date du fichier chiffré",
				"sortie sous un nom tiré au hasard, datée du 1er janvier 2000\n"+
					"la date de création, elle, reste lisible dans le système de fichiers",
				&o.brouiller),
		).WithHideFunc(func() bool { return estDossier || !o.garderMeta }),

		huh.NewGroup(
			huh.NewInput().
				Title("mot de passe").
				// La description se recalcule à chaque frappe : l'utilisateur
				// voit la robustesse de son mot de passe pendant qu'il le tape.
				DescriptionFunc(func() string { return strengthHint(o.password) }, &o.password).
				EchoMode(huh.EchoModePassword).
				Value(&o.password).
				Validate(validatePassword),

			huh.NewInput().
				Title("confirmation").
				Description("une faute de frappe rendrait le fichier définitivement irrécupérable").
				EchoMode(huh.EchoModePassword).
				Value(&o.confirm).
				Validate(func(s string) error {
					if s != o.password {
						return errors.New("les deux saisies diffèrent")
					}
					return nil
				}),
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	return form, algoChamp
}

// appliquerDefauts renseigne des options neuves, et ne touche à rien d'autre.
//
// La distinction compte pour le retour en arrière : revenir sur cet écran doit
// retrouver les réponses déjà données, pas les remettre à zéro. Aucune valeur
// par défaut n'est le zéro de son type — AlgoAES vaut 1, les profils sont des
// chaînes non vides — donc la struct zéro désigne sans ambiguïté des options
// jamais renseignées.
func appliquerDefauts(o *optionsChiffrement, estDossier bool) {
	if *o != (optionsChiffrement{}) {
		return
	}
	o.algo, o.kdf, o.padNiveau = pkg.AlgoAES, pkg.KDFStandard, pkg.PadStandard
	o.compresser = estDossier
}

func tuiEncrypt(path string, o *optionsChiffrement) error {
	// Un dossier est presque toujours un mélange de texte, de code et de
	// métadonnées répétitives, et le tar ajoute lui-même beaucoup de zéros de
	// bourrage : la compression y gagne largement plus que sur un fichier
	// isolé. Elle est donc proposée déjà active — mais toujours refusable,
	// puisqu'elle laisse fuiter la compressibilité du contenu.
	estDossier := false
	if st, err := os.Stat(path); err == nil {
		estDossier = st.IsDir()
	}
	// zstd est le seul algorithme proposé : gzip n'est plus produit, seulement
	// relu pour les anciens fichiers. La question se réduit donc à « compresser
	// ou pas ».
	//
	// Les métadonnées ne concernent qu'un fichier : l'archive tar d'un dossier
	// porte déjà noms, dates et permissions de chaque entrée.
	appliquerDefauts(o, estDossier)

	// La taille sert à annoncer ce que coûterait chaque palier. Inconnue — un
	// dossier, un chemin illisible —, padHint se rabat sur les pourcentages.
	tailleClair := int64(-1)
	if taille, err := pkg.InputSize(path); err == nil && !estDossier {
		tailleClair = taille
	}

	// La boucle sert au retour depuis la question de l'écrasement : on
	// réaffiche les options, avec les réponses déjà saisies.
	for {
		form, ancre := encryptForm(o, estDossier, tailleClair)
		if err := lancerEtape(form, ancre); err != nil {
			return err
		}

		// Le groupe du remplissage est masqué quand la compression est active,
		// mais masquer n'efface pas : un aller-retour dans le formulaire — pad à
		// oui, retour en arrière, compression à oui — laissait les deux posés, et
		// l'opération échouait plus loin sur « le remplissage et la compression
		// s'excluent ». C'est la compression, dernier choix visible, qui tranche.
		if o.compresser {
			o.pad = false
		}
		// Même raison pour le brouillage : son groupe disparaît si les
		// métadonnées ne sont plus conservées, mais un « oui » resté derrière
		// enverrait le fichier sous un nom que plus rien ne permettrait de
		// retrouver.
		if !o.garderMeta {
			o.brouiller = false
		}

		out := path + extension
		if o.brouiller {
			// Un nom tiré au hasard n'entre en collision avec rien : la question
			// de l'écrasement ne se pose donc pas, et nomBrouille a déjà vérifié
			// que la place est libre.
			nom, err := nomBrouille(path)
			if err != nil {
				return err
			}
			out = nom
		}
		ecraser := false
		if !o.brouiller {
			var err error
			ecraser, err = confirmerEcrasement(out)
			if errors.Is(err, errRetour) {
				continue // retour aux options
			}
			if err != nil {
				return err
			}
		}
		// La ligne « sel » du cadre reste sur une seule ligne : les mentions
		// s'y ajoutent plutôt que de casser la mise en page.
		salt := "16 o aléatoires · en-tête authentifié"
		switch {
		case estDossier && o.pad:
			salt = "16 o aléatoires · dossier tar · taille masquée"
		case estDossier:
			salt = "16 o aléatoires · dossier empaqueté en tar"
		case o.pad:
			salt = "16 o aléatoires · taille réelle masquée"
		}
		info := jobInfo{
			Action: "chiffrement",
			In:     path,
			Out:    out,
			AEAD:   pkg.AlgoName(o.algo),
			// Le profil choisi, pas le profil par défaut : afficher « m=256MiB »
			// alors que l'utilisateur venait de sélectionner « maximum » démentait
			// son propre choix à l'écran.
			KDF:     o.kdf.KDFLabel(),
			Salt:    salt,
			Success: out,
		}
		if err := runJob(info, func(p func(int64, int64)) error {
			return pkg.Encrypt(path, out, []byte(o.password), pkg.Options{
				Algo: o.algo, Comp: compEncodee(o.compresser), Pad: o.pad, PadProfile: o.padNiveau,
				KDF: o.kdf, Metadata: metaEncodee(o.garderMeta), Force: ecraser, Progress: p,
			})
		}); err != nil {
			return err
		}
		errSuppression := supprimerOriginal(path, out, o.password, estDossier)
		if o.brouiller {
			// La date se pose après coup : le fichier n'existe pas avant. Elle se
			// pose surtout en dernier, après supprimerOriginal — celui-ci relit le
			// chiffré en entier pour l'authentifier avant d'effacer l'original, et
			// cette lecture remet la date d'accès à l'heure réelle. Poser la date
			// neutre avant revenait à la faire défaire aussitôt : « ls -lu »
			// rendait l'heure du chiffrement.
			//
			// Un échec ici ne perd rien — le chiffré est écrit et valide — mais il
			// laisse la vraie date en place, donc il se dit. Le taire ferait
			// croire à une protection qui n'a pas eu lieu.
			if err := brouillerDate(out); err != nil {
				fmt.Fprintf(os.Stderr, "  %s  %s\n\n", styleError.Render("!"), err)
			}
		}
		return errSuppression
	}
}

// passwordForm est l'écran commun au déchiffrement et à la vérification : le
// détail de l'en-tête, lisible sans mot de passe, puis le mot de passe. Il rend
// aussi le champ de saisie, ancre du retour vers le choix de la cible — la note
// qui le précède n'est pas sélectionnable, huh la saute.
func passwordForm(details string, password *string) (*huh.Form, huh.Field) {
	champ := huh.NewInput().
		Title("mot de passe").
		EchoMode(huh.EchoModePassword).
		Value(password).
		Validate(validatePassword)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			champ,
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	return form, champ
}

func tuiDecrypt(path string) error {
	// L'en-tête est lisible sans mot de passe : on affiche les vrais
	// paramètres du fichier avant de demander quoi que ce soit.
	d, err := pkg.Inspect(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += "\ncontient un dossier : il sera extrait dans " +
			filepath.Base(strings.TrimSuffix(path, extension)) + string(os.PathSeparator) +
			", qui ne doit pas déjà exister"
	}
	if d.Version < 3 {
		details += fmt.Sprintf("\nformat v%d, plus ancien que celui produit aujourd'hui : lecture seule, il sera relu tel quel", d.Version)
	}

	password := ""
	out := strings.TrimSuffix(path, extension)
	// La boucle sert au retour depuis la question de l'écrasement : on
	// redemande le mot de passe, déjà saisi et donc déjà rempli.
	for {
		form, ancre := passwordForm(details, &password)
		if err := lancerEtape(form, ancre); err != nil {
			return err
		}

		ecraser, err := confirmerEcrasement(out)
		if errors.Is(err, errRetour) {
			continue // retour au mot de passe
		}
		if err != nil {
			return err
		}
		info := jobInfo{
			Action:  "déchiffrement",
			In:      path,
			Out:     out,
			AEAD:    d.Algo,
			KDF:     d.KDF,
			Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
			Success: out,
		}
		// DecryptTo et non Decrypt : le nom d'origine, quand le fichier en
		// porte un, ne remonte que par le résultat — Decrypt le jette. La
		// variable est écrite dans la goroutine de l'opération et lue après,
		// une fois que runJob a reçu sa fin.
		var meta *pkg.FileMetadata
		if err := runJob(info, func(p func(int64, int64)) error {
			res, err := pkg.DecryptTo(path, out, []byte(password), pkg.Options{Force: ecraser, Progress: p})
			meta = res.Metadata
			return err
		}); err != nil {
			return err
		}
		if err := restituerNom(out, meta); err != nil {
			return err
		}
		return supprimerChiffre(path)
	}
}

// restituerNom rend au fichier déchiffré le nom qu'il portait avant d'être
// chiffré, si son propriétaire le veut bien.
//
// Ce nom vit à l'intérieur du chiffré : il n'est lisible qu'une fois le contenu
// authentifié, donc bien après le choix de la destination — impossible de
// nommer la sortie avec avant de l'avoir vérifiée. D'où cette question posée
// après coup plutôt qu'un renommage d'autorité : la sortie porte le nom que
// l'utilisateur vient de choisir, le remplacer sans un mot serait une surprise.
// Le CLI, lui, se contente d'annoncer le nom — il n'a personne à qui demander.
func restituerNom(out string, meta *pkg.FileMetadata) error {
	if meta == nil || meta.Name == filepath.Base(out) {
		return nil
	}
	fmt.Printf("  %s  %s\n\n", styleDim.Render("nom d'origine"), styleText.Render(meta.Name))

	cible, libre := cibleRestitution(out, meta)
	if !libre {
		fmt.Printf("  %s\n\n", styleFaint.Render("un fichier de ce nom existe déjà ici : rien n'a été renommé"))
		return nil
	}

	renommer := true
	champ := questionFermee(
		"lui rendre son nom ?",
		"il est pour l'instant enregistré sous "+filepath.Base(out),
		"renommer en "+meta.Name, "garder "+filepath.Base(out), &renommer)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	// Pas d'ancre : le fichier est déchiffré, il n'y a plus d'écran où revenir.
	if err := lancerEtape(form, nil); err != nil {
		return err
	}
	if !renommer {
		return nil
	}
	// Un renommage raté ne perd rien : le clair est écrit, authentifié et
	// complet, seul son nom reste celui de la sortie. Le remonter comme une
	// erreur ferait sortir en code 1 sur un déchiffrement réussi — et le cas
	// n'est pas théorique sous Windows, qui refuse « < > : " | ? * » et les noms
	// de périphériques réservés là où l'assainissement du nom d'origine, pensé
	// pour les séparateurs, les laisse passer.
	if err := os.Rename(out, cible); err != nil {
		fmt.Fprintf(os.Stderr, "  %s  %s\n\n", styleError.Render("!"),
			fmt.Sprintf("renommage en %s impossible (%v) : le fichier reste sous %s",
				meta.Name, err, filepath.Base(out)))
		return nil
	}
	fmt.Printf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(cible))
	return nil
}

// cibleRestitution dit où irait le fichier s'il reprenait son nom d'origine, et
// si la place y est libre. Le nom a été assaini à la relecture — il ne porte
// plus ni séparateur ni « .. » — donc il reste dans le dossier de la sortie.
//
// Un nom déjà pris ne déclenche pas de proposition d'écrasement : personne ne
// veut se voir offrir de détruire un fichier juste après en avoir sauvé un.
func cibleRestitution(out string, meta *pkg.FileMetadata) (cible string, libre bool) {
	if meta == nil || meta.Name == "" || meta.Name == filepath.Base(out) {
		return "", false
	}
	cible = filepath.Join(filepath.Dir(out), meta.Name)
	if _, err := os.Lstat(cible); err == nil {
		return cible, false
	}
	return cible, true
}

// tuiPasswd change le mot de passe sans re-chiffrer le contenu.
//
// Les trois champs tiennent sur un seul écran : l'actuel, le nouveau et sa
// confirmation. Le contrôle de l'actuel n'a lieu qu'à la validation, dans pkg —
// le vérifier champ par champ coûterait une dérivation Argon2 à chaque frappe.
func tuiPasswd(path string) error {
	d, err := pkg.Inspect(path)
	if err != nil {
		return err
	}
	if d.Version < pkg.VersionEnveloppe {
		return fmt.Errorf("ce fichier est au format v%d : son contenu est chiffré par une clé tirée du mot de passe, "+
			"il faut donc le déchiffrer puis le rechiffrer pour en changer", d.Version)
	}

	details := fmt.Sprintf("format v%d · %s · %s\nle contenu ne sera pas rechiffré : seul l'en-tête change", d.Version, d.Algo, d.KDF)
	ancien, nouveau, confirme := "", "", ""

	champ := huh.NewInput().
		Title("mot de passe actuel").
		EchoMode(huh.EchoModePassword).
		Value(&ancien).
		Validate(func(s string) error {
			if s == "" {
				return errors.New("indique le mot de passe actuel")
			}
			return nil
		})

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().Title("fichier").Description(details),
			champ,
			huh.NewInput().
				Title("nouveau mot de passe").
				DescriptionFunc(func() string { return strengthHint(nouveau) }, &nouveau).
				EchoMode(huh.EchoModePassword).
				Value(&nouveau).
				Validate(validatePassword),
			huh.NewInput().
				Title("confirmation").
				Description("une faute de frappe rendrait le fichier définitivement irrécupérable").
				EchoMode(huh.EchoModePassword).
				Value(&confirme).
				Validate(func(s string) error {
					if s != nouveau {
						return errors.New("les deux saisies diffèrent")
					}
					return nil
				}),
		),
	).WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)

	if err := lancerEtape(form, champ); err != nil {
		return err
	}

	if err := pkg.ChangePassword(path, []byte(ancien), []byte(nouveau)); err != nil {
		return err
	}
	fmt.Printf("  %s  %s\n", styleAccent.Render("✓"),
		styleText.Render("mot de passe changé, le contenu n'a pas été retouché"))
	fmt.Printf("  %s\n\n", styleFaint.Render(avertissementRevocation))
	return nil
}

func tuiVerify(path string) error {
	d, err := pkg.Inspect(path)
	if err != nil {
		return err
	}

	details := fmt.Sprintf("format v%d · %s · %s", d.Version, d.Algo, d.KDF)
	if d.Compressed {
		details += " · compressé"
	}
	if d.Archive {
		details += " · dossier"
	}
	details += "\nrien ne sera écrit sur le disque"

	password := ""
	form, ancre := passwordForm(details, &password)
	if err := lancerEtape(form, ancre); err != nil {
		return err
	}

	info := jobInfo{
		Action:  "vérification",
		In:      path,
		Out:     "(rien, contrôle seul)",
		AEAD:    d.Algo,
		KDF:     d.KDF,
		Salt:    fmt.Sprintf("format v%d · lu dans l'en-tête", d.Version),
		Success: verifySucces(d.Archive),
	}
	return runJob(info, func(p func(int64, int64)) error {
		return pkg.Verify(path, []byte(password), pkg.Options{Progress: p})
	})
}

// teaOptions est vide en production. Les tests s'en servent pour faire
// tourner l'écran sans terminal, et donc vérifier sa durée réelle.
var teaOptions []tea.ProgramOption

// runJob lance l'opération dans une goroutine et affiche l'écran animé.
func runJob(info jobInfo, op func(progress func(done, total int64)) error) error {
	if size, err := pkg.InputSize(info.In); err == nil {
		info.Size = size
	}

	var done atomic.Int64
	model := newProgressModel(info, &done)
	prog := tea.NewProgram(model, teaOptions...)

	// L'erreur passe par un canal plutôt que par une variable partagée : elle
	// est écrite par la goroutine de chiffrement et lue ici après coup.
	errCh := make(chan error, 1)
	go func() {
		err := op(func(d, _ int64) { done.Store(d) })
		errCh <- err
		prog.Send(doneMsg{err: err})
	}()

	if _, err := prog.Run(); err != nil {
		// Ctrl+C ferme l'écran mais ne prévient pas l'opération : sans cette
		// sortie franche, elle continuerait en arrière-plan, invisible, et un
		// ✓ arriverait après coup sur un terminal déjà rendu. On nettoie les
		// temporaires puis on quitte, comme le handler de signal — la mort du
		// processus est ce qui interrompt réellement le chiffrement.
		if errors.Is(err, tea.ErrInterrupted) || errors.Is(err, tea.ErrProgramKilled) {
			pkg.CleanupTemporaries()
			fmt.Fprintln(os.Stderr, "\ninterrompu")
			os.Exit(exitInterrompu)
		}
		// Toute autre panne de l'affichage laisse l'opération en cours : la même
		// sortie franche s'impose, sinon le processus meurt sur le retour d'erreur
		// en abandonnant un .chto-tmp-* dans le dossier de l'utilisateur.
		pkg.CleanupTemporaries()
		return err
	}
	if err := <-errCh; err != nil {
		return err
	}

	fmt.Printf("  %s  %s\n\n", styleAccent.Render("✓"), styleText.Render(info.Success))
	return nil
}

// --- Saisie du mot de passe hors TUI ------------------------------------

// readPassword récupère le mot de passe sans jamais le faire transiter par la
// ligne de commande : le flag -key de la v1 était visible dans `ps aux` pour
// tous les utilisateurs de la machine et finissait dans l'historique du shell.
//
// Trois chemins, dans cet ordre :
//
//   - stdinTaken (l'entrée standard porte les données, avec -in -) : le mot de
//     passe est demandé sur le terminal de contrôle, /dev/tty. Sans ce détour,
//     la première ligne des *données* serait lue comme mot de passe — un bug
//     silencieux qui chiffrerait le reste avec un secret involontaire.
//   - entrée standard qui n'est pas un terminal : on lit une ligne. C'est le
//     chemin des scripts, et il ne fuite ni dans ps ni dans les arguments :
//     echo 'motdepasse' | chiffremento -mode enc -in f
//   - terminal : saisie masquée.
func readPassword(confirm bool, stdinTaken bool) ([]byte, error) {
	if stdinTaken {
		return readPasswordFromTTY(confirm)
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		line, err := lecteurStdin().ReadString('\n')
		if err != nil && line == "" {
			return nil, errors.New("aucun mot de passe reçu sur l'entrée standard")
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return nil, errors.New("mot de passe vide")
		}
		return []byte(pw), nil
	}

	password := ""
	field := huh.NewInput().
		Title("mot de passe").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		Validate(validatePassword).
		WithTheme(formTheme())
	if err := field.Run(); err != nil {
		return nil, err
	}

	if confirm {
		second := ""
		check := huh.NewInput().
			Title("confirmation").
			EchoMode(huh.EchoModePassword).
			Value(&second).
			Validate(func(s string) error {
				if s != password {
					return errors.New("les deux saisies diffèrent")
				}
				return nil
			}).
			WithTheme(formTheme())
		if err := check.Run(); err != nil {
			return nil, err
		}
	}

	return []byte(password), nil
}

// readPasswordFromTTY demande le mot de passe au terminal de contrôle, l'entrée
// standard étant occupée par les données.
//
// huh n'est pas utilisable ici : il lit os.Stdin. On passe donc directement par
// term.ReadPassword sur /dev/tty, ce qui donne la même saisie masquée sans
// habillage.
// lecteurStdin rend un lecteur bufferisé partagé entre les appels.
//
// Un bufio.Reader neuf à chaque lecture avalait jusqu'à 4 Kio d'entrée pour n'en
// rendre qu'une ligne, et jetait le reste avec lui : la deuxième lecture ne
// trouvait plus rien. Invisible tant qu'une commande ne demandait qu'un mot de
// passe, fatal dès qu'elle en demande deux — c'est le cas de passwd.
//
// La source est comparée à chaque appel parce que les tests remplacent
// os.Stdin : un lecteur figé au démarrage lirait le mauvais descripteur.
//
// Sans garde de concurrence, volontairement : le parcours d'une commande est
// séquentiel, et deux saisies de mot de passe en parallèle n'auraient de toute
// façon aucun sens sur une entrée standard unique. Un futur mode qui lirait
// stdin depuis plusieurs goroutines devrait passer ce lecteur en paramètre
// plutôt que d'ajouter un verrou ici.
var (
	stdinLecteur *bufio.Reader
	stdinSource  *os.File
)

func lecteurStdin() *bufio.Reader {
	if stdinLecteur == nil || stdinSource != os.Stdin {
		stdinSource = os.Stdin
		stdinLecteur = bufio.NewReader(os.Stdin)
	}
	return stdinLecteur
}

func readPasswordFromTTY(confirm bool) ([]byte, error) {
	tty, err := os.OpenFile(ttyDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("l'entrée standard porte les données à chiffrer, "+
			"le mot de passe doit donc être saisi au terminal — introuvable ici (%w). "+
			"Utilise -in FICHIER plutôt que -in -", err)
	}
	defer tty.Close()

	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("le terminal de contrôle n'est pas utilisable pour une saisie masquée : " +
			"utilise -in FICHIER plutôt que -in -")
	}

	ask := func(prompt string) ([]byte, error) {
		fmt.Fprintf(tty, "%s ", styleDim.Render(prompt))
		pw, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if err != nil {
			return nil, fmt.Errorf("lecture du mot de passe: %w", err)
		}
		return pw, nil
	}

	password, err := ask("mot de passe :")
	if err != nil {
		return nil, err
	}
	if err := validatePassword(string(password)); err != nil {
		return nil, err
	}

	if confirm {
		second, err := ask("confirmation :")
		if err != nil {
			return nil, err
		}
		defer zero(second)
		if !bytes.Equal(password, second) {
			return nil, errors.New("les deux saisies diffèrent")
		}
	}
	return password, nil
}

func validatePassword(s string) error {
	if s == "" {
		return errors.New("le mot de passe ne peut pas être vide")
	}
	return nil
}

// Seuils de l'indicateur de force, en bits d'entropie estimée par zxcvbn.
//
// Ils sont calibrés sur une attaque *hors ligne* : l'attaquant a le fichier et
// calcule à son rythme. Argon2id à 256 MiB le limite à l'ordre de 10⁴
// tentatives par seconde même avec du matériel dédié, soit ~2¹³/s. À ce
// rythme, 35 bits tombent en une poignée de jours et 50 bits demandent des
// milliers d'années. D'où les deux paliers.
//
// Ces seuils sont bien plus bas que ceux de la v2.0 parce que la mesure a
// changé de nature : le compte combinatoire d'avant surestimait tout — il
// donnait 60 bits à « azerty123 » — là où zxcvbn compte le nombre réel de
// tentatives nécessaires.
const (
	bitsFaible  = 35
	bitsCorrect = 50

	// offlineGuessRate : hypothèse d'attaque, en tentatives par seconde.
	offlineGuessRate = 1e4
)

// passwordEntropy estime l'entropie en bits à partir du nombre de tentatives
// que zxcvbn juge nécessaires pour retrouver le mot de passe.
//
// zxcvbn ne compte pas les combinaisons possibles : il décompose la saisie en
// motifs (mots de dictionnaire, prénoms, dates, suites de touches, répétitions,
// l33t speak) et additionne le coût de chacun. C'est ce qui fait que
// « azerty123 » est désormais évalué à une vingtaine de bits au lieu d'une
// soixantaine. Ça reste un repère pour l'utilisateur, pas une garantie, et rien
// ne bloque la saisie.
func passwordEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	guesses := zxcvbn.PasswordStrength(s, nil).Guesses
	if guesses < 2 {
		return 0
	}
	return math.Log2(guesses)
}

// strengthHint traduit l'entropie en une ligne lisible, avec l'ordre de
// grandeur du temps qu'une attaque hors ligne y passerait.
func strengthHint(s string) string {
	if s == "" {
		return "jamais affiché, jamais visible dans ps ni dans l'historique"
	}
	bits := passwordEntropy(s)
	verdict := "solide"
	switch {
	case bits < bitsFaible:
		verdict = "faible, une phrase de passe serait bien plus sûre"
	case bits < bitsCorrect:
		verdict = "correct"
	}
	return fmt.Sprintf("~%.0f bits — %s · %s hors ligne", bits, verdict, crackTime(bits))
}

// crackTime donne l'ordre de grandeur, pas une prédiction : seule la puissance
// de dix compte, et l'hypothèse de débit peut se tromper d'un facteur cent.
func crackTime(bits float64) string {
	if bits <= 0 {
		return "instantané"
	}
	secondes := math.Pow(2, bits) / offlineGuessRate
	switch {
	case secondes < 60:
		return "cassé en quelques secondes"
	case secondes < 3600:
		return "cassé en quelques minutes"
	case secondes < 86400:
		return "cassé en quelques heures"
	case secondes < 30*86400:
		return "cassé en quelques jours"
	case secondes < 365*86400:
		return "cassé en quelques mois"
	case secondes < 1000*365*86400:
		return fmt.Sprintf("~%.0f ans", secondes/(365*86400))
	default:
		return "des millénaires"
	}
}

// verifySucces adapte la phrase de fin : sur une archive, ce qui est contrôlé
// est bien qu'elle serait extractible, pas seulement lisible.
func verifySucces(archive bool) string {
	if archive {
		return "archive intacte, extractible, rien écrit sur le disque"
	}
	return "fichier intact, déchiffrable, rien écrit sur le disque"
}

// confirmerEcrasement demande son avis à l'utilisateur quand la destination
// existe déjà, plutôt que de la remplacer en silence.
//
// C'est le pendant du drapeau -force du CLI : ici la question peut être posée,
// donc elle l'est. Un dossier n'est jamais proposé à l'écrasement — le
// remplacer voudrait dire supprimer une arborescence entière sur un simple
// « oui ».
//
// Le booléen rendu est la réponse réelle de l'utilisateur, et il alimente
// Options.Force. Poser Force à true d'office désarmait la garde de pkg pour
// toute la TUI, y compris quand il n'y avait rien à écraser et donc aucune
// question posée : un fichier apparu entre ce Lstat et l'écriture était
// détruit sans un mot. En rendant false quand la place est libre, on laisse
// pkg refaire le contrôle au moment d'écrire.
func confirmerEcrasement(dest string) (bool, error) {
	info, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // rien à cet emplacement : rien à demander
	}
	if err != nil {
		// Ni un fichier, ni une absence franche : un EACCES sur le parent
		// passait ici pour « la place est libre ».
		return false, fmt.Errorf("vérification de %s: %w", dest, err)
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s existe déjà et c'est un dossier : déplace-le ou renomme-le avant de continuer", dest)
	}

	ecraser := false
	champ := questionFermee(
		dest+" existe déjà — l'écraser ?",
		"son contenu actuel sera définitivement perdu",
		"écraser", "annuler", &ecraser)
	form := huh.NewForm(huh.NewGroup(champ)).
		WithTheme(formTheme()).WithKeyMap(formKeyMap()).WithShowHelp(true)
	// L'ancre rend errRetour quand l'utilisateur recule : l'appelant réaffiche
	// alors ses options plutôt que d'abandonner l'opération. Reculer et annuler
	// ne disent pas la même chose — annuler arrête tout.
	if err := lancerEtape(form, champ); err != nil {
		return false, err
	}
	if !ecraser {
		return false, fmt.Errorf("annulé : %s n'a pas été touché", dest)
	}
	return true, nil
}

// compEncodee traduit la réponse de l'interface en identifiant de compression.
func compEncodee(compresser bool) byte {
	if compresser {
		return pkg.CompZstd
	}
	return pkg.CompNone
}

func compressHint(dossier bool) string {
	if dossier {
		return "proposée active sur un dossier · laisse fuiter la compressibilité du contenu"
	}
	return "réduit la taille, mais laisse fuiter la compressibilité du contenu"
}

// shellEchappeLesEspaces dit si l'hôte échappe les espaces d'un chemin avec des
// contre-obliques. Faux sous Windows, où la contre-oblique est le séparateur de
// chemin : « C:\Users\x\mes documents » y deviendrait « C:Usersxmes documents ».
//
// Une variable et non un test direct sur runtime.GOOS, pour que le test couvre
// les deux branches depuis n'importe quel système.
var shellEchappeLesEspaces = os.PathSeparator != '\\'

// devirerGuillemets nettoie un chemin collé dans le champ par un
// glisser-déposer : le terminal le livre quoté (« '/a/mon fichier.txt' ») ou
// échappé (« /a/mon\ fichier.txt »), et validateTarget répondrait « chemin
// introuvable » à un fichier qui existe.
//
// Le retrait des guillemets vaut partout — l'explorateur Windows quote lui aussi
// les chemins à espaces. Le déséchappement, lui, est réservé aux systèmes où la
// contre-oblique n'est pas un séparateur : ailleurs il détruirait le chemin au
// lieu de le réparer.
func devirerGuillemets(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && (p[0] == '\'' || p[0] == '"') && p[len(p)-1] == p[0] {
		p = p[1 : len(p)-1]
	}
	if !shellEchappeLesEspaces || !strings.Contains(p, `\`) {
		return p
	}
	return strings.NewReplacer(`\ `, " ", `\'`, "'", `\"`, "\"").Replace(p)
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			// filepath.Join et non une concaténation : sous Windows, coller
			// « /docs » à « C:\Users\x » produisait un chemin aux séparateurs
			// mélangés. Go l'accepte, mais il s'affiche mal partout.
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// kdfHint décrit un profil KDF pour la TUI. La mémoire est annoncée parce
// qu'elle sera aussi exigée au déchiffrement.
func kdfHint(p pkg.KDFProfile) string {
	return fmt.Sprintf("%s · %d Mio de mémoire, exigés aussi au déchiffrement",
		p.KDFLabel(), p.MemoryMiB())
}

// padHint décrit un palier de remplissage. Sur un fichier de taille connue, il
// montre le résultat plutôt qu'une règle : c'est le seul moyen de choisir en
// connaissance de cause, le coût d'un même profil allant de quelques pour cent
// à un doublement selon la taille.
func padHint(tailleClair int64, p pkg.PadProfile) string {
	if tailleClair <= 0 {
		return padRegle(p)
	}
	bas, haut := pkg.PadFenetre(tailleClair, p)
	surcout := float64(haut-tailleClair) / float64(tailleClair) * 100
	return fmt.Sprintf("%s → environ %s  (+%.1f %%) · tout ce qui pèse de %s à %s sort identique",
		humanSize(tailleClair), humanSize(haut), surcout, humanSize(bas), humanSize(haut))
}

// padRegle dit ce que le profil garantit, indépendamment d'un fichier donné.
func padRegle(p pkg.PadProfile) string {
	switch p {
	case pkg.PadFort:
		return "palier deux fois plus large, surcoût plafonné à ~25 %"
	case pkg.PadMaximum:
		return "tous les fichiers d'une octave sortent à la même taille, jusqu'à +100 %"
	default:
		return "surcoût plafonné à ~12 %"
	}
}

// metaEncodee traduit la réponse de la TUI en mode de métadonnées.
func metaEncodee(garder bool) pkg.MetadataMode {
	if garder {
		return pkg.MetadataMinimal
	}
	return pkg.MetadataNone
}
