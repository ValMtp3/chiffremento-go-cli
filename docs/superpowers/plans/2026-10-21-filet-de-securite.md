# Filet de sécurité (étape 0) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Poser une spec des comportements et des tests qui attrapent toute
régression avant les refontes à venir (zxcvbn, plein écran, format v5).

**Architecture:** `SPEC.md` liste les règles numérotées, chacune reliée à des
tests ; un test Go vérifie ce lien. Trois niveaux de tests s'ajoutent à
l'existant : le contrat des commandes `-mode …` (testscript, binaire réel),
les parcours de l'interface guidée (binaire réel dans un pty, assertions sur
les fichiers et codes de sortie, jamais sur la mise en page) et un fuzzing
aller-retour dans `pkg/`. La CI gagne un seuil de couverture ; un workflow
hebdomadaire lance des tests de mutation sur `pkg/`.

**Tech Stack:** Go 1.26 (module), `testing`, `github.com/rogpeppe/go-internal/testscript`
v1.16.0 (test seulement), `github.com/creack/pty` v1.1.24 (déjà là),
`github.com/charmbracelet/x/ansi` (déjà là en indirect), gremlins v0.6.0
(outil CI, hors `go.mod`).

**Spec:** `docs/superpowers/plans/2026-10-21-feuille-de-route.md`, section
« 0. Filet de sécurité ».

## Global Constraints

- Aucun changement de comportement du binaire : cette étape n'ajoute que des
  tests, de la doc et de la CI. Tout écart trouvé est noté, pas corrigé ici
  (sauf accord explicite de Valentin).
- Taille du binaire inchangée : `go build -trimpath -ldflags="-s -w"` avant /
  après, à l'octet près (les dépendances de test n'entrent pas dans le
  binaire).
- gremlins n'entre jamais dans `go.mod` : `go install …@v0.6.0` dans le
  workflow uniquement.
- Actions GitHub épinglées par SHA de commit, comme le reste de `.github/`.
- Tests du pty : `//go:build !windows` ; testscript tourne sur les trois OS.
- Chaque test a un garde-fou de durée (pas de blocage jusqu'au timeout global).
- Commentaires et messages en français, dans le style existant.
- Préfixer les commandes shell par `rtk` en local.

## Review Focus

1. Mot de passe terminé par `\r\n` sur l'entrée standard (Windows) : accepté
   sans le `\r` — test dans la Task 2 (`motdepasse_crlf.txtar`).
2. Fichier vide (0 octet) : chiffré puis déchiffré, il redonne un fichier
   vide identique — Task 2 (`fichier_vide.txtar`).
3. Noms avec espaces, accents et emoji : aller-retour exact du nom — Task 2
   (`noms_speciaux.txtar`).
4. Destination existante sans `-force` : refus, fichier existant intact —
   Task 2 (`refus_ecrasement.txtar`).
5. Échap ou Ctrl+C dans l'interface : code 130, aucun fichier partiel laissé
   — Task 3 (`TestE2EInterruption`).

---

### Task 1: SPEC.md et test de traçabilité

**Files:**
- Create: `SPEC.md`
- Create: `spec_test.go`

**Interfaces:**
- Produces: format de règle `### R-<DOMAINE>-NN — <titre>` suivi d'une ligne
  `Tests : TestA, TestB` ; les tâches suivantes y ajoutent leurs tests.
  Domaines : `CLI`, `TUI`, `FMT` (compatibilité des formats), `CRY`
  (propriétés cryptographiques), `FS` (fichiers, écrasement, suppression),
  `PHR` (phrase de passe), `PERF` (repères de légèreté).

- [ ] **Step 1: Écrire le test de traçabilité (il échoue : SPEC.md absent)**

```go
package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// La spec ne vaut que si chaque règle est réellement vérifiée. Ce test relie
// SPEC.md au code de test : une règle sans test, ou qui cite un test disparu
// (renommé, supprimé), fait échouer la suite. C'est ce qui empêche une
// refonte de retirer une vérification sans que personne ne le voie.
var (
	motifRegle = regexp.MustCompile(`^### (R-[A-Z]+-\d{2}) — .+$`)
	motifTests = regexp.MustCompile(`^Tests : (.+)$`)
)

func TestSpecChaqueRegleAUnTestExistant(t *testing.T) {
	existants := testsDuDepot(t)

	f, err := os.Open("SPEC.md")
	if err != nil {
		t.Fatalf("SPEC.md illisible : %v", err)
	}
	defer f.Close()

	vus := map[string]bool{}
	regle := ""
	aDesTests := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ligne := sc.Text()
		if m := motifRegle.FindStringSubmatch(ligne); m != nil {
			regle = m[1]
			if vus[regle] {
				t.Errorf("%s est défini deux fois", regle)
			}
			vus[regle] = true
			continue
		}
		m := motifTests.FindStringSubmatch(ligne)
		if m == nil || regle == "" {
			continue
		}
		for _, nom := range strings.Split(m[1], ",") {
			nom = strings.TrimSpace(nom)
			if !existants[nom] {
				t.Errorf("%s cite %s, qui n'existe dans aucun fichier _test.go", regle, nom)
			}
			aDesTests[regle] = true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(vus) == 0 {
		t.Fatal("aucune règle trouvée dans SPEC.md : le format des titres a changé ?")
	}
	for r := range vus {
		if !aDesTests[r] {
			t.Errorf("%s n'a aucun test", r)
		}
	}
}

// testsDuDepot rend le nom de toutes les fonctions Test et Fuzz du dépôt,
// lues dans les sources plutôt qu'à l'exécution : une règle peut citer un
// test d'un autre paquet ou réservé à un système.
func testsDuDepot(t *testing.T) map[string]bool {
	t.Helper()
	noms := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fichier, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range fichier.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil &&
				(strings.HasPrefix(fn.Name.Name, "Test") || strings.HasPrefix(fn.Name.Name, "Fuzz")) {
				noms[fn.Name.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return noms
}
```

- [ ] **Step 2: Lancer, constater l'échec**

Run: `rtk go test -run TestSpecChaqueRegleAUnTestExistant .`
Expected: FAIL « SPEC.md illisible ».

- [ ] **Step 3: Extraire les règles existantes**

Lire `README.md` (sections d'usage, sécurité, formats), `main.go:45-147`
(`run`), `ROADMAP.md`, les commentaires de tête des tests (`cli_test.go`,
`regressions_cli_test.go`, `pkg/regressions_test.go`, `pkg/v3_test.go`,
`pkg/v4_test.go`, `navigation_audit_test.go`, `suppression_test.go`) et
`CLAUDE.md` (repères mesurés). Une règle = un comportement observable qu'un
utilisateur ou un script attend. Pour chacune, citer les tests existants qui
la vérifient. Une règle sans test existant reste dans SPEC.md : la Task 2 ou 3
lui ajoute son test (noter `Tests : ` vide en attendant, le test échouera —
c'est voulu, il sert de liste de travail).

En-tête de `SPEC.md` :

```markdown
# chiffremento — spécification des comportements

Chaque règle décrit ce que l'outil garantit. Elle cite les tests qui la
vérifient ; `spec_test.go` échoue si une règle n'a pas de test, ou cite un
test qui n'existe plus. Changer un comportement = changer la règle ici, dans
la même PR.

Numérotation : `R-<DOMAINE>-NN`, jamais réutilisée (une règle retirée est
barrée, pas renumérotée).
```

Règles obligatoires (au minimum, en plus de celles extraites) :

- `R-CLI-01` Sans argument et hors terminal : usage sur stderr, code 1.
- `R-CLI-02` `-mode` inconnu : message qui liste les modes, code 1.
- `R-CLI-03` `-mode` ou `-in` manquant : usage, code 1.
- `R-CLI-04` Options de chiffrement hors `enc` : note sur stderr, ignorées.
- `R-CLI-05` Le mot de passe vient de l'entrée standard quand elle n'est pas
  un terminal ; une fin de ligne `\r\n` est retirée.
- `R-CLI-06` `-in -` : données sur l'entrée standard, mot de passe sur le
  terminal ; sans terminal, erreur qui propose `-in FICHIER`.
- `R-CLI-07` `-version` affiche `chiffremento <version>` sur stdout, code 0.
- `R-CLI-08` Erreur : `erreur : <cause>` sur stderr, code 1 ; abandon : 130.
- `R-CLI-09` `genpass` : `-mots` borné, phrase seule sur stdout.
- `R-FS-01` Destination existante sans `-force` : refus, destination intacte.
- `R-FS-02` Aucun fichier partiel laissé après une erreur ou un abandon.
- `R-FS-03` Fichier vide : aller-retour exact.
- `R-FS-04` Noms avec espaces, accents, emoji : aller-retour exact.
- `R-FMT-01` Les fichiers v1, v2, v4 de `pkg/testdata` se déchiffrent.
- `R-CRY-01` Mauvais mot de passe : refus, rien d'écrit.
- `R-CRY-02` Un octet modifié n'importe où : refus.
- `R-CRY-03` Aller-retour exact quelles que soient les options.
- `R-TUI-01` Chiffrer un fichier depuis l'interface guidée.
- `R-TUI-02` Déchiffrer depuis l'interface guidée.
- `R-TUI-03` Vérifier depuis l'interface guidée.
- `R-TUI-04` Échap / Ctrl+C : code 130, terminal restauré, aucun fichier partiel.
- `R-TUI-05` Mauvaise phrase dans l'interface : message clair, rien d'écrit.

- [ ] **Step 4: Lancer : seules les règles sans test échouent**

Run: `rtk go test -run TestSpecChaqueRegleAUnTestExistant .`
Expected: FAIL listant uniquement des règles dont la ligne `Tests :` est
vide (celles que les Tasks 2 et 3 vont couvrir). Aucun « cite X qui n'existe
dans aucun fichier » : sinon corriger le nom cité.

- [ ] **Step 5: Commit**

```bash
rtk git add SPEC.md spec_test.go
rtk git commit -m "test: ajoute SPEC.md et le test qui relie chaque règle à ses tests"
```

### Task 2: Contrat des commandes `-mode …` avec testscript

**Files:**
- Create: `script_test.go`
- Create: `testdata/script/*.txtar`
- Modify: `go.mod`, `go.sum` (ajout de `github.com/rogpeppe/go-internal v1.16.0`)
- Modify: `SPEC.md` (lignes `Tests :` des règles CLI et FS)

**Interfaces:**
- Produces: `TestMain` du paquet `main`, qui sert aussi la Task 3 : si la
  variable d'environnement `CHIFFREMENTO_E2E_MAIN=1` est posée, le binaire de
  test se comporte comme `chiffremento` (appelle `main()`).
- Produces: `TestScripts` (nom à citer dans SPEC.md).

- [ ] **Step 1: Mesurer la taille du binaire avant**

Run: `go build -trimpath -ldflags="-s -w" -o /tmp/avant . && stat -f %z /tmp/avant`
Noter le chiffre (attendu ~8,3 Mo).

- [ ] **Step 2: Ajouter la dépendance et le lanceur**

Run: `rtk go get github.com/rogpeppe/go-internal@v1.16.0`

```go
package main

import (
	"os"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

// TestMain fait du binaire de test un chiffremento complet, pour deux usages :
//   - testscript installe la commande « chiffremento » dans le PATH des
//     scripts de testdata/script ;
//   - les tests de bout en bout du pty relancent ce même binaire avec
//     CHIFFREMENTO_E2E_MAIN=1.
// Dans les deux cas c'est le vrai main() qui tourne, drapeaux et codes de
// sortie compris : c'est le contrat que voient les scripts des utilisateurs.
func TestMain(m *testing.M) {
	if os.Getenv("CHIFFREMENTO_E2E_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	testscript.Main(m, map[string]func(){"chiffremento": main})
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{Dir: "testdata/script"})
}
```

- [ ] **Step 3: Écrire les scripts (un comportement par fichier)**

`testdata/script/sans_argument.txtar` :

```
# R-CLI-01 : hors terminal, sans argument, on affiche l'usage et on échoue.
! exec chiffremento
stderr 'interface guidée nécessite un terminal'
```

`testdata/script/mode_inconnu.txtar` :

```
! exec chiffremento -mode zip -in a.txt
stderr 'mode inconnu "zip"'
stderr 'enc, dec, verify, info, passwd, bench ou genpass'
-- a.txt --
x
```

`testdata/script/aller_retour.txtar` :

```
# R-CRY-03 / R-CLI-05 : mot de passe sur l'entrée standard.
stdin mdp.txt
exec chiffremento -mode enc -in secret.txt
exists secret.txt.chto
cp secret.txt original.txt
rm secret.txt
stdin mdp.txt
exec chiffremento -mode dec -in secret.txt.chto
cmp secret.txt original.txt
-- mdp.txt --
correct horse battery staple
-- secret.txt --
données confidentielles
```

`testdata/script/motdepasse_crlf.txtar` : identique à `aller_retour.txtar`,
mais le chiffrement lit `mdp_crlf.txt`, converti en `\r\n` par une commande
de script `crlf` ; le déchiffrement lit `mdp.txt` en `\n` et doit réussir.
On n'écrit pas le `\r` dans le `.txtar` : git ou un éditeur peut normaliser
les fins de ligne. `printf` n'existe pas sous Windows. La commande se déclare
dans `TestScripts` :

```go
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/script",
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// crlf FICHIER : réécrit FICHIER avec des fins de ligne Windows.
			"crlf": func(ts *testscript.TestScript, neg bool, args []string) {
				if neg || len(args) != 1 {
					ts.Fatalf("usage: crlf FICHIER")
				}
				contenu := ts.ReadFile(args[0])
				contenu = strings.ReplaceAll(contenu, "\n", "\r\n")
				ts.Check(os.WriteFile(ts.MkAbs(args[0]), []byte(contenu), 0o600))
			},
		},
	})
}
```

(Cette version de `TestScripts` remplace celle de l'étape 2 ; importer
`strings`.)

```
cp mdp.txt mdp_crlf.txt
crlf mdp_crlf.txt
stdin mdp_crlf.txt
exec chiffremento -mode enc -in secret.txt
...
```

`testdata/script/fichier_vide.txtar` : `vide.txt` créé par une section vide
`-- vide.txt --`, aller-retour, `cmp`.

`testdata/script/noms_speciaux.txtar` : même aller-retour sur
`rapport final é 🔒.txt`.

`testdata/script/refus_ecrasement.txtar` :

```
# R-FS-01 : la destination existe, pas de -force : refus, rien n'est touché.
stdin mdp.txt
! exec chiffremento -mode enc -in a.txt -out deja.chto
stderr 'erreur :'
cmp deja.chto temoin.chto
-- mdp.txt --
correct horse battery staple
-- a.txt --
contenu
-- deja.chto --
ne pas toucher
-- temoin.chto --
ne pas toucher
```

`testdata/script/mauvais_mot_de_passe.txtar` : chiffrer avec `mdp.txt`,
déchiffrer avec `faux.txt` : `! exec`, `stderr 'mot de passe incorrect'`,
`! exists secret.txt` après suppression préalable de l'original.

`testdata/script/options_ignorees.txtar` :
`exec chiffremento -mode verify -in x.chto -comp` sur un chiffré valide,
`stderr 'ils sont ignorés ici'`.

`testdata/script/version.txtar` : `exec chiffremento -version`,
`stdout '^chiffremento '`.

`testdata/script/genpass.txtar` : `exec chiffremento -mode genpass -mots 6`
puis `stdout '^(\S+[ -]){5}\S+\n$'` (adapter le séparateur à la sortie réelle
de `doGenpass`, `phrase_tui.go:199`) ; `! exec chiffremento -mode genpass -mots 1`.

`testdata/script/dossier.txtar`, `testdata/script/verify_info.txtar`,
`testdata/script/stdout.txtar` (`-out -`) : un comportement chacun, mêmes
motifs.

Note : sous testscript, `flag.CommandLine` contient déjà les drapeaux
`-test.*`, donc `usage()` les affiche aussi. Aucun script ne doit vérifier
l'*absence* d'un texte dans l'usage.

- [ ] **Step 4: Lancer**

Run: `rtk go test -run TestScripts -count=1 .`
Expected: PASS. Si un script échoue sur un comportement réel (pas sur une
erreur du script), **ne pas corriger le code** : noter l'écart dans le compte
rendu de la tâche et demander à Valentin.

- [ ] **Step 5: Prouver que les scripts mordent**

Inverser temporairement le test d'écrasement dans `openDest` (`main.go:621`)
pour qu'il écrase toujours, relancer `TestScripts` : `refus_ecrasement.txtar`
doit échouer. Remettre le code, `git diff main.go` doit être vide.

- [ ] **Step 6: Taille du binaire après**

Run: `go build -trimpath -ldflags="-s -w" -o /tmp/apres . && stat -f %z /tmp/apres`
Expected: identique à l'étape 1.

- [ ] **Step 7: Relier à la spec, puis commit**

Compléter les lignes `Tests : TestScripts` des règles CLI et FS concernées.

```bash
rtk git add go.mod go.sum script_test.go testdata/script SPEC.md
rtk git commit -m "test: contrat des commandes -mode avec testscript"
```

### Task 3: Parcours de l'interface guidée dans un pty

**Files:**
- Create: `e2e_pty_test.go` (`//go:build !windows`)
- Modify: `SPEC.md` (règles TUI)

**Interfaces:**
- Consumes: `TestMain` et `CHIFFREMENTO_E2E_MAIN=1` (Task 2).
- Produces: un pilote `pilote` dont seules les méthodes connaissent les
  touches. À l'étape 3 (plein écran), on ne réécrit que ces méthodes ; les
  tests `TestE2E*` restent tels quels.

```go
type pilote struct{ /* pty maître, processus, tampon de sortie */ }
func lancerPilote(t *testing.T, dossier string) *pilote
func (p *pilote) attendre(texte string)          // échoue après 20 s
func (p *pilote) touches(seq string)
func (p *pilote) choisirAction(action string)   // "chiffrer", "déchiffrer", "vérifier"
func (p *pilote) saisirChemin(chemin string)
func (p *pilote) saisirPhrase(phrase string, confirmer bool)
func (p *pilote) validerOptionsParDefaut()
func (p *pilote) codeDeSortie() int             // attend la fin, 60 s max
```

- [ ] **Step 1: Écrire le pilote**

Points obligatoires (voir la note « tester la TUI dans un pty ») :
1. Lancer `os.Args[0]` sans argument, `Env` = environnement +
   `CHIFFREMENTO_E2E_MAIN=1`, `TERM=xterm-256color`, `Dir` = dossier de test,
   via `pty.StartWithSize` (100×40).
2. Une goroutine lit la sortie en continu, la garde dans un tampon protégé
   par un mutex, et **répond** : à `\x1b]11;?\x1b\\` par
   `\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\`, à `\x1b[6n` par `\x1b[1;1R` — après
   avoir vu la requête, jamais avant.
3. `attendre` cherche dans `ansi.Strip(tampon)` (`github.com/charmbracelet/x/ansi`).
4. `t.Cleanup` tue le processus s'il tourne encore et ferme le pty.
5. Les méthodes de haut niveau sont écrites en lisant `tui.go:41-170`
   (`runTUI`, `choixForm`, `cibleForm`) et les libellés réels ; flèches
   `\x1b[A` `\x1b[B`, entrée `\r`.

- [ ] **Step 2: Écrire les tests de parcours**

```go
func TestE2EChiffrerPuisDechiffrer(t *testing.T) {
	dossier := t.TempDir()
	original := []byte("données confidentielles\n")
	if err := os.WriteFile(filepath.Join(dossier, "secret.txt"), original, 0o600); err != nil {
		t.Fatal(err)
	}

	p := lancerPilote(t, dossier)
	p.choisirAction("chiffrer")
	p.saisirChemin("secret.txt")
	p.saisirPhrase("correct horse battery staple", true)
	p.validerOptionsParDefaut()
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("chiffrement : code %d", code)
	}
	if _, err := os.Stat(filepath.Join(dossier, "secret.txt.chto")); err != nil {
		t.Fatalf("aucun chiffré produit : %v", err)
	}

	if err := os.Remove(filepath.Join(dossier, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	p = lancerPilote(t, dossier)
	p.choisirAction("déchiffrer")
	p.saisirChemin("secret.txt.chto")
	p.saisirPhrase("correct horse battery staple", false)
	if code := p.codeDeSortie(); code != 0 {
		t.Fatalf("déchiffrement : code %d", code)
	}
	obtenu, err := os.ReadFile(filepath.Join(dossier, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obtenu, original) {
		t.Fatalf("contenu déchiffré différent : %q", obtenu)
	}
}
```

Puis, sur le même modèle :
- `TestE2EVerifier` : chiffré préparé avec `pkg.Encrypt` (profil standard),
  action « vérifier », code 0, sortie contenant le mot de succès réel de
  `verifySucces` (`tui.go:1175`).
- `TestE2EMauvaisePhrase` : déchiffrer avec une autre phrase ; l'écran
  affiche « mot de passe incorrect » ; aucun fichier clair créé.
- `TestE2EInterruption` : Échap au premier écran → code 130 ; puis Ctrl+C
  (`\x03`) pendant la saisie de la phrase → code 130, dossier inchangé
  (même liste de fichiers qu'avant).
- `TestE2ESuppressionApresCoup` : si le parcours propose de supprimer
  l'original (`suppression.go:174`, `demanderSuppression`), répondre oui :
  l'original disparaît, le chiffré reste et se déchiffre.

- [ ] **Step 3: Lancer**

Run: `rtk go test -run TestE2E -count=1 -v .`
Expected: PASS, chaque test sous 30 s. Lancer aussi avec `-race`.

- [ ] **Step 4: Prouver que les tests mordent**

Faire temporairement écrire un octet de trop par `tuiDecrypt`
(`tui.go:614`) ou sauter son écriture : `TestE2EChiffrerPuisDechiffrer` doit
échouer. Remettre le code, `git diff tui.go` vide.

- [ ] **Step 5: Relier à la spec, mesurer, commit**

Compléter `Tests :` des règles TUI. Mesurer ce que les processus enfants
apportent : `go test -cover -run 'TestScripts|TestE2E' -count=1 .`. Depuis
Go 1.20, `go test -cover` pose `GOCOVERDIR` et fusionne les compteurs des
enfants qui héritent de l'environnement et se terminent normalement (pas
tués). Le pilote doit donc transmettre `os.Environ()` et laisser l'enfant
sortir seul. Noter le chiffre. S'il ne monte pas au-dessus de 58,4 %, le
seuil de la Task 5 ne protège pas les parcours de l'interface : le signaler
à Valentin.

```bash
rtk git add e2e_pty_test.go SPEC.md
rtk git commit -m "test: parcours de bout en bout de l'interface guidée dans un pty"
```

### Task 4: Fuzzing aller-retour dans `pkg/`

**Files:**
- Modify: `pkg/fuzz_test.go`
- Modify: `.github/workflows/ci.yml` (une étape de fuzzing en plus)
- Modify: `SPEC.md` (`R-CRY-03`)

**Interfaces:**
- Produces: `FuzzAllerRetour`.

- [ ] **Step 1: Trouver le point d'entrée sous Argon2**

Argon2 en profil standard coûte ~256 Mio et des centaines de ms : impossible
à chaque itération. Lire `pkg/crypto.go:540-830` et `pkg/keys.go:117-160` pour
trouver la fonction interne qui chiffre un flux avec des clés déjà dérivées
(`*keySet` / `*masterV4`). Dériver les clés **une fois** hors de `f.Fuzz`,
puis fuzzer cette fonction. **Interdit** : ajouter un paramètre ou une
variable de production pour affaiblir Argon2 en test. Si aucune fonction
interne ne convient sans toucher au code de production, s'arrêter et
demander à Valentin.

- [ ] **Step 2: Écrire le fuzz**

Entrées fuzzées : `data []byte`, `algo byte` (ramené à AES, ChaCha, cascade),
`comp bool`, `pad bool` (comp et pad s'excluent : forcer `pad=false` si
`comp`). Propriété : déchiffrer(chiffrer(data)) == data, et un octet modifié
dans le chiffré (position dérivée de `len(data)`) fait échouer le
déchiffrement. Graines : vide, 1 octet, 64 Kio + 1, contenu compressible.

- [ ] **Step 3: Lancer**

Run: `rtk go test ./pkg -run '^$' -fuzz FuzzAllerRetour -fuzztime 60s -parallel 4`
Expected: aucun échec. Tout échec = bug réel : ne pas corriger, demander.

- [ ] **Step 4: CI + spec + commit**

Ajouter dans `ci.yml`, à côté des deux autres fuzzings (même `if` ubuntu,
`-fuzztime 30s -parallel 4`). Ajouter `FuzzAllerRetour` à `R-CRY-03`.

```bash
rtk git add pkg/fuzz_test.go .github/workflows/ci.yml SPEC.md
rtk git commit -m "test: fuzzing aller-retour chiffrer puis déchiffrer"
```

### Task 5: Seuil de couverture en CI

**Files:**
- Create: `scripts/couverture.sh`
- Create: `.couverture-min`
- Modify: `.github/workflows/ci.yml`
- Modify: `Makefile` (cible `couverture`)

- [ ] **Step 1: Écrire le script**

Un profil par paquet : `go tool cover -func=X.cover | tail -1` donne alors
exactement le chiffre que `go test -cover` affiche (couverture par
instruction). Un profil commun mélangerait `main` et `pkg`.

```sh
#!/bin/sh
# Échoue si la couverture d'un paquet passe sous son plancher.
# .couverture-min : une ligne « fichier.cover plancher » par paquet.
# Les planchers se remontent à la main quand la couverture progresse, jamais
# automatiquement : une baisse doit toujours être un choix visible.
set -eu
statut=0
while read -r profil plancher; do
	[ -z "$profil" ] && continue
	reel=$(go tool cover -func="$profil" | tail -1 | awk '{ sub("%", "", $NF); print $NF }')
	if awk -v r="$reel" -v m="$plancher" 'BEGIN { exit !(r < m) }'; then
		echo "couverture ($profil) : $reel % < plancher $plancher %"
		statut=1
	else
		echo "couverture ($profil) : $reel % (plancher $plancher %)"
	fi
done < .couverture-min
exit $statut
```

Les profils sont produits par
`go test -race -timeout 25m -coverprofile=main.cover .` et
`go test -race -timeout 25m -coverprofile=pkg.cover ./pkg`.

- [ ] **Step 2: Fixer les planchers**

Lancer la mesure après les Tasks 2 à 4 ; plancher = chiffre mesuré arrondi
à l'entier inférieur. `.couverture-min` :

```
main.cover <mesuré>
pkg.cover <mesuré>
```

Ajouter `*.cover` à `.gitignore`.

- [ ] **Step 3: Brancher la CI**

Dans `ci.yml`, sur ubuntu seulement : remplacer l'étape Tests par une
version qui écrit les profils (`-coverprofile`) en gardant `-race` et
`-timeout 25m`, puis une étape « Seuil de couverture » qui lance le script.
macOS et Windows gardent la commande actuelle.

- [ ] **Step 4: Vérifier qu'il mord**

Mettre temporairement un plancher à 99 : le script doit échouer avec le
message. Remettre la valeur.

- [ ] **Step 5: Commit**

```bash
rtk git add scripts/couverture.sh .couverture-min .github/workflows/ci.yml Makefile
rtk git commit -m "ci: échoue si la couverture passe sous son plancher"
```

### Task 6: Tests de mutation hebdomadaires sur `pkg/`

**Files:**
- Create: `.github/workflows/mutation.yml`
- Modify: `Makefile` (cible `mutation`)
- Modify: `SPEC.md` (section finale « Outils de vérification »)

- [ ] **Step 1: Première passe locale**

Run: `go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 && gremlins unleash ./pkg`
Noter : mutants tués, vivants, efficacité. Lister les mutants vivants dans
le compte rendu de la tâche (fichier, ligne, mutation) : chacun est un test
manquant ou un code mort. Ne rien corriger dans cette tâche ; Valentin
décide lesquels traiter.

- [ ] **Step 2: Workflow**

`schedule` hebdomadaire (lundi 05:00 UTC) + `workflow_dispatch`, ubuntu,
`permissions: contents: read`, checkout et setup-go épinglés par les mêmes SHA
que `ci.yml`, `go install …@v0.6.0`, puis
`gremlins unleash ./pkg --threshold-efficacy <efficacité mesurée arrondie à l'entier inférieur>`.
`timeout-minutes: 120`.

- [ ] **Step 3: Makefile + commit**

Cible `mutation` qui lance la même commande en local.

```bash
rtk git add .github/workflows/mutation.yml Makefile SPEC.md
rtk git commit -m "ci: tests de mutation hebdomadaires sur pkg"
```

### Task 7: Vérification finale et PR

- [ ] **Step 1:** `rtk go test -race -timeout 25m -count=1 ./...` → PASS.
- [ ] **Step 2:** `gofmt -l .` vide, `go vet ./...` propre.
- [ ] **Step 3:** `TestSpecChaqueRegleAUnTestExistant` vert : toutes les
  règles ont un test.
- [ ] **Step 4:** taille du binaire identique à la Task 2, étape 1 ; durée de
  la suite avant / après notée.
- [ ] **Step 5:** revue (ECC `/code-review` + mattpocock `code-review` en
  parallèle), puis présenter à Valentin : chiffres, écarts trouvés, mutants
  vivants. PR seulement après son accord.
