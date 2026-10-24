# Interface plein écran — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** au lancement sans argument, une seule interface en écran alternatif :
barre du haut, barre du bas, cadre centré, menu qui revient après chaque
opération, phrase gardée pour la session sur demande, aide `?`.

**Architecture :** « écran hôte + parcours inchangés ». Un seul `tea.Program`
(écran alternatif) dessine les barres et le cadre, et affiche le sous-écran
courant (formulaire huh, phrase générée, progression, carte résultat, erreur,
aide). Les parcours actuels (`tuiEncrypt`, `tuiDecrypt`, `tuiVerify`,
`tuiPasswd`, suppression) tournent dans une goroutine à part. Ils confient
chaque sous-écran à l'hôte, puis attendent sa réponse sur un canal. Leur logique
(retours avec `errRetour`, écrasement, suppression, effacement des secrets) ne
change pas : seul le « où s'affiche le formulaire » change.

**Tech stack :** Go 1.26, bubbletea v1.3.10, huh v1.0.0, lipgloss v1.1.0 (déjà
présents). Aucune nouvelle dépendance.

**Spec :** feuille de route `docs/superpowers/plans/2026-10-21-feuille-de-route.md`
(étape 3, décisions du 2026-10-21) + séance de questions du 2026-10-24, résumée
ci-dessous.

## Décisions (à ne pas rediscuter)

| Sujet | Décision |
|---|---|
| Ordre | Le plein écran passe **avant** la release v2.4.0 et avant les releases signées (étape 2) |
| Périmètre | Seulement au lancement sans argument ; `-mode …` garde sa sortie simple (et `readPassword` son champ huh hors plein écran) |
| Programme | Un seul programme bubbletea, écran alternatif |
| Architecture | Écran hôte + parcours inchangés dans une goroutine, relais par canal |
| Formulaires | huh gardé, affiché dans le cadre (grammaire des touches et ses 15 tests conservés) |
| Barre du haut | `chiffremento vX.Y.Z · <opération> › <étape>` à gauche ; `● phrase en mémoire` à droite quand une phrase est gardée |
| Barre du bas | Les touches de l'écran courant (ex. `↑↓ choisir  → valider  ← revenir  ? aide  ctrl+c quitter`) |
| Cadre | Centré, largeur = largeur du terminal − 4, bornée à 52..80 colonnes. Terminal trop petit : barres masquées, cadre sur toute la place |
| Menu | Revient après chaque opération. Ligne « quitter » en bas + touche `q` (sur le menu seulement, jamais pendant une saisie) |
| Échap | Abandonne l'opération en cours (rien n'est écrit) et revient au menu ; sur le menu, ne fait rien. Ctrl+C quitte toujours (code 130) |
| Fin d'opération | Carte résultat dans le cadre (✓, fichier produit, détails, puis question de suppression s'il y a lieu) ; ⏎ revient au menu |
| Erreur | Cause + quoi faire, dans le cadre ; ⏎ revient au menu |
| Sortie | Après la sortie de l'écran alternatif, les résumés complets de la session sont imprimés (mêmes textes qu'aujourd'hui) |
| Code de sortie | 0 si tout a réussi ; 1 si au moins une opération a échoué dans la session ; 130 sur Ctrl+C |
| Phrase en session | Après une opération réussie avec une phrase saisie : « garder cette phrase pour la session ? » (défaut : non). Si oui : indicateur en haut, proposée à la prochaine saisie (⏎ pour l'utiliser, ou retaper) ; oubliée après 5 min sans touche, par la touche `o`, et à la sortie ; octets mis à zéro. Jamais de clé dérivée gardée : Argon2 tourne à chaque opération |
| Minuteur d'inactivité | Un seul `tea.Tick` réarmé à chaque touche, jamais une boucle. Réveils au repos à mesurer (référence 110–150/s) |
| Aide | `?` ouvre un écran : explication courte de l'outil + raccourcis ; `?`, Échap ou ⏎ la referme |
| Réglages communs | `phrase_tui.go:168` et `runJob` passent par les réglages communs (30 i/s, sortie unique) |

## Global Constraints

- Aucune nouvelle dépendance. Pas d'emoji ni de Nerd Fonts ; cadres en traits simples (`┌─┐│└┘`). `●` et `›` sont des caractères Unicode ordinaires, déjà acceptés par la direction artistique (pas des emoji).
- Couleur : accent unique `#E65A28` et les 3 gris de `theme.go`. Rendu correct sans couleur (`NO_COLOR`, TERM=dumb).
- `TERM=dumb` ou entrée/sortie qui n'est pas un terminal : on garde le comportement actuel (huh en mode accessible, pas d'écran alternatif).
- Secrets : jamais copiés dans une chaîne de plus que nécessaire ; mis à zéro dès qu'ils ne servent plus (oubli, délai, sortie, Ctrl+C). Revue sécurité obligatoire (ECC `security-review`) sur la tâche de la phrase en session.
- Légèreté : 30 images/s au plus ; aucun minuteur qui tourne au repos en dehors de celui de l'inactivité et de l'animation de progression ; mesurer réveils au repos, mémoire et binaire avant/après.
- Les tests e2e vérifient fichiers produits, codes de sortie et restauration du terminal, pas la mise en page.
- Chaque commande shell est préfixée par `rtk`. Commits sur la branche de l'étape seulement, jamais push/merge sans accord.

## Review Focus

1. **Redimensionnement pendant une saisie** : le cadre se recentre et huh garde la saisie et le focus. Test dans la tâche 1.
2. **Ctrl+C pendant l'écran de progression** : temporaire supprimé, original intact, code 130, terminal restauré (écho, curseur, écran alternatif quitté). Test e2e existant adapté dans la tâche 4.
3. **Échap pendant l'écriture** (progression en cours) : Échap n'abandonne pas une écriture déjà lancée (sinon fichier à moitié écrit) ; il n'agit qu'avant le lancement de l'opération. Test dans la tâche 3.
4. **Phrase en mémoire pendant le délai d'inactivité** : au bout de 5 min sans touche, l'indicateur disparaît et les octets sont à zéro, même si l'écran est sur la progression. Test dans la tâche 6.
5. **Terminal minuscule** (40×10) : rien ne déborde ni ne panique ; barres masquées. Test dans la tâche 1.

---

## Structure des fichiers

```text
hote.go            écran hôte : modèle racine, relais par canal, Échap, ?, q, minuteur
cadre.go           mise en page : barres, cadre centré, petit terminal
aide.go            écran d'aide
resultat.go        carte résultat et écran d'erreur, résumés accumulés
session.go         phrase gardée pour la session (garder, proposer, oublier)
tui.go             runTUI → menu persistant ; lancerEtape/runJob passent par l'hôte
navigation.go      lancerEtape/lancerChamp : hôte si présent, sinon chemin actuel
progress.go        progressModel en sous-écran, largeur = cadre
phrase_tui.go      modelePhrase en sous-écran
main.go            code de sortie, résumés, Ctrl+C unifié
```

---

### Tâche 1 : écran hôte et mise en page

**Files :** Create `hote.go`, `cadre.go`, `aide.go`, `hote_test.go`, `cadre_test.go`.

**Interfaces :**
- Produces : `type hote struct` (modèle racine `tea.Model`) et `func (h *hote) afficher(ecran sousEcran) (tea.Model, error)` : appelée depuis la goroutine du parcours, elle pousse le sous-écran à l'hôte et bloque jusqu'à sa fin (soumis, annulé par Échap → `errMenu`, Ctrl+C → `huh.ErrUserAborted`).
- Produces : `type sousEcran interface { tea.Model; Touches() string; Titre() string }` (barre du bas, fil d'Ariane).
- Produces : `func largeurCadre(largeurTerminal int) int` (bornes 52..80, marge 4), `func petitTerminal(l, h int) bool` (barres masquées si `l < 56` ou `h < 16`), `func disposer(l, h int, haut, corps, bas string) string`.
- Produces : `var errMenu = errors.New("retour au menu")`.

- [ ] **Step 1 : tests.**
  - `TestLargeurCadre` : 40→40 (place totale en petit terminal), 56→52, 60→56, 100→80, 200→80.
  - `TestPetitTerminalMasqueLesBarres` : 50×12 → ni barre du haut ni barre du bas.
  - `TestDispositionCentree` : à 100×40, chaque ligne du cadre a la même marge gauche, `(100−80)/2`.
  - `TestRedimensionnementGardeLaSaisie` : un `huh.Input` affiché, on tape « abc », puis `tea.WindowSizeMsg{60,20}` : la saisie et le focus sont gardés.
  - `TestAideSOuvreEtSeFerme` : `?` → l'écran contient « raccourcis », et `?` le referme.
  - `TestTerminalMinuscule` : `WindowSizeMsg{40,10}` sans panique, et aucune ligne plus large que 40 (`lipgloss.Width`).
  - `TestRelaisSansCourse` : 100 appels successifs à `afficher` depuis une goroutine, sous `-race`.
- [ ] **Step 2 : lancer les tests** (`rtk go test -race -run 'Cadre|Terminal|Disposition|Redimension|Aide|Relais' .`). Attendu : FAIL.
- [ ] **Step 3 : implémenter.** Tout le rendu passe par `lipgloss.Width` (jamais `len`). La barre du haut et la barre du bas sont tronquées proprement si elles sont trop longues.
- [ ] **Step 4 : lancer les tests.** Attendu : PASS. Commit : `feat: écran hôte plein écran et mise en page centrée`.

### Tâche 2 : formulaires dans le cadre

**Files :** Modify `navigation.go` (`lancerEtape`, `lancerChamp`, `optionsProgramme`), `tui.go` (constructeurs de formulaires : largeur), `phrase_tui.go:161-195`. Tests : `navigation_test.go`, `navigation_audit_test.go`, `phrase_tui_test.go` (existants, doivent rester verts).

**Interfaces :**
- Consumes : `hote.afficher`, `sousEcran` (tâche 1).
- Produces : variable de paquet `hoteCourant *hote` (nil hors plein écran). `lancerEtape(form, ancre)` utilise l'hôte s'il existe, sinon le chemin actuel (inchangé pour `readPassword` et TERM=dumb). `etapePhrase` affiche `modelePhrase` par l'hôte ; `phrase_tui.go:168` ne crée plus de programme à part.

- [ ] **Step 1 : tests.** `TestLancerEtapeParLHote` : avec un hôte de test, `lancerEtape` renvoie `errRetour` sur ← depuis l'ancre, et nil sur la validation. `TestLancerEtapeSansHote` : le chemin actuel est inchangé. Les 15 tests de R-TUI-06 restent verts sans modification.
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : implémenter.** Les formulaires prennent la largeur intérieure du cadre (`form.WithWidth`). La touche de retour et son rappel restent ceux de `etapeModel`, qui devient un `sousEcran`.
- [ ] **Step 4 : lancer** `rtk go test -race .`. Attendu : PASS. Commit : `refactor: les formulaires s'affichent dans le cadre de l'écran hôte`.

### Tâche 3 : menu persistant, Échap, quitter, code de sortie

**Files :** Modify `tui.go` (`runTUI`, `choixForm`), `main.go` (`main`, `run`, `installSignalHandler`), `e2e_pty_test.go` (pilote), `SPEC.md` (R-TUI-04, R-TUI-11 nouvelle).

**Interfaces :**
- Produces : `runTUI() (codeSortie int, err error)` : lance l'hôte en écran alternatif, fait tourner les parcours dans une goroutine, revient au menu après chaque opération ou `errMenu`. Le menu a une ligne « quitter » et la touche `q`.
- Produces : `type session struct { echecs int; resumes []string }`. Le code de sortie vaut 0, ou 1 si `echecs > 0`, ou 130 sur Ctrl+C.

- [ ] **Step 1 : tests.**
  - `TestEchapAvantLancementRevientAuMenu` : Échap sur l'écran des options → menu, et rien n'est écrit dans le dossier.
  - `TestEchapPendantEcritureIgnore` : Échap pendant la progression ne fait rien (Review Focus 3).
  - `TestQuitterDepuisLeMenu` : `q` → code 0. « quitter » + ⏎ → code 0.
  - `TestQSansEffetPendantSaisie` : « q » tapé dans un champ texte s'écrit dans le champ.
  - `TestCodeSortieApresEchec` : un échec puis « quitter » → code 1.
  - e2e : le pilote apprend `quitter()`. TestE2EChiffrerPuisDechiffrer enchaîne chiffrer puis déchiffrer **dans la même session**, puis quitte : code 0.
  - `SPEC.md` : R-TUI-04 fixe le rôle d'Échap. Nouvelle règle R-TUI-11 : menu persistant, quitter et code de sortie.
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : implémenter.** Le gestionnaire SIGINT global reste pour les `-mode`. En plein écran, Ctrl+C passe par l'hôte (`tea.Interrupt`), qui restaure le terminal, nettoie les temporaires, imprime les résumés, puis sort en 130.
- [ ] **Step 4 : lancer** `caffeinate -i go test -race ./...`. Attendu : PASS. Commit : `feat: menu persistant, Échap et code de sortie de session`.

### Tâche 4 : progression dans le cadre

**Files :** Modify `progress.go` (`View` : largeur du cadre), `tui.go:906` (`runJob` : sous-écran de l'hôte, plus de `os.Exit(130)`), `progress_test.go` (`TestRenduLargeurConstante`), `SPEC.md` (R-TUI-08).

**Interfaces :**
- Produces : `newProgressModel(info, done, largeur int)` ; `runJob` affiche par l'hôte s'il existe, sinon son programme actuel (gardé pour `TestDureeEcranReelle`).

- [ ] **Step 1 : tests.** `TestRenduLargeurConstante` vérifie que toutes les lignes ont la largeur du cadre, à 52, 64 et 80. `TestDureeEcranReelle` reste vert (4 s ≤ durée ≤ 12 s). TestE2EInterruptionPendantOperation : temporaire supprimé, original intact, code 130, écran alternatif quitté (`\x1b[?1049l` vu) et terminal restauré (Review Focus 2).
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : implémenter.** La durée minimale de 4 s reste, comme le cadre des détails et la barre ; seule la largeur suit le cadre.
- [ ] **Step 4 : lancer les tests.** Attendu : PASS. Commit : `refactor: écran de progression dans le cadre`.

### Tâche 5 : carte résultat, écran d'erreur, résumés à la sortie

**Files :** Create `resultat.go`, `resultat_test.go`. Modify `tui.go` (les `fmt.Printf` de résumé : `runJob` ~950, `restituerNom` ~712-760, `tuiPasswd` ~850, `tuiEncrypt` ~560), `suppression.go` (messages), `SPEC.md` (R-TUI-05).

**Interfaces :**
- Produces : `func (s *session) noter(resume string)`, `func carteResultat(lignes []string) sousEcran` (⏎ → menu), `func ecranErreur(err error) sousEcran` (cause + « quoi faire », ⏎ → menu). Chaque `fmt.Printf` de résumé devient `session.noter(...)`, affiché dans la carte, puis réimprimé tel quel sur stdout après la sortie de l'écran alternatif.
- Les messages « quoi faire » réutilisent ceux qui existent (`indiceForce`, `pkg.ErrBadPassword`…), sans nouveau texte inventé.

- [ ] **Step 1 : tests.**
  - `TestResumesImprimesALaSortie` : après chiffrer puis quitter, stdout contient le même texte qu'aujourd'hui (le `✓` et le chemin produit).
  - `TestEcranErreurMauvaisePhrase` : cause + quoi faire, puis ⏎ → menu, rien n'est écrit.
  - TestE2EMauvaisePhrase : mauvaise phrase, ⏎, quitter → code 1, aucun fichier (R-TUI-05).
  - La question de suppression apparaît dans la carte, après le `✓`, avec « garder » par défaut (règles actuelles).
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : implémenter.**
- [ ] **Step 4 : lancer** `caffeinate -i go test -race ./...`. Attendu : PASS. Commit : `feat: carte résultat, écran d'erreur et résumés à la sortie`.

### Tâche 6 : phrase gardée pour la session

**Files :** Create `session.go` (partie phrase), `session_test.go`. Modify `tui.go` (après succès de `tuiEncrypt`/`tuiDecrypt`/`tuiVerify` avec une phrase saisie ; `passwordForm` et l'écran mot de passe de `encryptForm` : proposition), `hote.go` (minuteur, touche `o`, indicateur), `SPEC.md` (R-TUI-12 nouvelle).

**Interfaces :**
- Produces : `type phraseSession struct { mu sync.Mutex; octets []byte; echeance time.Time }`, `garder(p []byte)` (copie), `prendre() ([]byte, bool)` (copie pour l'appelant, qui la met à zéro après usage), `oublier()` (met à zéro), `active() bool`.
- Délai : `const delaiOubli = 5 * time.Minute`. Une touche repousse l'échéance. Un seul `tea.Tick` est programmé à l'échéance ; à son arrivée, si l'échéance a été repoussée, on en reprogramme un seul.
- Proposition : à la saisie suivante, une question « utiliser la phrase en mémoire ? » (défaut : oui), ou « la saisir » qui affiche le champ habituel.
- Jamais pour `tuiPasswd` (changer de mot de passe demande toujours une saisie), et jamais de clé dérivée gardée.

- [ ] **Step 1 : tests.**
  - `TestPhraseOublieeApresDelai` : avec une horloge injectée, à 5 min les octets sont à zéro et l'indicateur disparaît (Review Focus 4).
  - `TestToucheOOublie`.
  - `TestPhraseOublieeALaSortie` (dont Ctrl+C).
  - `TestPrendreRendUneCopie`.
  - `TestUnSeulMinuteur` : aucun tick n'est programmé quand aucune phrase n'est gardée ; un seul est en attente quand une phrase l'est.
  - `TestGarderDemandeAccord` : le défaut est non, et rien n'est gardé sans oui.
  - e2e : chiffrer avec « garder » = oui, puis déchiffrer en acceptant la phrase en mémoire → contenu restitué.
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : implémenter.** Puis lancer la revue sécurité ECC `security-review` sur `session.go` et les points de prise et d'oubli.
- [ ] **Step 4 : lancer** `caffeinate -i go test -race ./...`. Attendu : PASS. Commit : `feat: phrase gardée pour la session, sur demande`.

### Tâche 7 : mesures, documentation, feuille de route

**Files :** Modify `CLAUDE.md` (repères), `README.md` (FR + EN : description de l'interface, touches), `SPEC.md` (relecture TUI), `docs/superpowers/plans/2026-10-21-feuille-de-route.md` (ordre : étape 3 avant l'étape 2, état).

- [ ] **Step 1 : mesurer** `main` et la branche :
  - réveils au repos sur le menu et sur un formulaire, pendant 30 s (référence : 110–150/s) ;
  - pic mémoire d'une session « chiffrer puis quitter » ;
  - temps jusqu'au premier écran (référence : ~62 ms) ;
  - taille du binaire (`-s -w`).
- [ ] **Step 2 : documentation**, en FR et en EN pour le README. Le tableau des touches doit correspondre à l'écran d'aide.
- [ ] **Step 3 : commit** `docs: interface plein écran, repères mesurés`.
- [ ] **Step 4 : revue avant la PR** (règles de l'utilisateur) : `/refactor-clean`, puis `/code-review` (ECC) et `code-review` (mattpocock) en parallèle, puis `verification-before-completion`.
