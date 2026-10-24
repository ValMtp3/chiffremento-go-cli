# zxcvbn interne et allégé — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** remplacer la dépendance `github.com/trustelem/zxcvbn` v1.0.1 par une
copie interne qui ne coûte rien au lancement, et lui apprendre les mots, prénoms
et noms de famille français.

**Architecture :** copie de zxcvbn dans `internal/zxcvbn`. Les listes de mots ne
sont plus un littéral Go construit au démarrage (~13 Mo, ~7 ms à chaque
lancement), mais des fichiers texte compressés en zstd, embarqués (`go:embed`) et
décodés une seule fois au premier besoin (`sync.Once`). Un générateur Go, lancé
à la main, fabrique ces fichiers. L'interface lance le chargement en
arrière-plan dès l'affichage de l'écran du mot de passe.

**Tech stack :** Go 1.26, `github.com/klauspost/compress/zstd` (déjà dans
`go.mod`), `github.com/dlclark/regexp2` v1.12.0 (déjà présent en indirect, passe
en direct).

**Spec :** décisions du 2026-10-21 dans
`docs/superpowers/plans/2026-10-21-feuille-de-route.md` (étape 1) + séance de
questions du 2026-10-23, résumée ci-dessous.

## Décisions (2026-10-23, à ne pas rediscuter)

| Sujet | Décision |
|---|---|
| Emplacement | `internal/zxcvbn` (non importable hors du module) |
| Stockage des listes | texte, un mot par ligne, compressé en zstd, `go:embed` |
| Chargement | `sync.Once` au premier usage + préchargement en arrière-plan à l'affichage de l'écran du mot de passe |
| Listes anglaises | gardées telles quelles (mêmes mots, même ordre que v1.0.1) |
| Mots français | les 7 776 de `pkg/mots_fr.txt`, **pas de deuxième copie** ; rang fixe 7 776 pour tous (~12,9 bits par mot) |
| Prénoms | INSEE, Fichier des prénoms, édition juillet 2025 (https://www.insee.fr/fr/statistiques/8894961), fichier national, 10 000 plus fréquents (somme toutes années et sexes) |
| Noms de famille | INSEE, Fichier des noms, 2018 (https://www.insee.fr/fr/statistiques/3536630), fichier national, 10 000 plus fréquents (somme des décennies) |
| Fichiers INSEE bruts | **pas dans le dépôt** : URL + SHA-256 notés dans le générateur, qui refuse un fichier dont l'empreinte diffère |
| Génération | programme Go dans le dépôt, lancé à la main (`go generate`) |
| Attribution | `NOTICE` à la racine + une ligne dans le README (FR et EN) |
| Mise à jour amont | workflow mensuel qui ouvre une issue si trustelem/zxcvbn publie |
| Affichage de la force | inchangé (refait à l'étape 3 de la feuille de route) |

## Global Constraints

- Licence de zxcvbn : MIT, `Copyright (c) 2018 Vincent Vanackere and Trustelem` — `internal/zxcvbn/LICENSE.txt` copié tel quel.
- Licence INSEE : Licence Ouverte / Open Licence 2.0 (Etalab). Mention obligatoire « Source : Insee » + date des données + « listes filtrées et tronquées » + aucune caution de l'INSEE.
- Aucune nouvelle dépendance. `github.com/test-go/testify` (utilisé par les tests amont) **n'est pas ajouté** : un petit paquet de test local le remplace (tâche 1).
- Signature publique conservée : `zxcvbn.PasswordStrength(password string, userInputs []string) Result`. Côté appelant, seul `tui.go` change.
- Chaque commande shell est préfixée par `rtk` (règle de l'utilisateur).
- Chaque commit attend l'accord de l'utilisateur (règle « Git » de son CLAUDE.md) : demander avant chaque étape « Commit ».
- `make lint` (gofmt + go vet) et `go test -race ./...` passent à la fin de chaque tâche.

## Review Focus

1. **Saisie accentuée** (« hélène1990 », « Françoise ») : un prénom accentué doit être reconnu, avec ou sans accent. Test dans la tâche 3.
2. **Préchargement et première touche en même temps** : deux goroutines appellent le chargement ensemble. Une seule construction, aucune course (`go test -race`). Test dans la tâche 2.
3. **Majuscules** (« DUPONT », « Martin ») : reconnues comme le nom en minuscules, avec le surcoût normal des majuscules de zxcvbn. Test dans la tâche 3.
4. **UTF-8 invalide et mot de passe vide** : pas de panique, `Guesses` vaut 0 comme aujourd'hui. Test `TestCornerCases`, conservé dans la tâche 1.
5. **Utilisateur qui annule l'écran du mot de passe** : le préchargement finit seul, ne bloque pas la sortie et ne garde rien de plus. Vérifié par le parcours pty existant (`e2e_pty_test.go`) dans la tâche 4.

---

## Structure des fichiers

```text
internal/zxcvbn/
  LICENSE.txt                  MIT amont, tel quel
  AMONT                        une ligne : « v1.0.1 » (lu par le workflow mensuel)
  zxcvbn.go                    PasswordStrength, Precharger
  time_estimate.go             copié
  zxcvbn_test.go               test amont (testdata/output.json), sans testify
  parite_test.go               parité avec la v1.0.1 externe (testdata/parite.json)
  francais_test.go             nouveau comportement (mots, prénoms, noms)
  testdata/output.json         copié
  testdata/parite.json         produit à la tâche 1, avant le retrait de la dépendance
  adjacency/                   graphes de claviers, chargés au premier usage
  frequency/
    frequency.go               Liste, Anglais(), Francais()
    listes/*.txt.zst           listes embarquées
  match/, scoring/, matching/  copiés ; chemins d'import réécrits
  internal/mathutils/          copié
  internal/verif/              remplaçant local de testify (assert, require)
  outils/genlistes/main.go     générateur (go generate)
pkg/passphrase.go              + MotsPhrase()
tui.go                         import interne + préchargement
NOTICE                         attribution INSEE + MIT zxcvbn
.github/workflows/zxcvbn-amont.yml
```

---

### Tâche 1 : copie interne fidèle et preuve de parité

**Files :**
- Create : tout `internal/zxcvbn/` copié depuis `$(go env GOMODCACHE)/github.com/trustelem/zxcvbn@v1.0.1`, **sans** `data/`, `data-scripts/`, `fuzz/`, `.travis.yml`, `.gitignore`
- Create : `internal/zxcvbn/internal/verif/assert/assert.go`, `internal/zxcvbn/internal/verif/require/require.go`
- Create : `internal/zxcvbn/parite_test.go`, `internal/zxcvbn/testdata/parite.json`, `internal/zxcvbn/AMONT`

**Interfaces :**
- Produces : `internal/zxcvbn.PasswordStrength(password string, userInputs []string) Result`, comportement identique à la v1.0.1.
- Produces : `assert.Equal`, `assert.EqualValues`, `assert.Empty`, `assert.Len`, `assert.True` (signature `(t testing.TB, …, msgAndArgs ...any) bool`, comparaison `reflect.DeepEqual`, `EqualValues` convertit vers le type attendu) et `require.NoError(t testing.TB, err error, msgAndArgs ...any)`. Ce sont les seules fonctions de testify utilisées par les tests amont.

- [ ] **Step 1 : produire la référence de parité, tant que la dépendance externe est là.**
  Programme jetable dans le scratchpad (hors dépôt). Il appelle la v1.0.1 externe et écrit `internal/zxcvbn/testdata/parite.json` : `[{"password", "guesses", "score"}]`. Corpus :
  - les 70 mots de passe de `testdata/gen.sh` (amont) ;
  - ceux des tests du projet : `azerty123`, `azertyuiopqs`, `x7Qv2mKp9Lzt`, `motdepasse`, `soleil`, `marie`, `dupont`, `Martin1990`, `hélène1990`, `Françoise`, `DUPONT`, `chiffremento`, `abaisse-abandon-abaque`, `nicolas.dupont@exemple.fr`, `0612345678`, `P@ssw0rd!`.
- [ ] **Step 2 : écrire `TestPariteAvecV101`** (dans `parite_test.go`, paquet `zxcvbn`). Pour chaque entrée : `PasswordStrength(p, nil).Guesses == guesses` (égalité exacte des `float64`) et `Score == score`. À la tâche 3, ce test passera sur les seuls dictionnaires anglais (voir l'interface `passwordStrength` de la tâche 3).
- [ ] **Step 3 : lancer le test** : `rtk go test ./internal/zxcvbn/ -run TestPariteAvecV101`. Attendu : FAIL, la copie n'existe pas encore.
- [ ] **Step 4 : copier l'amont.**
  - Réécrire les imports `github.com/trustelem/zxcvbn/` en `chiffremento-cli/internal/zxcvbn/`.
  - Réécrire `github.com/test-go/testify/` en `chiffremento-cli/internal/zxcvbn/internal/verif/`.
  - Remplacer `ioutil.ReadFile` par `os.ReadFile`.
  - Écrire `AMONT` (`v1.0.1`).
  - Un commentaire d'en-tête dans `zxcvbn.go` dit d'où vient la copie et renvoie à `LICENSE.txt`.
- [ ] **Step 5 : lancer** `rtk go test -race ./internal/zxcvbn/...`. Attendu : PASS, tests amont compris (`TestPasswordStrength`, `TestCornerCases`, `Test_displayTime`, tests de `matching/` et `scoring/`).
- [ ] **Step 6 : commit** (après accord) : `refactor: copie interne de zxcvbn v1.0.1 avec preuve de parité`.

### Tâche 2 : listes compressées et chargement paresseux

**Files :**
- Create : `internal/zxcvbn/frequency/frequency.go`, `internal/zxcvbn/frequency/listes/{passwords,english_wikipedia,female_names,male_names,surnames,us_tv_and_film}.txt.zst`, `internal/zxcvbn/outils/genlistes/main.go`
- Delete : `internal/zxcvbn/frequency/lists.go`
- Modify : `internal/zxcvbn/matching/omnimatch.go` (`defaultRankedDictionnaries`, `defaultGraphs`), `internal/zxcvbn/adjacency/adjacency.go` (`init`), `internal/zxcvbn/scoring/guesses.go:174-178`, `internal/zxcvbn/zxcvbn.go`
- Test : `internal/zxcvbn/frequency/frequency_test.go`, `internal/zxcvbn/zxcvbn_test.go`

**Interfaces :**
- Produces : `frequency.Liste struct { Mots []string; RangFixe int }`. `RangFixe == 0` : le rang suit l'ordre (1, 2, 3…). Sinon, tous les mots ont ce rang.
- Produces : `frequency.Anglais() map[string]Liste` : les 6 listes amont, noms de clés inchangés. Décodage dans un `sync.OnceValue`. Un échec de décodage est une erreur de programmation (données embarquées) : `panic` avec un message clair, comme `regexp.MustCompile`, et `TestListesEmbarquees` le garantit.
- Produces : `adjacency.Graphe(nom string) *Graph`, construit une seule fois. Remplace la map globale `Graphs` et son `init()`.
- Produces : `zxcvbn.Precharger()` : force le chargement (listes, classement, graphes) et ne fait rien s'il est déjà fait. On peut l'appeler depuis plusieurs goroutines à la fois.
- Generator : `go run ./internal/zxcvbn/outils/genlistes -amont <chemin vers frequency/lists.go v1.0.1> [-prenoms … -noms …] -sortie internal/zxcvbn/frequency/listes`. Il lit le littéral Go amont avec `go/parser` (aucun `import` de l'amont), écrit un mot par ligne en `\n`, et compresse avec `zstd.SpeedBestCompression`. Directive `//go:generate` dans `frequency.go`, avec la commande documentée.

- [ ] **Step 1 : écrire les tests.**
  - `TestListesEmbarquees` : `Anglais()` renvoie les 6 clés, avec ces tailles exactes : passwords 30000, english_wikipedia 30000, female_names 3712, surnames 10000, us_tv_and_film 19160, male_names 983. `Mots[0]` vaut `123456`, `the`, `mary`, `smith`, `you`, `james`.
  - `TestAucunChargementAuDemarrage` : un compteur `nbChargements` (variable de paquet `atomic.Int32`, incrémentée dans le chargement) vaut 0 dans `TestMain` avant `m.Run()`.
  - `TestPrechargerConcurrent` : 8 goroutines appellent `Precharger()` et `PasswordStrength("azerty123", nil)` en même temps, puis `nbChargements == 1`. À lancer avec `-race`.
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL (`Anglais` et `Precharger` n'existent pas).
- [ ] **Step 3 : écrire le générateur**, produire les 6 `.txt.zst`, supprimer `lists.go`, puis rendre paresseux le classement (`omnimatch.go`) et les graphes (`adjacency.go`, `guesses.go`). Le décodeur zstd : `zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))`, refermé après usage.
- [ ] **Step 4 : lancer** `rtk go test -race ./internal/zxcvbn/...`. Attendu : PASS, **`TestPariteAvecV101` compris**.
- [ ] **Step 5 : mesurer** (scratchpad, binaire `-s -w`). Taille du binaire, puis le « peak memory footprint » de `/usr/bin/time -l` pour un programme qui importe le paquet sans l'appeler, et pour un qui appelle `PasswordStrength` une fois. Ajouter le temps du premier appel (`BenchmarkPremierAppel`, sous-processus ou `-count=1`). Noter les chiffres dans le message de commit.
- [ ] **Step 6 : commit** (après accord) : `perf: listes de zxcvbn compressées et chargées au premier usage`.

### Tâche 3 : dictionnaires français

**Files :**
- Modify : `internal/zxcvbn/outils/genlistes/main.go` (options `-prenoms`, `-noms`), `internal/zxcvbn/frequency/frequency.go`, `internal/zxcvbn/matching/dictionary.go` (`buildRankedDict`), `internal/zxcvbn/matching/omnimatch.go`, `internal/zxcvbn/zxcvbn.go`, `internal/zxcvbn/parite_test.go`, `pkg/passphrase.go`
- Create : `internal/zxcvbn/frequency/listes/{prenoms_fr,noms_fr}.txt.zst`, `internal/zxcvbn/francais_test.go`, `NOTICE`
- Modify : `README.md` (FR + EN), `SPEC.md` (section PHR)

**Interfaces :**
- Produces : `pkg.MotsPhrase() ([]string, error)` : copie (`slices.Clone`) de la liste chargée par `listeMots`, pour que personne ne modifie la liste du générateur de phrases.
- Produces : `frequency.Francais() map[string]Liste` avec 3 clés :
  - `mots_fr` : depuis `pkg.MotsPhrase()`, avec `RangFixe: 7776` ;
  - `prenoms_fr` : 10 000 entrées, rang selon la fréquence ;
  - `noms_fr` : 10 000 entrées, rang selon la fréquence.
- Produces (non exporté, paquet `zxcvbn`) : `passwordStrength(password string, userInputs []string, listes map[string]frequency.Liste) Result`. `PasswordStrength` l'appelle avec anglais + français (classement construit une fois), et `TestPariteAvecV101` avec `frequency.Anglais()` seul.
- Generator INSEE :
  - Prénoms : fichier national, colonnes `sexe;prenom;periode;valeur` (vérifier l'en-tête du fichier téléchargé, et l'écrire dans le générateur s'il diffère). Exclure `_PRENOMS_RARES`, additionner `valeur` par prénom, trier par total décroissant (égalité : ordre alphabétique), garder 10 000.
  - Noms : fichier national, nom + effectifs par décennie, même méthode.
  - Écriture en minuscules. Si la forme sans accent diffère (table fixe : é è ê ë à â ä î ï ô ö ù û ü ÿ ç, œ→oe, æ→ae), l'écrire **aussi**, juste après et au même rang. Les tirets et apostrophes sont gardés tels quels.
  - Constantes `urlPrenoms`, `shaPrenoms`, `urlNoms`, `shaNoms` en tête du fichier : refus avec message clair si l'empreinte diffère.
  - Les fichiers sont téléchargés à la main (`curl`) dans le scratchpad, jamais dans le dépôt.

- [ ] **Step 1 : écrire les tests** (`francais_test.go`).
  - `TestMotFrancaisFaible` : `bits(p) < bitsFaible` (35) pour `soleil`, `abandon`, `marie`, `dupont`, `Martin`, `DUPONT`, `hélène1990`, `helene1990`, `Françoise`. Ici, `bits = log2(Guesses)`.
  - `TestMotsFrancaisRangFixe` : la séquence de `PasswordStrength("abaisse", nil)` est un seul match `dictionary`, `DictionaryName == "mots_fr"` et `Rank == 7776`. Même chose pour `noisette`.
  - `TestListesFrancaises` : `len(prenoms_fr.Mots) >= 10000`, `len(noms_fr.Mots) >= 10000` (variantes sans accent comprises), `noms_fr.Mots[0] == "martin"`, aucune entrée vide, aucune `_prenoms_rares`.
  - `TestPariteAvecV101` passe désormais par `passwordStrength(p, nil, frequency.Anglais())`.
- [ ] **Step 2 : lancer les tests.** Attendu : FAIL.
- [ ] **Step 3 : télécharger** les deux fichiers INSEE, calculer leur SHA-256, renseigner les constantes, lancer `go generate ./internal/zxcvbn/frequency`, puis brancher `Francais()` et le rang fixe dans `buildRankedDict`.
- [ ] **Step 4 : lancer** `rtk go test -race ./internal/zxcvbn/... ./pkg/...`. Attendu : PASS, parité comprise.
- [ ] **Step 5 : documentation.**
  - `NOTICE` : MIT de zxcvbn (texte complet) ; liste Tails/Tor (CC0) ; INSEE. Pour l'INSEE : « Source : Insee », nom des deux fichiers, édition (juillet 2025 / mai 2018), URL, Licence Ouverte 2.0 avec son URL, « listes filtrées (10 000 entrées les plus fréquentes) et mises en minuscules ; l'Insee ne cautionne pas ce logiciel ». Préciser que la licence MIT du code ne s'applique pas à ces données.
  - README FR et EN : une ligne qui renvoie à `NOTICE`.
  - `SPEC.md` : règle `R-PHR-08 — Dictionnaires français dans l'indicateur de force` (mots de la liste, 10 000 prénoms et noms INSEE, avec ou sans accent), suivie de `Tests : TestMotFrancaisFaible, TestMotsFrancaisRangFixe, TestListesFrancaises`. Vérifier avec `rtk go test -run TestSpecChaqueRegleAUnTestExistant .` que le test du filet de sécurité retrouve les tests.
- [ ] **Step 6 : mesurer** à nouveau (même protocole que la tâche 2) et noter l'écart dû au français.
- [ ] **Step 7 : commit** (après accord) : `feat: l'indicateur de force connaît les mots, prénoms et noms français`.

### Tâche 4 : brancher l'interface et retirer la dépendance

**Files :**
- Modify : `tui.go:19` (import), `tui.go` aux deux écrans de saisie (autour de `:393` et `:816`), `go.mod`, `go.sum`
- Test : `tui_test.go`, `e2e_pty_test.go` (existants)

**Interfaces :**
- Consumes : `zxcvbn.PasswordStrength`, `zxcvbn.Precharger` (tâche 2).

- [ ] **Step 1 : remplacer l'import** par `chiffremento-cli/internal/zxcvbn`.
- [ ] **Step 2 : précharger.** Ajouter `go zxcvbn.Precharger()` au moment où chacun des deux formulaires de mot de passe est construit. Pas avant : `-mode …` et les autres écrans ne chargent rien.
- [ ] **Step 3 : nettoyer les dépendances.** `rtk go mod tidy`. Attendu : `trustelem/zxcvbn` disparaît de `go.mod`, `dlclark/regexp2` passe en direct, rien d'autre ne bouge (`rtk git diff go.mod`).
- [ ] **Step 4 : lancer** `rtk make lint` puis `caffeinate -i go test -race ./...` (voir la mémoire « longues suites »). Attendu : PASS, avec `TestIndicateurDeForceDictionnaire` et les parcours pty compris.
- [ ] **Step 5 : vérifier dans un vrai terminal** (skill `run`, pty) : la première touche de l'écran du mot de passe ne gèle pas, l'indicateur affiche « faible » pour `dupont`.
- [ ] **Step 6 : commit** (après accord) : `refactor: l'interface utilise la copie interne de zxcvbn`.

### Tâche 5 : surveillance mensuelle de l'amont

**Files :**
- Create : `.github/workflows/zxcvbn-amont.yml`

- [ ] **Step 1 : écrire le workflow.**
  - Déclenchement : `schedule: cron "0 6 1 * *"` + `workflow_dispatch`.
  - `permissions: contents: read, issues: write`.
  - Lire `internal/zxcvbn/AMONT`, puis la dernière version publiée (`gh api repos/trustelem/zxcvbn/tags --jq '.[0].name'`).
  - Si elle diffère et qu'aucune issue ouverte ne porte le titre `zxcvbn amont : <version> publiée`, faire `gh issue create` avec ce titre et un corps qui renvoie à la procédure de mise à jour (générateur, parité).
  - Mêmes conventions que `mutation.yml` : commentaires en français, actions épinglées par empreinte comme dans `ci.yml`.
- [ ] **Step 2 : vérifier** la syntaxe (`actionlint` s'il est installé, sinon relecture) et simuler la logique en local avec `gh api`.
- [ ] **Step 3 : commit** (après accord) : `ci: issue mensuelle si zxcvbn amont publie une version`.

### Tâche 6 : mesures finales et repères

**Files :**
- Modify : `CLAUDE.md` (repères mesurés), `docs/superpowers/plans/2026-10-21-feuille-de-route.md` (étape 0 « fait », étape 1 avec le lien vers ce plan)

- [ ] **Step 1 : mesurer** `main` et la branche avec le même protocole, 3 exécutions chacune (ignorer la première, cache disque froid) :
  - taille du binaire `go build -trimpath -ldflags="-s -w"` ;
  - pic mémoire et temps de `-version` ;
  - pic mémoire d'un `-mode genpass` ;
  - coût du premier `PasswordStrength`.
  Référence avant (2026-10-23) : binaire **8 348 898 octets**, `-version` **~15,6 Mo** au pic, 0,01 s.
- [ ] **Step 2 : mettre à jour** la ligne zxcvbn de `CLAUDE.md`, ainsi que la ligne « Binaire », avec les nouveaux chiffres.
- [ ] **Step 3 : commit** (après accord) : `docs: repères mesurés après zxcvbn interne`.
- [ ] **Step 4 : revue avant la PR** (règles de l'utilisateur) : `/refactor-clean`, puis `/code-review` (ECC) et `code-review` (mattpocock) en parallèle, puis `verification-before-completion`. La PR annonce les chiffres et cite `dlclark/regexp2` (passé de dépendance indirecte à directe).
