# Publier une release

Ce document décrit chaque étape d'une release de Chiffremento, de la décision du numéro jusqu'à la vérification de l'installation par Homebrew. On le suit dans l'ordre : chaque étape suppose la précédente terminée.

Le principe à retenir : **un tag `v*` poussé sur GitHub déclenche toute la publication**. Le workflow `.github/workflows/release.yml` lance GoReleaser, qui compile les binaires, crée la release GitHub (en brouillon), signe et atteste les fichiers, puis met à jour le cask Homebrew. La release n'est publiée qu'une fois la signature vérifiée. Tout ce qui doit figurer dans la release — code, README, ROADMAP — doit donc être sur `main` **avant** le tag.

## Vue d'ensemble

| # | Étape | Où |
| :--- | :--- | :--- |
| 1 | Choisir le numéro de version | — |
| 2 | Vérifier que `main` est prêt | local + CI |
| 3 | Mettre à jour la documentation | PR vers `main` |
| 4 | Poser et pousser le tag | local |
| 5 | Suivre la publication (brouillon vérifié puis publié, Homebrew) | Actions |
| 6 | Écrire la description de la release | GitHub |
| 7 | Vérifier signature, provenance et installation | macOS, Linux |

---

## 1. Choisir le numéro de version

Le numéro suit [semver](https://semver.org/lang/fr/) : `MAJEUR.MINEUR.CORRECTIF`.

| Ce qui change | On monte | Exemple |
| :--- | :--- | :--- |
| Correctifs seulement, aucune option nouvelle | le correctif | `2.2.0` → `2.2.1` |
| Une fonctionnalité ou une option nouvelle | le mineur | `2.2.1` → `2.3.0` |
| Un changement qui casse un usage existant (option retirée, fichiers plus relus) | le majeur | `2.3.0` → `3.0.0` |

⚠️ **Version du programme et version du format sont indépendantes.** La première suit les fonctionnalités, la seconde la structure binaire des `.chto` (en v4 aujourd'hui). Un nouveau format monte au moins le mineur, et doit toujours relire les anciens formats.

## 2. Vérifier que `main` est prêt

1. Toutes les PR prévues pour la release sont mergées, y compris les mises à jour Dependabot qu'on veut embarquer.
2. La CI de `main` est verte sur les trois systèmes (Linux, macOS, Windows) :

   ```bash
   gh run list --branch main --limit 5
   ```

3. Les mêmes contrôles passent en local, sur un `main` à jour :

   ```bash
   git switch main && git pull --ff-only
   make lint
   make test        # go test -race ./...
   ```

4. Si la release touche aux performances, on remesure (voir le principe de légèreté dans `CLAUDE.md`). Les chiffres mesurés servent ensuite dans la description de la release.
5. On essaie à la main la nouveauté principale, avec `go run .` (interface guidée) ou avec ses flags.

## 3. Mettre à jour la documentation

On fait toujours ces changements dans **une branche et une PR**, jamais directement sur `main`. Convention de commit : `docs: aligne la documentation sur la version X.Y.Z`.

### `README.md` (deux langues)

Le README est bilingue : **chaque changement se fait en français et en anglais**.

- [ ] La bannière d'exemple affiche la nouvelle version (`chiffremento chiffrement  vX.Y.Z`). Garder la même longueur pour ne pas décaler le cadre.
- [ ] Une section `## ✨ Nouveautés vX.Y` (`## ✨ New in vX.Y`) en tête, ou `## 🔧 Correctifs vX.Y.Z` (`## 🔧 Fixes in vX.Y.Z`) pour une version de correctifs.
- [ ] La section de correctifs de la version précédente est retirée : elle reste lisible dans sa release GitHub. Les sections « Nouveautés » des versions mineures restent.
- [ ] Une ligne `> Le **format de fichier** …` dit si le format change ou non.
- [ ] Le tableau des flags et la liste des fonctionnalités couvrent les nouvelles options.
- [ ] Si le format change : la section qui décrit l'en-tête est à jour.

### `ROADMAP.md`

- [ ] `Dernière version publiée : **vX.Y.Z**` en haut du fichier.
- [ ] Une section `### vX.Y — …` ajoutée **en dernier** dans « ✅ Livré » (les versions vont de la plus ancienne à la plus récente).
- [ ] Les éléments livrés sont retirés de « Ce qui reste ».

### Autres fichiers à relire

- [ ] `CLAUDE.md` : si la release change une convention, une commande ou un repère de performance.
- [ ] `install.sh` : si le nom des archives ou la liste des plateformes change (il doit rester cohérent avec `archives.name_template` de `.goreleaser.yaml`).
- [ ] `.goreleaser.yaml` : si une plateforme est ajoutée ou retirée.

Puis : PR, relecture, merge.

## 4. Poser et pousser le tag

Sur un `main` à jour, **après** le merge de la PR de documentation :

```bash
git switch main && git pull --ff-only
git log --oneline -3              # le dernier commit est bien celui attendu
git tag -a vX.Y.Z -m "vX.Y.Z"     # tag annoté, comme les précédents
git push origin vX.Y.Z
```

- Le tag commence **toujours par `v`** : le workflow ne réagit qu'aux tags `v*`.
- Un tag annoté garde l'auteur et la date. Un tag simple (`git tag vX.Y.Z`) ne les garde pas.

🔴 **Ne jamais déplacer ni supprimer un tag déjà publié.** Quelqu'un a peut-être déjà téléchargé les binaires ou installé par Homebrew. Si une erreur passe dans une release, on publie une version de correctif (`X.Y.Z+1`).

## 5. Suivre la publication

Le push du tag lance le workflow `goreleaser` :

```bash
gh run list --workflow release.yml --limit 1
gh run watch <id>
```

GoReleaser fait alors, dans l'ordre :

1. `go mod tidy`, puis compilation pour **6 cibles** : Linux, macOS et Windows, chacun en `amd64` et `arm64`. Les binaires sont compilés avec `-trimpath` (reproductibles) et la version injectée par `-X main.version`.
2. Archives `chiffremento_X.Y.Z_<os>_<arch>.tar.gz` (`.zip` pour Windows), `checksums.txt` (qui contient aussi l'empreinte d'`install.sh`, `checksum.extra_files`), et `install.sh` joint tel quel (`release.extra_files`).
3. Release GitHub **en brouillon** (`draft: true`), avec un changelog généré à partir des commits. Les commits `docs:` et `test:` en sont exclus.
4. Un SBOM par archive (syft : la liste des bibliothèques embarquées), puis la signature de `checksums.txt` par cosign, sans clé (`checksums.txt.sigstore.json`).
5. **Homebrew** : écriture de `Casks/chiffremento.rb` dans le dépôt [`ValMtp3/homebrew-tap`](https://github.com/ValMtp3/homebrew-tap). Le cask retire l'attribut de quarantaine de macOS après l'installation, car les binaires ne sont pas signés.

Ensuite, le workflow fait ce que GoReleaser ne fait pas :

1. **Provenance** : `actions/attest-build-provenance` atteste que les archives et `checksums.txt` sortent de ce workflow, sur ce tag.
2. **Vérification du brouillon** : il retélécharge les fichiers du brouillon, puis vérifie la signature de `checksums.txt` (identité de référence ci-dessous), les empreintes des archives, des SBOM et d'`install.sh` (`sha256sum -c`, tous dans `checksums.txt` donc couverts par la signature) et l'attestation de chaque archive (`gh attestation verify`).
3. **Publication** : seulement si tout est bon, la release passe de brouillon à publiée. Au moindre échec, le job devient rouge et la release reste un brouillon, invisible du public.

Pourquoi un brouillon : une release publiée d'emblée peut être téléchargée avant qu'on ait vérifié quoi que ce soit, et on ne la retire plus proprement. Image : on ne met pas le colis en rayon avant d'avoir contrôlé le scellé.

### Identité de signature (référence unique)

C'est ce qui prouve qu'une signature vient de ce dépôt et de ce workflow, pas d'un autre. Les mêmes deux valeurs sont dans `release.yml` et dans `install.sh` ; en changer une impose de changer les autres :

| | Valeur |
| :--- | :--- |
| Identité (expression régulière) | `^https://github.com/ValMtp3/chiffremento-go-cli/.github/workflows/release.yml@refs/tags/v` |
| Émetteur | `https://token.actions.githubusercontent.com` |

### Fenêtre du cask Homebrew

GoReleaser écrit le cask dans le tap **pendant que la release est encore un brouillon**. Les fichiers qu'il désigne répondent 404 au public tant que la release n'est pas publiée : un `brew upgrade --cask chiffremento` lancé dans cette fenêtre échoue (rien n'est cassé, on relance plus tard).

La fenêtre dure de l'étape « Homebrew » jusqu'à l'étape « Publier la release » : l'attestation, le téléchargement et les trois vérifications, soit **quelques dizaines de secondes à 2 minutes** (estimation d'après les étapes ; à chronométrer sur la première vraie release et à noter ici). Une vérification qui échoue laisse la fenêtre ouverte : voir plus bas.

Choix : on documente au lieu de déplacer l'écriture du cask après la publication. GoReleaser ne sait pas publier le cask seul après coup ; il faudrait `skip_upload` plus un second GoReleaser, soit plus de pièces à maintenir pour une fenêtre de quelques minutes.

### Si le workflow échoue

- **Étape Homebrew en erreur d'authentification** : le secret `TAP_GITHUB_TOKEN` a sans doute expiré. C'est un jeton personnel GitHub avec un droit d'écriture sur `homebrew-tap`. Le régénérer, le mettre à jour (`gh secret set TAP_GITHUB_TOKEN`), puis relancer.
- **Relancer sans toucher au tag** : depuis l'onglet Actions, « Run workflow » sur le tag concerné (`workflow_dispatch`). `replace_existing_artifacts: true` permet de republier des fichiers déjà envoyés ; la signature (même nom de fichier) est remplacée, pas dupliquée.
- **La vérification échoue (signature, empreinte ou attestation)** : la release reste en brouillon et le cask du tap pointe déjà vers elle (fenêtre ci-dessus). Les deux correctifs :
  1. Lire l'étape en erreur dans le journal. Cause fréquente : réseau ou service Sigstore indisponible. On relance alors le workflow (« Run workflow ») : GoReleaser supprime l'ancien brouillon (`replace_existing_draft`) et en recrée un, il n'en reste donc qu'un. Si le journal dit « Plusieurs releases pour le tag », supprimer à la main le brouillon en trop (`gh release list`, puis `gh release delete vX.Y.Z --yes`) avant de relancer.
  2. Si les fichiers eux-mêmes sont en cause (empreinte fausse, identité inattendue) : ne **pas** publier à la main. Supprimer le brouillon (`gh release delete vX.Y.Z --yes`, sans `--cleanup-tag`), corriger, relancer. La release n'a jamais été publique, mais la règle de l'étape 4 reste la même : sans accord, on ne le déplace pas.
- **Relance sur une release déjà publiée** : GoReleaser garde l'état de la release (vérifié dans son code, v2.18.3). Elle reste publiée, ses fichiers sont remplacés. L'étape « Publier » ne fait alors rien. ⚠️ Si la vérification échoue pendant cette relance, la release **reste publique** (le workflow ne dépublie jamais, ce serait pire pour ceux qui l'ont déjà téléchargée) mais ses fichiers viennent d'être remplacés par des fichiers non vérifiés. Rejouer vite le workflow ; à défaut, repasser la release en brouillon à la main (`gh release edit vX.Y.Z --draft=true`) le temps d'enquêter.
- **Release à blanc** : le workflow `.github/workflows/release-a-blanc.yml` rejoue compilation, archives, checksums et SBOM (`--snapshot`, sans signature ni publication) sur toute PR qui touche `.goreleaser.yaml`, `release.yml`, lui-même ou `install.sh`. Une faute de config se voit donc sur la PR, pas pendant la release. On peut aussi le lancer à la main (« Run workflow »).
- Pour tester la configuration en local (GoReleaser n'est pas une dépendance du projet, à installer à part) :

  ```bash
  goreleaser check
  goreleaser release --snapshot --clean   # compile tout dans dist/, ne publie rien
  ```

## 6. Écrire la description de la release

Le changelog généré n'est qu'une liste de commits. On le remplace par une vraie description, en gardant la liste des commits en bas :

```bash
gh release view vX.Y.Z --json body -q .body > changelog.md   # garder la liste des commits
# écrire notes.md selon le modèle ci-dessous, y coller changelog.md à la fin
gh release edit vX.Y.Z --notes-file notes.md
```

Le **titre de la release reste le numéro seul** (`vX.Y.Z`), comme GoReleaser le crée : on ne le change pas. Le résumé de la version va dans l'accroche, en tête de la description.

### Règles de style

1. **Une accroche avant les détails.** Un titre `##` qui résume la version en une phrase, puis 2 ou 3 phrases qui disent ce qu'on gagne. Commencer par le bénéfice pour l'utilisateur, pas par la technique.
2. **Le format de fichier est toujours mentionné**, même quand il ne change pas. C'est la première question d'un utilisateur : « mes anciens `.chto` s'ouvrent-ils encore ? ».
3. **Une section `###` par thème**, avec un emoji en tête de titre : ✨ nouveauté, 🪶 légèreté, ⚡ vitesse, 🛡️ fiabilité, 🔐 sécurité, 🪟 Windows, 📦 installation.
4. **Des chiffres mesurés, jamais estimés.** Quand il y a des gains, un tableau avant/après. Les chiffres viennent des messages de commit ou d'une mesure refaite pour la release.
5. **Chaque terme technique expliqué en une phrase** (« Argon2, qui sert à dériver la clé »). La release est lue par des utilisateurs, pas seulement par des développeurs.
6. **Aucune invention.** Pas d'exemple de sortie fabriqué : le copier depuis une vraie exécution, ou ne pas en mettre.
7. **Toujours une section « Installer ou mettre à jour »**, avec les commandes Homebrew.
8. **Le français d'abord, l'anglais en résumé** dans un bloc `<details>` replié.
9. Phrases courtes, mots simples, pas de remplissage.

### Modèle

````markdown
## <emoji> Chiffremento X.Y : <ce que la version apporte, en une phrase>

<2 ou 3 phrases : le bénéfice principal, puis le reste en une ligne.>

Le **format de fichier ne change pas** (vN). Les `.chto` créés avec les versions précédentes s'ouvrent comme avant.

### ✨ <Nouveauté principale>

<À quoi ça sert, en une phrase. Comment ça marche, en une ou deux.>

- <Détail d'usage>
- En ligne de commande : `chiffremento -mode …`

### 🪶 Plus léger

| | Avant | Après |
| :--- | ---: | ---: |
| <mesure> | <valeur> | **<valeur>** |

### 🛡️ Fiabilité

- **<Ce qui ne pouvait plus arriver>** : <conséquence pour l'utilisateur>.

### 📦 Installer ou mettre à jour

**Homebrew (macOS)**

```bash
brew tap ValMtp3/homebrew-tap
brew install --cask chiffremento   # première installation
brew upgrade --cask chiffremento   # mise à jour
```

**Linux et Windows** : téléchargez l'archive de votre système et `checksums.txt` ci-dessous (voir le README).

---

<details>
<summary>🇬🇧 English</summary>

**Chiffremento X.Y: <one-line summary>.** The file format <does not change / moves to vN>.

- **✨ <Feature>**: <one sentence>.
- **🪶 Lighter**: <numbers>.

Upgrade: `brew upgrade --cask chiffremento`.

</details>

## Changelog
<liste des commits générée par GoReleaser>
````

La description de la [v2.3.0](https://github.com/ValMtp3/chiffremento-go-cli/releases/tag/v2.3.0) sert d'exemple complet.

## 7. Vérifier signature, provenance et installation

Une release n'est terminée qu'une fois installée comme le ferait un utilisateur.

1. **Les fichiers de la release** : 6 archives, 6 SBOM (`.sbom.json`), `checksums.txt`, `checksums.txt.sigstore.json` et `install.sh`. La release est publiée (pas en brouillon).

   ```bash
   gh release view vX.Y.Z --json assets -q '.assets[].name'
   ```

2. **Le cask Homebrew** contient la nouvelle version :

   ```bash
   gh api repos/ValMtp3/homebrew-tap/contents/Casks/chiffremento.rb -q .content | base64 -d | grep version
   ```

3. **L'installation Homebrew** sur macOS :

   ```bash
   brew update && brew upgrade --cask chiffremento
   chiffremento -version   # doit afficher X.Y.Z, pas « dev »
   ```

4. **Une archive Linux** : l'empreinte correspond à `checksums.txt`.

   ```bash
   gh release download vX.Y.Z -p 'chiffremento_*_linux_amd64.tar.gz' -p checksums.txt -p checksums.txt.sigstore.json
   sha256sum --ignore-missing -c checksums.txt
   ```

5. **Signature et provenance**, à refaire à la main (le workflow l'a déjà fait, mais l'utilisateur doit pouvoir le refaire). Avec les fichiers de l'étape 4 :

   ```bash
   cosign verify-blob --bundle checksums.txt.sigstore.json \
     --certificate-identity-regexp '^https://github.com/ValMtp3/chiffremento-go-cli/.github/workflows/release.yml@refs/tags/v' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     checksums.txt
   gh attestation verify chiffremento_X.Y.Z_linux_amd64.tar.gz --repo ValMtp3/chiffremento-go-cli \
     --signer-workflow ValMtp3/chiffremento-go-cli/.github/workflows/release.yml
   ```

   Les deux doivent finir sur « Verified OK » (ou un message équivalent). Sinon, voir « La vérification échoue » à l'étape 5.

6. **Un aller-retour réel** avec le binaire installé : chiffrer puis déchiffrer un fichier, et ouvrir un `.chto` créé par la version précédente.

## Aide-mémoire

```text
[ ] 1. Version choisie (semver), format de fichier noté
[ ] 2. main à jour, CI verte sur 3 systèmes, make lint + make test OK
[ ] 3. README (FR + EN), ROADMAP, CLAUDE.md : PR mergée
[ ] 4. git tag -a vX.Y.Z && git push origin vX.Y.Z
[ ] 5. Workflow goreleaser vert (brouillon vérifié puis publié), cask mis à jour
[ ] 6. Description de la release écrite (modèle ci-dessus)
[ ] 7. Signature + provenance vérifiées, brew upgrade + chiffremento -version + aller-retour OK
```
