# Releases signées et préparation de la v2.4.0 — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** que la v2.4.0 soit la première release signée (signature, liste des
composants, preuve de provenance, `install.sh` qui vérifie), avec une CI macOS
qui ne frôle plus sa limite et une capture réelle du plein écran dans le README.

**Architecture :** tout passe par la release existante (`release.yml` +
GoReleaser v2). GoReleaser signe `checksums.txt` avec cosign sans clé
(identité OIDC du workflow GitHub), produit un SBOM par archive avec syft, et le
workflow ajoute une attestation de provenance GitHub sur les archives. La
release est d'abord créée en brouillon, vérifiée par le workflow lui-même, puis
publiée. `install.sh` vérifie la signature quand cosign est installé.

**Spec :** feuille de route `docs/superpowers/plans/2026-10-21-feuille-de-route.md`
(étape 2) + décisions du 2026-10-25 ci-dessous.

## Décisions (à ne pas rediscuter)

| Sujet | Décision |
|---|---|
| Signature | cosign sans clé (keyless, Sigstore), sur `checksums.txt` : un seul fichier signé couvre toutes les archives par leurs empreintes. Bundle `checksums.txt.sigstore.json` joint à la release |
| SBOM | Option `sboms:` de GoReleaser avec syft, installé dans le job CI seulement (jamais dans `go.mod`) ; un SBOM par archive |
| Provenance | Attestations GitHub (`actions/attest-build-provenance`, format SLSA), vérifiables avec `gh attestation verify` |
| install.sh | Empreinte SHA-256 toujours vérifiée (déjà le cas). Si cosign est présent : vérifier la signature de `checksums.txt` (identité = ce workflow sur un tag `v*`), refuser si elle échoue. Si cosign est absent : avertir « signature non vérifiée : installe cosign pour plus de sûreté » et continuer. Décisions finales : cosign présent + bundle absent → toujours refuser (quelle que soit la version) ; cosign plus ancien que 2.6.2 (3.0.4 en v3) → refuser ; `install.sh` est joint à la release et listé dans `checksums.txt` (donc signé) |
| Release | `replace_existing_draft: true` (un brouillon laissé par une vérification échouée est recréé à la relance) ; GoReleaser figé sur `v2.18.3` |
| CI macOS | Sous `-race`, les tests de `pkg` qui dérivent avec 256 Mio–1 Gio passent au profil de test le plus léger ; les profils lourds restent testés sans `-race`, dans le job séparé `profils-lourds` |
| Capture README | Bloc texte capturé d'une vraie session dans un pty (FR + EN), aucune capture fabriquée |
| Branche | `ci/releases-signees`, empilée sur `feat/plein-ecran` (PR #23 pas encore mergée) ; la PR s'ouvre après le merge de #23 |

## Global Constraints

- Actions épinglées par SHA de commit avec commentaire de version (convention de `release.yml`) ; permissions minimales par job (`id-token: write` et `attestations: write` seulement où il faut).
- Aucune dépendance Go ajoutée ; outils (cosign, syft) installés dans la CI uniquement.
- Le jeton du tap Homebrew (`TAP_GITHUB_TOKEN`) reste limité au job qui en a besoin.
- Rien n'est publié pendant le développement : aucun tag poussé, aucune release créée (vérifications en `--snapshot` et sur un dépôt de test local).
- `install.sh` reste POSIX `sh` et sans dépendance nouvelle obligatoire.
- Chaque commande shell est préfixée par `rtk`. Commits sur la branche seulement, jamais push/merge sans accord.

## Review Focus

1. **Identité de signature trop large** : `install.sh` doit exiger l'identité exacte du workflow de ce dépôt sur un tag `v*` (pas « n'importe quel workflow GitHub »). Test dans la tâche 3.
2. **cosign présent mais réseau absent** : la vérification échoue ; message clair et refus (pas de repli silencieux sur « continuer »). Test dans la tâche 3.
3. **Relance d'une release** (`workflow_dispatch`, `replace_existing_artifacts`) : signature et attestation refaites sans doublon bloquant. Vérifié dans la tâche 1.
4. **Tests `-race` allégés qui ne testent plus rien** : chaque test allégé garde son assertion ; le profil lourd reste couvert sans `-race`. Tâche 4.
5. **Cask Homebrew pendant le brouillon** : le cask pointe vers des fichiers encore en brouillon ; fenêtre à mesurer et documenter dans `RELEASE.md`. Tâche 2.

---

### Tâche 1 : signature et SBOM dans GoReleaser

**Files :** Modify `.goreleaser.yaml` (`signs:`, `sboms:`, `release.draft: true`), `.github/workflows/release.yml` (installation pinned de cosign et syft, `permissions: id-token: write`), Create un job `release-a-blanc` (sur PR touchant la config de release) qui lance `goreleaser check` puis `goreleaser release --snapshot --clean --skip=publish,sign`.

- [ ] **Step 1 :** `goreleaser check` sur la config modifiée (installé dans le scratchpad, jamais dans le dépôt) → OK.
- [ ] **Step 2 :** `goreleaser release --snapshot --clean --skip=publish,sign` en local → `dist/` contient les 6 archives, `checksums.txt` et un SBOM par archive (vérifier qu'un SBOM liste bien `golang.org/x/crypto` et `klauspost/compress`).
- [ ] **Step 3 :** signature : `signs` avec `cmd: cosign`, `args: ["sign-blob", "--bundle=${signature}", "${artifact}", "--yes"]`, `artifacts: checksum`, `signature: "${artifact}.sigstore.json"`. Relance (Review Focus 3) : vérifier que `replace_existing_artifacts` remplace aussi le bundle.
- [ ] **Step 4 :** commit `ci: signature cosign et SBOM des releases`.

### Tâche 2 : provenance, vérification avant publication

**Files :** Modify `.github/workflows/release.yml`, `RELEASE.md`.

- [ ] **Step 1 :** après GoReleaser, `actions/attest-build-provenance` sur `dist/*.tar.gz`, `dist/*.zip`, `dist/checksums.txt` (`permissions: attestations: write`).
- [ ] **Step 2 :** étape de vérification dans le même job : télécharger les fichiers du brouillon, `cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp '^https://github.com/ValMtp3/chiffremento-go-cli/.github/workflows/release.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt`, `sha256sum -c checksums.txt`, `gh attestation verify <archive> --repo ValMtp3/chiffremento-go-cli`. Puis seulement `gh release edit <tag> --draft=false`. Un échec laisse la release en brouillon et fait échouer le job.
- [ ] **Step 3 :** `RELEASE.md` : nouvelles étapes 5 (brouillon vérifié puis publié) et 7 (vérifier signature et provenance), fenêtre du cask Homebrew (Review Focus 5), quoi faire si la vérification échoue.
- [ ] **Step 4 :** relecture YAML (actionlint s'il est installé), commit `ci: provenance et vérification avant publication`.

### Tâche 3 : install.sh vérifie la signature

**Files :** Modify `install.sh`, `README.md` (FR + EN : section « Vérifier une release »). Create `install_test.sh` (ou test Go qui lance `sh install.sh` dans un dossier temporaire avec un faux `cosign` dans le PATH).

- [ ] **Step 1 : tests.** Faux `cosign` qui réussit → installation ; qui échoue → refus avec message ; absent → avertissement exact « signature non vérifiée : installe cosign pour plus de sûreté » et installation ; bundle absent alors que cosign est présent → refuser, quelle que soit la version (décision finale : sans signature, `checksums.txt` ne prouve rien ; l'ancien « avertir et continuer » est abandonné) ; identité passée à cosign = exactement l'expression du Review Focus 1 (le faux cosign enregistre ses arguments) ; cosign sans réseau (faux cosign qui échoue avec une erreur réseau) → refus clair (Review Focus 2).
- [ ] **Step 2 :** lancer, voir l'échec. **Step 3 :** implémenter. **Step 4 :** lancer, voir passer. Commit `feat: install.sh vérifie la signature de la release`.

### Tâche 4 : CI macOS sous sa limite

**Files :** Modify les tests de `pkg` qui dérivent en profil standard ou renforcé (repérer via `grep` les profils KDF dans `pkg/*_test.go`), avec `raceEnabled` (`pkg/race_on.go`, `race_off.go`).

- [ ] **Step 1 :** mesurer `go test -race ./pkg` et `go test ./pkg` en local (durée, 2 exécutions) et noter les 10 tests les plus lents (`-json`).
- [ ] **Step 2 :** sous `raceEnabled`, ces tests utilisent le profil de test le plus léger ; sans `-race`, rien ne change. Chaque test garde ses assertions (Review Focus 4).
- [ ] **Step 3 :** remesurer ; objectif : `-race ./pkg` divisé au moins par 2 en local. Commit `test: profils légers sous -race pour tenir la limite de la CI macOS`.

### Tâche 5 : capture réelle du plein écran

**Files :** Modify `README.md` (FR + EN).

- [ ] **Step 1 :** programme jetable (scratchpad) qui lance le vrai binaire dans un pty 80×24 (répondre à OSC 11 et ESC[6n), capture l'écran du menu puis d'un formulaire, retire les séquences ANSI.
- [ ] **Step 2 :** coller les captures telles quelles dans le README (FR, et EN avec les mêmes captures et une légende traduite — l'interface est en français). Commit `docs: capture réelle de l'interface plein écran`.

### Tâche 6 : mesures, feuille de route, revue

- [ ] **Step 1 :** taille du binaire inchangée (rien dans le code de production) ; durée CI avant/après.
- [ ] **Step 2 :** feuille de route : étape 2 « en cours (PR à ouvrir) ».
- [ ] **Step 3 :** revue avant PR (règles de l'utilisateur) : `/code-review` (ECC) et `code-review` (mattpocock) en parallèle, puis `verification-before-completion`.
