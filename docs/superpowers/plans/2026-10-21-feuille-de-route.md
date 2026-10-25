# Feuille de route chiffremento — après la v2.3.0

Document de suivi sur plusieurs sessions. Une étape = une branche = une PR.
Chaque étape a son plan détaillé, écrit au moment où on l'attaque (sauf
l'étape 0, déjà détaillée).

Décisions prises avec Valentin le 2026-10-21. Ne pas les rediscuter sans
nouvelle demande.

## Ordre

| # | Étape | Branche | Plan détaillé | État |
|---|---|---|---|---|
| 0 | Filet de sécurité : SPEC.md + tests | `test/filet-securite` | `2026-10-21-filet-de-securite.md` | fait (PR #21) |
| 1 | zxcvbn allégé | `perf/zxcvbn-interne` | `2026-10-23-zxcvbn-interne.md` | fait (PR #22) |
| 3 | Interface plein écran | `feat/plein-ecran` | `2026-10-24-plein-ecran.md` | en cours (branche prête, PR à ouvrir) |
| 2 | Releases signées | `ci/releases-signees` | à écrire | à faire |
| 4 | Format v5 | `feat/format-v5` | à écrire | à faire |
| 5 | Mode destinataire | `feat/destinataire` | à écrire (séance de questions d'abord) | à faire |
| 6 | FORMAT.md + explication courte + ROADMAP.md | `docs/format` | à écrire | à faire |

Décision du 2026-10-24 : l'étape 3 passe avant l'étape 2 et avant la
release v2.4.0.

L'étape 0 passe en premier : les parcours de l'interface (`tuiEncrypt`,
`tuiDecrypt`, `tuiVerify`, `runTUI`, `run`, la suppression) sont couverts à
0 %, et l'étape 3 les réécrit.

## Décisions par étape

### 0. Filet de sécurité
- `SPEC.md` à la racine, règles numérotées `R-<DOMAINE>-NN`, chacune liée à au
  moins un test ; un test Go échoue si une règle n'a pas de test existant.
- Interface testée de bout en bout : vrai binaire dans un pty, vérifications
  sur les fichiers produits et le code de sortie, pas sur la mise en page.
- Commandes `-mode …` : `testscript` (`github.com/rogpeppe/go-internal`
  v1.16.0, dépendance de test seulement).
- Seuil de couverture en CI, tests de mutation hebdomadaires sur `pkg/`
  (gremlins v0.6.0, installé dans le workflow, jamais dans `go.mod`),
  fuzzing aller-retour chiffrer → déchiffrer.

### 1. zxcvbn allégé
- Copie interne chargée au premier usage ; dictionnaires anglais gardés ;
  ajout des 7 776 mots français + prénoms et noms INSEE (licence à vérifier).
- Workflow mensuel qui ouvre une issue si trustelem/zxcvbn publie.
- Ne pas retoucher l'affichage de la force : il sera refait à l'étape 3.
- Mesurer : taille du binaire (`-s -w`), mémoire et temps au lancement.

### 2. Releases signées
- cosign keyless + SBOM + provenance.
- `install.sh` : si cosign est absent, vérifie le SHA-256, avertit
  (« signature non vérifiée : installe cosign pour plus de sûreté ») et
  continue.

### 3. Interface plein écran
- Seulement au lancement sans argument ; `-mode …` garde sa sortie simple.
- Un seul programme bubbletea (écran alternatif) qui enchaîne les étapes.
- Barre du haut, barre du bas, cadre centré de 52 à 80 colonnes selon la
  fenêtre. Terminal trop petit : barres masquées, cadre sur toute la place.
- Fin d'opération : retour au menu. En quittant : les résumés complets
  actuels sont imprimés. Erreur : cause + quoi faire dans le cadre, ⏎ menu.
- Phrase gardée pour la session : proposée à confirmer ; indicateur
  « phrase en mémoire » ; oubli après 5 min d'inactivité ; touche `o`.
  Octets mis à zéro à l'oubli, au délai et à la sortie. Jamais de clé
  dérivée gardée : Argon2 tourne à chaque opération (sel par fichier).
- Minuteur d'inactivité : un seul `tea.Tick` réarmé à chaque touche, jamais
  une boucle. Mesurer les réveils au repos (référence 110–150/s).
- Écran d'aide `?` : explication courte + raccourcis.
- Inclut le passage de `phrase_tui.go:168` sur les réglages communs.

### 4. Format v5
- Enveloppes typées dans l'en-tête, permissions dans les métadonnées,
  drapeau « contenu vide » authentifié, taille du clair authentifiée.
- Non retenu : fichier-clé.

### 5. Mode destinataire
- X25519 + ML-KEM-768, nouveau type d'enveloppe v5, sans v6.
- Séance de questions dédiée au début de l'étape.

### 6. Documentation
- Explication « comment ça marche » en très peu de mots, claire pour tout
  le monde : haut du README, écran d'aide, début de FORMAT.md.
- FORMAT.md octet par octet + vecteurs de test ; ROADMAP.md mise à jour.

## Écartés
Lister/extraire un seul fichier, multi-fichiers, découpage du paquet main.
