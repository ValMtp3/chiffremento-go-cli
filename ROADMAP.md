# Roadmap Chiffremento CLI

> **Légende**
> - 🔥 **Priorité haute** · ⭐️ **Priorité moyenne** · ☁️ **Idées futures**
> - 🟢 **Facile** | 🟡 **Moyen** | 🔴 **Difficile**

## ✅ Livré en v2.0

- [x] Interface guidée (TUI) — `huh` + `bubbletea`, lancée quand aucun flag n'est passé
- [x] Barre de progression sur les gros fichiers
- [x] Écriture atomique — un échec ne détruit plus le fichier de destination
- [x] Format v2 : paramètres Argon2 stockés dans le fichier, en-tête lié à la clé
- [x] Argon2id porté à 256 MiB (~11× plus coûteux à attaquer)
- [x] Mode parano corrigé : un seul Argon2 au lieu de deux, l'attaquant paye enfin le même prix
- [x] Suppression du flag `-key` — le mot de passe ne transite plus par la ligne de commande
- [x] `-mode info` — inspecter un `.chto` sans mot de passe
- [x] `-mode verify` — contrôler qu'un fichier est intact et déchiffrable sans rien écrire
- [x] Indicateur de force du mot de passe en direct dans la TUI
- [x] Nettoyage des temporaires sur Ctrl+C, et `fsync` du répertoire après le rename

---

## Phase 1 : Sécurité du format

### 🔥 🟡 Clé de fichier et enveloppe (DEK/KEK)

Aujourd'hui, la clé de chiffrement **est** dérivée du mot de passe. Conséquence : changer de mot de passe impose de re-chiffrer tout le fichier, et il est impossible d'avoir plusieurs mots de passe pour un même fichier.

La structure classique : tirer une clé aléatoire par fichier (la DEK), chiffrer les données avec elle, puis stocker la DEK chiffrée par une clé dérivée du mot de passe (la KEK), dans l'en-tête.

Ce que ça débloque, pour ~40 lignes :

- `chiffremento passwd -in fichier.chto` : changer le mot de passe en réécrivant 60 octets d'en-tête, même sur un fichier de 100 Go ;
- plusieurs mots de passe ou destinataires pour un même fichier (une enveloppe chacun) ;
- **prérequis du mode post-quantique** ci-dessous.

C'est le changement de structure le plus rentable qui reste. À faire avant tout le reste de cette phase, parce qu'il modifie le format.

### 🔥 🟢 Profils KDF sélectionnables

Les paramètres Argon2 sont désormais dans l'en-tête, donc ajustables sans casser l'existant. Reste à les exposer, avec trois profils nommés plutôt que des chiffres à retenir :

| Profil | m | t | p | Durée mesurée | Usage |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `standard` *(défaut)* | 256 MiB | 3 | 4 | ~144 ms | le compromis actuel |
| `fort` | 512 MiB | 4 | 4 | ~400 ms | données sensibles, mot de passe moyen |
| `parano` | 1 GiB | 4 | 4 | ~1,2 s | secret durable, attaquant motivé |

`chiffremento -mode enc -in doc.pdf -kdf fort`, et un sélecteur dans la TUI affichant la durée réelle mesurée sur la machine.

Deux points à ne pas manquer :

- **le déchiffrement exige la même mémoire que le chiffrement.** Un fichier scellé en `parano` sur une machine à 32 Go sera indéchiffrable sur un Raspberry Pi. À afficher clairement au moment du choix ;
- le plafond de lecture est fixé à 2 GiB (garde-fou anti-OOM), les profils doivent rester en dessous.

Dépend du benchmark ci-dessous pour proposer un profil adapté à la machine.

### 🔥 🟡 Métadonnées optionnelles et masquées

`rapport-medical.pdf.chto` annonce son contenu. Déplacer les métadonnées **à l'intérieur** du flux chiffré, dans un petit bloc en tête de payload, et rendre chaque champ optionnel :

- **nom d'origine** — restauré au déchiffrement, ce qui permet une sortie neutre (`a3f9c2.chto`) ;
- **date de modification** — aujourd'hui simplement perdue ;
- **permissions** — idem.

Avec trois niveaux : tout conserver (défaut), **minimiser** (date arrondie au jour, permissions normalisées à 0600), ou **tout masquer** (aucune métadonnée écrite, le déchiffré prend un nom neutre et la date du jour).

Arrondir la date plutôt que la conserver au nanoseconde n'est pas cosmétique : une date précise corrèle un fichier chiffré avec des traces système, des journaux ou d'autres fichiers.

À combiner avec le masquage de taille ci-dessous — nom, date et taille sont les trois fuites du même ordre.

### ⭐️ 🟢 Fichier-clé en second facteur

Combiner le mot de passe avec le contenu d'un fichier (sur une clé USB, par exemple) via HKDF : `chiffremento -mode enc -in doc.pdf -keyfile /Volumes/USB/cle.bin`. Un mot de passe seul devient insuffisant, et la force ne dépend plus uniquement de ce que l'utilisateur retient. Simple à implémenter, gain réel.

### ⭐️ 🟡 Masquage de la taille (padding)

La taille du `.chto` suit celle du clair : sur un jeu de fichiers connu, ça suffit parfois à identifier lequel a été chiffré. Ajouter un remplissage optionnel par paliers (arrondi à la puissance de deux supérieure, ou à un multiple configurable), avec la longueur réelle stockée dans le flux chiffré.

> Note : cette fonctionnalité a été annoncée à tort dans le README de la v1.1.0 alors qu'elle n'existait pas. La mention a été retirée ; à réimplémenter pour de vrai ici.

### ⭐️ 🟢 Sortie ASCII (`-armor`)

Encodage base64 avec en-tête et pied lisibles, pour coller un secret dans un mail ou une messagerie. C'est ce que fait `age --armor`.

### 🔥 🟢 Commande `benchmark`

`chiffremento benchmark` mesure Argon2id sur la machine hôte et **recommande un profil**, au lieu de laisser deviner. Sortie visée :

```
argon2id sur cette machine (10 cœurs, 32 Gio)

  32 MiB  t=3  p=4      23 ms   ← format v1, trop faible aujourd'hui
  64 MiB  t=3  p=4      38 ms   ← plancher RFC 9106
 256 MiB  t=3  p=4     144 ms   ← standard, recommandé ici
 512 MiB  t=4  p=4     412 ms   ← fort
   1 GiB  t=4  p=4    1230 ms   ← parano

débit AEAD          aes-256-gcm 2.1 Gio/s · chacha20 1.4 Gio/s · cascade 780 Mio/s
```

Deux usages : choisir un profil KDF en connaissance de cause, et **savoir sur quelle machine on déchiffrera**. Le débit AEAD sert aussi à trancher entre AES et ChaCha — sur une machine sans accélération AES, ChaCha est nettement plus rapide, ce qui n'est pas évident *a priori*.

Ne pas utiliser `crypto/rand` pour les données de test : de l'aléa n'est pas nécessaire pour mesurer un débit et ça faussait la mesure sur les petits volumes.

---

## Phase 2 : Mode destinataire et post-quantique

> **Précision importante.** Le mode mot de passe actuel est **déjà résistant au quantique**. Argon2id + AES-256-GCM / ChaCha20-Poly1305 relèvent de la cryptographie symétrique : l'algorithme de Grover ramène 256 bits de sécurité à 128, ce qui reste hors d'atteinte. Il n'y a donc **rien à corriger** de ce côté, et l'annoncer serait mérité plutôt que marketing.
>
> Le post-quantique ne devient un vrai sujet que le jour où l'outil gagne un mode à **clé publique** : c'est là que X25519 et RSA tomberaient face à l'algorithme de Shor.

### ⭐️ 🔴 Mode destinataire + KEM hybride

- `chiffremento keygen` : génère une paire de clés. Chiffrer pour quelqu'un sans partager de mot de passe au préalable, comme `age`.
- Encapsulation **hybride X25519 + ML-KEM-768**, les deux secrets partagés combinés par HKDF (pas par XOR). Jamais de ML-KEM seul : le post-quantique est jeune, l'hybride conserve la sécurité classique si la cryptanalyse progresse.
- **Zéro dépendance** : `crypto/mlkem` (ML-KEM-768, FIPS 203) et `crypto/ecdh` sont dans la bibliothèque standard depuis Go 1.24, et le projet est déjà en Go 1.25. Surveiller aussi `crypto/hpke` (Go 1.26) si un KEM hybride y est ajouté.
- Impact format : nouvel identifiant d'algorithme et un bloc « destinataire » dans l'en-tête — l'encapsulation ML-KEM-768 pèse 1 088 octets.
- **Prérequis** : l'enveloppe DEK/KEK de la phase 1. Sans elle, le multi-destinataires est impossible.

---

## Phase 3 : Quel algorithme ajouter ?

### 🔥 🟢 D'abord : engagement de clé (*key commitment*)

**Ce n'est pas un nouveau chiffrement, et c'est pourtant l'ajout cryptographique le plus utile qui reste.**

AES-GCM et ChaCha20-Poly1305 ne sont **pas engageants sur la clé** : on peut fabriquer un ciphertext qui se déchiffre *validement* sous plusieurs clés différentes. Sur un outil dont la clé vient d'un mot de passe, ça ouvre la porte aux **attaques par oracle de partitionnement** (Len, Grubbs et Ristenpart, USENIX 2021) : au lieu d'éliminer un mot de passe par tentative, l'attaquant en élimine des milliers d'un coup. Autrement dit, les 144 ms d'Argon2 payées à chaque essai peuvent être contournées.

Honnêtement : l'attaque classique suppose un **oracle** — un service qui répond « déchiffrement réussi » ou non. Sur un outil de fichiers hors ligne, il n'y en a pas, donc l'exposition réelle est faible aujourd'hui. Mais elle devient réelle dès que `chiffremento` est appelé dans un service, un script automatisé ou un pipeline de sauvegarde qui rejoue des essais. Et le correctif est presque gratuit.

**Correctif, zéro dépendance, ~15 lignes :** ajouter au format un tag d'engagement de 32 octets,

```
commit = HKDF-Expand(SHA-256, masterKey, "chiffremento-v3-commit", 32)
```

écrit dans l'en-tête, comparé en temps constant **avant** de déchiffrer quoi que ce soit. Une clé qui ne correspond pas est rejetée immédiatement, et il devient impossible de fabriquer un ciphertext valide sous deux clés. Bénéfice secondaire : un mauvais mot de passe donne enfin une erreur claire au lieu d'un `sio: authentication failed`.

À faire en même temps que l'enveloppe DEK/KEK, les deux touchent l'en-tête.

### ⭐️ 🔴 Ensuite, si vraiment un nouvel AEAD

**Le coût caché domine le choix.** `minio/sio` ne connaît qu'AES-GCM et ChaCha20-Poly1305. Ajouter un troisième chiffrement veut dire **abandonner le format DARE** et écrire soi-même le découpage en blocs authentifiés — or c'est précisément là que se glissent les bugs de troncature et de réordonnancement, que DARE empêche gratuitement aujourd'hui. Ce n'est pas un ajout d'algorithme, c'est une réécriture du cœur.

Par ordre d'intérêt réel :

- **AEGIS-256** — le choix « moderne » défendable. Portfolio final CAESAR, en cours de normalisation au CFRG (`draft-irtf-cfrg-aegis-aead`), clé et nonce de 256 bits, et **souvent 2× plus rapide qu'AES-GCM** sur un processeur avec accélération AES, parce qu'il utilise les instructions AES sans passer par GCM. Il est aussi conçu avec les propriétés d'engagement en tête, ce que les analyses récentes soutiennent. Réserve : pas dans la bibliothèque standard, moins éprouvé en production que les deux autres, et pour un outil de chiffrement c'est un vrai argument contre.

- **XChaCha20-Poly1305** — nonce de 192 bits, donc tirage aléatoire sûr indéfiniment. Disponible dans `x/crypto/chacha20poly1305` (`NewX`). Mais DARE gère déjà les nonces correctement, avec numéro de séquence et marqueur de bloc final : **le gain concret ici est proche de zéro**. C'était dans l'ancienne roadmap ; je le déclasse.

- **AES-256-GCM-SIV** (RFC 8452) — résistant à la réutilisation de nonce. Même remarque : le problème qu'il résout n'existe pas dans ce format.

- **Rien de post-quantique.** Il n'y a aucun AEAD post-quantique à ajouter : AES-256 et ChaCha20 le sont déjà. Grover ramène 256 bits à 128, hors d'atteinte. Le post-quantique ne concerne que le mode à clé publique ci-dessus.

**Recommandation.** L'engagement de clé, oui, tout de suite. Un quatrième chiffrement, non — sauf si le format est de toute façon réécrit pour le chunking parallèle ci-dessous, auquel cas AEGIS-256 devient le candidat naturel, les deux chantiers partageant le même travail de fond.

Et une remarque sur l'existant : le mode cascade coûte deux passes de chiffrement pour se protéger d'une faiblesse dans **un seul** des deux algorithmes. C'est défendable, mais un tag d'engagement apporte plus de sécurité réelle pour une fraction du coût.

---

## Phase 4 : Performance

### ⭐️ 🔴 Chunking parallèle

Découper les gros fichiers pour chiffrer sur plusieurs cœurs. Attention : chaque bloc a besoin de son propre nonce et d'un index authentifié, sous peine de rendre possibles la réorganisation et la troncature — ce que le format DARE de `sio` empêche aujourd'hui gratuitement. À ne tenter que si le gain de débit est mesuré et significatif.

---

## Phase 5 : Confort et écosystème

- [ ] **Répertoires récursifs** 🔥 🟡 — chiffrer une arborescence en la conservant. À combiner avec le chiffrement des noms de fichiers.
- [ ] **Générateur de phrases de passe** ⭐️ 🟢 — `chiffremento genpass`, diceware ou équivalent, tiré de `crypto/rand`.
- [ ] **Détection des mots de passe faibles** ⭐️ 🟡 — l'estimation d'entropie livrée en v2.0 est purement combinatoire : elle ne repère ni les mots du dictionnaire, ni `azerty123`, ni les répétitions. Un vrai analyseur (zxcvbn) serait plus honnête.
- [ ] **Entrée et sortie sur les tubes** ⭐️ 🟢 — `-in -` et `-out -` pour s'insérer dans un pipeline (`tar czf - dossier | chiffremento -mode enc -in -`).
- [ ] **Complétions shell et page de manuel** ☁️ 🟢 — bash, zsh, fish.
- [ ] **Effacement de la source après chiffrement** ☁️ 🟡 — avec un avertissement honnête : sur SSD et systèmes de fichiers journalisés, la réécriture ne garantit rien.
