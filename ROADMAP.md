### Phase 4 : Compression et Choix d'Algo

Attention : On compresse **toujours avant** de chiffrer. Une donnée chiffrée ressemble à du bruit aléatoire et est mathématiquement incompressable.

**Ta mission :**

1. **Compression :**
* Ajoute un flag `-compress` (booléen).
* Si vrai, passe le flux de fichier dans `compress/gzip` ou `github.com/klauspost/compress/zstd` (plus rapide/efficace) *avant* de l'envoyer au chiffrement.
* Mets à jour ton Header (Phase 2) pour indiquer si le fichier est compressé ou non.


2. **Choix d'Algo :**
* Ajoute ChaCha20-Poly1305 (très rapide sur mobile/CPU sans AES-NI).
* Crée une interface Go `Encrypter` pour pouvoir switcher facilement entre AES et ChaCha20 selon le flag utilisateur.



---

### Phase 5 : Le mode "Parano" 😱

Ce mode est pour les utilisateurs qui n'ont confiance en rien.

**Idées d'implémentation pour ce mode :**

1. **Cascade :** Chiffrer avec AES, puis chiffrer le résultat avec ChaCha20.
2. **KDF Lente :** Augmenter drastiquement le temps et la mémoire pour Argon2 (ex: prendre 5 secondes pour dériver la clé), rendant le brute-force impossible.
3. **Nom de fichier :** Chiffrer aussi le nom du fichier original et le stocker dans le Header, puis renommer le fichier de sortie avec un hash aléatoire.

---

### Résumé de l'architecture (Structure des packages)

```text
/cmd/mycrypt/
    main.go       // Gestion des flags CLI
/pkg/
    /crypto/      // Tes wrappers autour d'AES et Argon2
    /format/      // Gestion du Header et lecture/écriture binaire
    /process/     // Pipeline : Compression -> Chiffrement -> RS

```
