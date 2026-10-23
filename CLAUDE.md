# chiffremento — règles du projet

## Légèreté : une exigence au même rang que la sécurité

chiffremento doit rester **léger et rapide** : taille du binaire, mémoire vive,
CPU, batterie, temps de réponse. Une fonctionnalité correcte mais lourde n'est
pas terminée.

1. **Mesurer avant et après** chaque changement qui touche au chemin
   d'exécution : temps, mémoire gardée, taille du binaire
   (`go build -trimpath -ldflags="-s -w"`). Annoncer le chiffre dans la PR,
   même négligeable.
2. **Signaler tout coût qui grandit avec les données** : une structure par
   fichier gardée en mémoire, un appel système par fichier, un parcours de plus
   de l'arborescence. Donner la mesure et proposer une variante plus légère.
3. **Mémoire constante** : streaming plutôt que chargement complet ; empreinte
   plutôt que liste quand il suffit de détecter un changement.
4. **Une dépendance se juge aussi sur son poids** : taille, sous-dépendances,
   processus lancés.

## Repères mesurés (macOS, Apple Silicon, octobre 2026)

- Le temps d'une opération est dominé par Argon2 (profil standard : 256 Mio,
  t=3) ; le chiffrement lui-même est secondaire. Ne pas optimiser l'AEAD avant
  d'avoir mesuré.
- Extraction d'un dossier de 5 000 petits fichiers : 0,47 s sans
  synchronisation, 0,55 s avec la synchronisation légère
  (`pkg/durabilite_*.go`), ~17 s avec un `os.File.Sync` par fichier
  (`F_FULLFSYNC` sous macOS) — à ne jamais réintroduire dans une boucle.
- Relevé avant suppression (`instantane.go`) : empreinte SHA-256 en mémoire
  constante ; une liste par entrée coûtait 14,8 Mo pour 100 000 fichiers.
- Mémoire : le pic d'une opération est le bloc d'Argon2 (~272 Mo en profil
  standard), rendu au système dès la dérivation finie (`debug.FreeOSMemory`
  dans `pkg/keys.go`) : ~17 Mo pendant le traitement. Avant, le bloc restait
  gardé et doublait quand deux dérivations se suivaient (`passwd` : 528 Mo).
  Mesurer avec le « peak memory footprint » de `/usr/bin/time -l`, pas le
  RSS, qui compte encore les pages rendues.
- Archivage et extraction : un seul tampon de copie par opération, jamais un
  par fichier (`io.Copy` en alloue un de 32 Kio à chaque appel).
- Interface : 30 images/s (`imagesParSeconde`, `navigation.go`) : ~110 à 150
  réveils par seconde au repos au lieu de ~250 ; premier écran en ~62 ms.
- zxcvbn (copie interne, `internal/zxcvbn`) : listes zstd embarquées, chargées
  au premier usage. Coût au lancement ≈ 0 : `-version` ~4,2 Mo de pic au lieu
  de ~15,5 Mo, `-mode genpass` ~5,0 Mo au lieu de ~15,9 Mo. Premier
  `PasswordStrength` : 7 à 12 ms, ~15,3 Mo après l'appel. L'interface le
  précharge en arrière-plan à l'écran du mot de passe. Les mots, prénoms et
  noms français sont compris dans ces chiffres.
- Binaire : ~6,2 Mo (`-s -w`), 6 160 850 o (avant : 8 348 898 o).
- L'écran de progression dure au moins 4 s : c'est un choix esthétique, pas un
  coût de calcul.
- La concurrence de l'encodeur zstd est voulue : la brider à 1 coûte ~22 % de
  débit.
