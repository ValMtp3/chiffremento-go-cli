# chiffremento — spécification des comportements

Chaque règle décrit ce que l'outil garantit. Elle cite les tests qui la
vérifient ; `spec_test.go` échoue si une règle n'a pas de test, ou cite un
test qui n'existe plus. Changer un comportement = changer la règle ici, dans
la même PR.

Numérotation : `R-<DOMAINE>-NN`, jamais réutilisée (une règle retirée est
barrée, pas renumérotée).

## CLI — ligne de commande

### R-CLI-01 — Sans argument, hors terminal : usage et échec
Sans argument et quand l'entrée standard n'est pas un terminal, l'usage est
écrit sur stderr et le code de sortie est 1. L'interface guidée ne se lance
pas, sinon elle attendrait une saisie qui n'arrivera jamais.

Tests : TestScripts

### R-CLI-02 — Mode inconnu
Un `-mode` inconnu produit un message qui liste les modes valides, et le code
de sortie 1.

Tests : TestScripts

### R-CLI-03 — `-mode` ou `-in` manquant
Sans `-mode` ou sans `-in` (hors `bench` et `genpass`), l'usage est affiché et
le code de sortie est 1.

Tests : TestScripts

### R-CLI-04 — Options hors de leur mode : note et ignorées
Les options de chiffrement (`-comp`, `-pad`, `-pad-niveau`, `-chacha`,
`-parano`, `-kdf`, `-meta`) passées hors du mode `enc` donnent une note sur
stderr et sont ignorées ; l'opération se déroule normalement.

Tests : TestScripts

### R-CLI-05 — Mot de passe lu sur l'entrée standard
Quand l'entrée standard n'est pas un terminal, le mot de passe est la première
ligne lue ; une fin de ligne `\r\n` est retirée. Un mot de passe n'est jamais
un argument de la ligne de commande.

Tests : TestScripts

### R-CLI-06 — `-in -` : le mot de passe vient du terminal
Avec `-in -`, les données arrivent par l'entrée standard et le mot de passe est
demandé sur le terminal de contrôle, sans lire les données comme mot de passe.
Sans terminal utilisable, l'erreur propose `-in FICHIER`.

Tests : TestReadPasswordDepuisTTY, TestReadPasswordSansTTY, TestDoVerifyDepuisFlux

### R-CLI-07 — `-version`
`-version` affiche `chiffremento <version>` sur stdout, code de sortie 0.

Tests : TestScripts

### R-CLI-08 — Erreurs et abandon
Une erreur s'écrit `erreur : <cause>` sur stderr avec le code 1. Un abandon
volontaire (Échap, Ctrl+C) sort avec le code 130, sans message d'erreur.

Tests : TestScripts

### R-CLI-09 — `genpass`
`-mode genpass` écrit la phrase seule, sur une ligne, sur stdout (l'entropie va
sur stderr). `-mots` est borné : en dessous du minimum ou au-dessus du maximum,
la commande échoue.

Tests : TestDoGenpass, TestPhraseTropCourteRefusee, TestPhraseTropLongueRefusee

### R-CLI-10 — Entrées refusées au chiffrement
`enc` refuse, avec un message qui dit pourquoi : une entrée déjà chiffrée
(extension `.chto`), `-in -` sans `-out`, une source identique à la destination
(y compris par chemin équivalent ou lien matériel), `-pad` avec `-comp`, et une
entrée absente.

Tests : TestDoEncryptRefus, TestCheckPaths

### R-CLI-11 — Entrées refusées au déchiffrement et à la vérification
`dec` et `verify` refusent un fichier sans extension `.chto` ; `dec -in -` exige
`-out` ; un fichier au format inconnu est refusé avant toute demande de mot de
passe ; `info` refuse un flux, dont l'en-tête ne peut pas être relu.

Tests : TestDoDecryptEtVerifyRefus

### R-CLI-12 — Options contradictoires
`-chacha` et `-parano` s'excluent. `-pad-niveau` sans `-pad` est refusé plutôt
qu'ignoré : l'utilisateur croirait sa taille masquée.

Tests : TestChooseAlgo, TestCheckPadFlags

### R-CLI-13 — Flux standard composables
`-out -` écrit le chiffré sur la sortie standard, relisible par le chemin
normal. Au déchiffrement d'un dossier, `-out -` sort l'archive en tar, à passer
à `tar`. Une destination spéciale (`/dev/null`, tube nommé, lien symbolique)
reste ce qu'elle est : elle n'est pas remplacée par un fichier ordinaire. Une
sortie fichier reste atomique même quand l'entrée est un flux : aucun temporaire
ne subsiste, et le clair écrit est en `0600`.

Tests : TestEncryptFluxVersFichierAtomique, TestDecryptFluxSortieEnClairPrivee, TestDoEncryptVersSortieStandard, TestDoDecryptDossierVersSortieStandard, TestFluxVersDevNull, TestFluxVersTubeNomme, TestFluxVersLienSymbolique

### R-CLI-14 — Dossier avec séparateur final
Un dossier désigné avec un séparateur final (`photos/`, cas du
glisser-déposer) donne `photos.chto`, jamais un fichier caché `photos/.chto`.

Tests : TestDoEncryptDossierSeparateurFinal

### R-CLI-15 — Aller-retour d'un fichier ou d'un dossier en ligne de commande
Chiffrer puis déchiffrer, fichier ou dossier, rend un contenu identique ; la
sortie par défaut est l'entrée suivie de `.chto`, ou la destination choisie
avec `-out`.

Tests : TestDoEncryptDecryptFichier, TestDoEncryptDestinationChoisie, TestDoEncryptDecryptDossier, TestDoEncryptRemplissage

### R-CLI-16 — `info` : en-tête lisible sans mot de passe
`info` affiche la version, l'algorithme, la compression, le remplissage et les
paramètres Argon2 sans demander de mot de passe ; un ancien format est signalé
comme étant en lecture seule.

Tests : TestDoVerifyEtDoInfo, TestDoInfoAncienFormat

### R-CLI-17 — `passwd` : changer le mot de passe
`passwd` lit l'ancien puis le nouveau mot de passe sur l'entrée standard. Le
nouveau ouvre le fichier, l'ancien non, et la taille du fichier ne change pas
(le corps n'est pas réécrit). Un format antérieur à v4 est refusé avant toute
saisie.

Tests : TestDoPasswd, TestDoPasswdRefusCasSansFichier, TestDoPasswdAncienFormat

## TUI — interface guidée

### R-TUI-01 — Chiffrer un fichier depuis l'interface guidée
Depuis un terminal, sans argument, l'interface guidée mène à un fichier chiffré
lisible par le déchiffrement.

Tests :

### R-TUI-02 — Déchiffrer depuis l'interface guidée
L'interface guidée déchiffre un `.chto` et restitue le contenu d'origine.

Tests :

### R-TUI-03 — Vérifier depuis l'interface guidée
L'interface guidée contrôle un `.chto` sans rien écrire.

Tests :

### R-TUI-04 — Abandon : code 130, terminal restauré, rien de partiel
Échap ou Ctrl+C dans l'interface sort avec le code 130, rend le terminal
(écho, curseur) dans son état d'origine et ne laisse aucun fichier partiel.

Tests :

### R-TUI-05 — Mauvaise phrase de passe dans l'interface
Une mauvaise phrase de passe donne un message clair, et rien n'est écrit.

Tests :

### R-TUI-06 — Grammaire de navigation
`↑↓` parcourent les réponses, `→` ou `entrée` valident, `←` revient à la
décision précédente en gardant les réponses déjà données ; dans un champ texte
et dans l'explorateur, le retour se fait avec `shift+tab`.

Tests : TestAuditValidationAuClavier, TestAuditRetourEnArriere, TestAuditDeplacementDansLesListes, TestAuditExplorateurFleches, TestRetourDepuis, TestRetourDepuisUneListe, TestRetourDepuisUneSaisie, TestRetourDepuisLexplorateur, TestPasDeRetourDepuisLesQuestionsSuivantes, TestEcranMotDePasseRevientEnArriere, TestOptionsSurviventAuRetour, TestFlecheDroiteValideLeDernierChamp, TestFlecheDroiteValideUneQuestionUnique, TestEntreeValideAussiLeDernierChamp, TestFlecheDroiteNeSoumetPasTropTot

### R-TUI-07 — Changement de mot de passe réservé à la v4
L'interface refuse de changer le mot de passe d'un fichier d'un ancien format,
avec un message qui l'explique.

Tests : TestTuiPasswdRefuseLesAnciensFormats

### R-TUI-08 — Écran de progression
L'écran de progression dure au moins la durée d'animation prévue, mais la barre
ne dépasse jamais l'avancement réel. Sa mise en page garde une largeur
constante, sans couleur ni emoji. Ctrl+C l'interrompt.

Tests : TestAnimationVisible, TestAnimationNeDepassePasLeReel, TestDureeEcranReelle, TestRenduLargeurConstante, TestRenduSansCouleur, TestCtrlCInterromptLaProgression

### R-TUI-09 — Écrasement d'un dossier jamais proposé
L'interface peut demander confirmation avant d'écraser un fichier, jamais un
dossier : une destination libre n'autorise rien, un dossier existant est
refusé sans question.

Tests : TestConfirmerEcrasementDossier

## FMT — compatibilité des formats

### R-FMT-01 — Les fichiers v1, v2 et v4 de référence se déchiffrent
Les fichiers produits par les versions précédentes (`pkg/testdata`, v1, v2 et
v4, dossiers et gzip compris) restent déchiffrables avec leur mot de passe, et
le contenu est exact. Un mauvais mot de passe sur un v4 est refusé par
l'engagement de clé.

Tests : TestCompatibiliteV1, TestCompatibiliteV2, TestCompatibiliteV2Dossier, TestCompatibiliteV4, TestVerifyFichierV1

### R-FMT-02 — Les nouveaux fichiers sont en v4
Tout fichier produit est écrit en version 4, avec les paramètres Argon2 du
profil choisi.

Tests : TestV4EstLeFormatProduit, TestEncryptEcritLaVersionCourante, TestEncryptEcritLaVersionCouranteAvecArgonRenforce

### R-FMT-03 — gzip lu, jamais écrit
La compression écrite est zstd. gzip n'est plus produit (refus avec un message
qui rassure sur les anciens fichiers) mais reste lu, y compris en v3.

Tests : TestChooseComp, TestGzipRefuseALEcriture, TestGzipResteLisibleEnV3

### R-FMT-04 — Structure binaire figée
La disposition binaire de l'en-tête v4 est figée par un test : magic, tailles
des champs et de chaque version d'en-tête (dont 117 octets en v4), identifiants
de version, d'algorithme et de compression, drapeaux connus. La modifier casse
le test exprès ; elle exige une nouvelle version de format. Le tripwire
historique garde en plus la version courante au moins égale à 3 et la présence
des fichiers de référence v1 et v2.

Tests : TestFormatV4Fige, TestProtocolSafety_Tripwire

### R-FMT-05 — En-tête incohérent ou hostile refusé
Un en-tête qui se contredit (deux façons de décrire la compression, drapeau
inconnu pour la version), ou qui annonce des paramètres Argon2 hors bornes
(jusqu'à 4 Tio de mémoire), est refusé avant toute allocation ou dérivation.

Tests : TestHeaderIncoherentRefuse, TestDrapeauMetadataRefuseAvantV3, TestParametresArgonHorsBornes, TestHeaderMemoireHostile

### R-FMT-06 — Fichier qui n'est pas un chiffré
Un fichier sans le bon début est refusé, sans être interprété.

Tests : TestFichierInvalide

### R-FMT-07 — Profils de dérivation
Les profils `standard`, `fort` et `maximum` sont de plus en plus coûteux, le
profil choisi est inscrit dans le fichier, et un profil inconnu est refusé.

Tests : TestProfilsKDFCroissantsEtValides, TestProfilKDFInscritDansLeHeader, TestProfilKDFInconnuRefuse, TestParseKDFProfile

## CRY — propriétés cryptographiques

### R-CRY-01 — Mauvais mot de passe : refus, rien d'écrit
Un mauvais mot de passe est refusé avec `ErrBadPassword` (« mot de passe
incorrect ») avant toute écriture, pour un fichier comme pour un dossier.

Tests : TestMauvaisMotDePasse, TestV4MauvaisMotDePasse, TestDossierMauvaisMotDePasse, TestDoDecryptMauvaisMotDePasse

### R-CRY-02 — Un octet modifié : refus
Modifier un seul octet de l'en-tête (version, drapeaux, algorithme, paramètres,
sel, engagement, enveloppe) ou du corps empêche le déchiffrement, et `verify`
le signale. Aucune sortie n'est laissée.

Tests : TestHeaderFalsifie, TestV4EnTeteAltere, TestCorpsFalsifie

### R-CRY-03 — Aller-retour exact quelles que soient les options
Chiffrer puis déchiffrer rend exactement le contenu d'origine, pour chaque
algorithme (AES-GCM, ChaCha20-Poly1305, cascade), avec ou sans compression
zstd, remplissage, métadonnées, et pour chaque profil de dérivation testé.

Tests : TestRoundTrip, TestV4RoundTrip, TestRoundTripDossier, TestFluxAllerRetour

### R-CRY-04 — Fichier tronqué : refus, aucun clair partiel
Un chiffré tronqué est refusé, et le clair authentifié jusqu'au point de
coupure n'atteint jamais le chemin final. Une archive coupée à l'en-tête ne
produit pas un dossier vide.

Tests : TestFichierTronque, TestTronquageNeLaissePasDeClair, TestArchiveTronqueeALEntete

### R-CRY-05 — Engagement sur la clé
L'engagement écrit dans l'en-tête ne dépend que du couple (mot de passe, sel) :
deux mots de passe distincts donnent deux engagements distincts, le même mot de
passe donne toujours le même, un sel différent change l'engagement, et il est
distinct de la clé d'enveloppe.

Tests : TestV4EngagementSurLaCle

### R-CRY-06 — La clé du contenu ne dépend pas du mot de passe
La clé qui chiffre les données est tirée au hasard par fichier, ce qui permet de
changer le mot de passe sans réécrire le corps.

Tests : TestV4CleDuContenuIndependanteDuMotDePasse, TestChangePassword, TestChangePasswordEnchaine

### R-CRY-07 — Changement de mot de passe sans perte
Avec un ancien mot de passe faux, le fichier n'est pas touché d'un octet. Les
formats antérieurs à v4 sont refusés avec un message qui dit quoi faire. Une
sauvegarde d'en-tête laissée par un changement interrompu n'est jamais écrasée
sans que l'utilisateur ait tranché.

Tests : TestChangePasswordMauvaisAncien, TestChangePasswordAnciensFormats, TestChangePasswordSauvegardePresente, TestChangePasswordSauvegardeDifferenteResteRefusee, TestChangePasswordSauvegardeIdentiqueEstReprise, TestChangePasswordSyncEnEchecGardeLaSauvegarde, TestChangePasswordRetourArriereNonConfirmeGardeLaSauvegarde, TestChangePasswordEntreesInvalides

### R-CRY-08 — Remplissage : la taille est réellement masquée
Avec `-pad`, deux fichiers de tailles proches (même palier) donnent des chiffrés
de même taille ; la fenêtre annoncée à l'utilisateur est exacte, et se réduit
au fichier lui-même au-delà du plafond.

Tests : TestRemplissageMasqueLaTaille, TestPadPalierSuitLeRemplissageReel, TestPadFenetreNePrometPasCeQuElleNeTientPas, TestPadFenetreDegenereAuPlafond, TestMetadataAvecRemplissage

### R-CRY-09 — Le remplissage et la compression s'excluent
`-pad` avec `-comp` est refusé à l'écriture, et un fichier qui annonce les deux
est refusé à la lecture.

Tests : TestRemplissageEtCompressionSExcluent, TestRemplissageAvecCompressionEnLecture, TestOptionsValidate

## FS — fichiers, écrasement, suppression

### R-FS-01 — Destination existante sans `-force` : refus, destination intacte
Une destination qui existe déjà est refusée au chiffrement comme au
déchiffrement, y compris sur le chemin des flux, et son contenu n'est pas
touché. `-force` est le seul moyen de la remplacer.

Tests : TestRefusEcrasementCLI, TestDestinationExistanteRefusee, TestOpenDestRefuseFichierExistant

### R-FS-02 — Aucun fichier partiel après une erreur ou un abandon
Après une erreur de déchiffrement, une destination déjà présente n'est pas
détruite, aucun `.chto-tmp-*` ne reste, et aucun dossier à moitié extrait
n'apparaît. L'interruption nettoie les temporaires en cours.

Tests : TestEchecNeDetruitPasLaCible, TestDecryptFluxMauvaisMotDePasseGardeLaDestination, TestDecryptFluxMauvaisMotDePasseNeLaissePasDeFichier, TestNettoyageTemporaires, TestDossierMauvaisMotDePasse

### R-FS-03 — Fichier vide : aller-retour exact
Un fichier vide se chiffre et se déchiffre en un fichier vide, ainsi qu'un
dossier vide.

Tests : TestRoundTripFichierVide, TestDossierVideResteLisible

### R-FS-04 — Noms avec espaces, accents, emoji : aller-retour exact
Les fichiers et dossiers dont le nom contient des espaces, des accents ou des
emoji sont chiffrés et restitués à l'identique.

Tests : TestScripts

### R-FS-05 — Un dossier existant n'est jamais fusionné
Déchiffrer une archive vers un dossier qui existe déjà est refusé, et le
contenu préexistant n'est pas touché.

Tests : TestDossierDestinationExistante

### R-FS-06 — Un dossier extrait ne s'écrase jamais, même avec `-force`
`-force` n'autorise pas à remplacer un dossier existant : cela reviendrait à
supprimer une arborescence entière.

Tests : TestScripts

### R-FS-07 — Liens symboliques refusés
Un lien symbolique, seul ou dans un dossier, est refusé au chiffrement avec un
message qui parle de lien, et aucun fichier de sortie n'est créé.

Tests : TestLienSymboliqueRefuse, TestDossierLienSymboliqueRefuse

### R-FS-08 — Une archive ne sort jamais de son dossier
À l'extraction, une entrée qui remonte (`..`), un chemin absolu, un lien, un
tube, un doublon ou une arborescence trop profonde fait refuser l'archive, et
rien n'est écrit hors du dossier de destination. `verify` refuse ce que
l'extraction refuserait.

Tests : TestExtractionRefuseLesCheminsHostiles, TestExtractionRefuseUnDoublon, TestVerifyDetecteUneArchiveHostile, TestSafeArchivePath, TestArborescenceTropProfonde, FuzzSafeArchivePath

### R-FS-09 — `verify` n'écrit rien
`verify` contrôle le fichier de bout en bout sans rien poser sur le disque,
même sur un fichier sain.

Tests : TestVerifyNEcritRien, TestVerify

### R-FS-10 — Permissions restreintes
Les fichiers produits (chiffré et déchiffré) sont en `0600` sur macOS et Linux.
Sous Windows, cette limite est documentée dans le modèle de menace.

Tests : TestPermissions

### R-FS-11 — Suppression de l'original seulement si la source est inchangée
Après une opération, l'original n'est supprimé que si la source est identique à
celle qui a été archivée : un fichier ajouté ou modifié entre-temps bloque la
suppression, et rien n'est effacé. La suppression n'est pas proposée quand le
chiffré est à l'intérieur du dossier à effacer.

Tests : TestVerifierInchange, TestVerifierInchangeFichierSeul, TestEffacerSiInchange, TestSuppressionPossible, TestRaisonSansReleve

### R-FS-12 — Nom et date brouillés
Un nom de sortie brouillé ne dit rien de la source mais reste dans son dossier ;
la date de modification est celle du 1er janvier 2000, et un échec pour la poser
remonte au lieu de passer pour un succès.

Tests : TestNomBrouille, TestBrouillerDate, TestBrouillerDateFichierAbsent

### R-FS-13 — Métadonnées conservées : un nom lisible au retour
Avec `-meta minimal`, tout nom légal se relit (y compris `rapport 10:30.txt`) ;
un nom que la relecture refuserait est refusé dès le chiffrement ; un nom
hostile (`../..`, chemin absolu, octet nul) est réduit à son dernier élément ou
refusé.

Tests : TestMetadataAllerRetour, TestMetadataNomHostile, TestMetadataNomAvecDeuxPointsAllerRetour, TestMetadataNomIllisibleRefuseALEcriture, TestMetadataNomTropLong, TestMetadataBlocCorrompu, TestSansMetadataParDefaut

### R-FS-14 — Nom utilisable selon la plateforme
Un nom d'origine restitué est adapté aux règles de la plateforme (caractères
interdits et espaces de fin sous Windows) avant tout renommage.

Tests : TestAdapterNomReglesWindows, TestNomUtilisableAdapteSousWindows, TestNomUtilisableIdentiteSousUnix

## PHR — phrase de passe

### R-PHR-01 — Structure de la phrase générée
Une phrase est faite de mots de la liste intégrée (CC0, Tails et Tor), avec une
majuscule en tête de mot, un séparateur entre chaque mot et exactement un
chiffre. Le nombre de mots est borné par un minimum et un maximum.

Tests : TestListeDeMots, TestPhraseStructure, TestPhraseTropCourteRefusee, TestPhraseTropLongueRefusee

### R-PHR-02 — Entropie annoncée exacte et uniforme
L'entropie affichée n'est ni gonflée ni arrondie à l'avantage de l'outil, et le
tirage est uniforme (aucun biais sur les séparateurs ni les chiffres).

Tests : TestPhraseEntropie, TestPhraseUniformite

### R-PHR-03 — Source d'aléa défaillante : échec
Si l'aléa fait défaut, la génération échoue : jamais de phrase prévisible en
silence.

Tests : TestPhraseAleaEnPanne

### R-PHR-04 — Phrase affichée masquée par défaut
Dans l'interface, la phrase est masquée par défaut, sans révéler sa longueur,
et remasquée en quittant l'écran : elle ne reste pas en clair dans le
défilement du terminal. Copier ne l'affiche pas, et un échec de copie est expliqué.

Tests : TestPhraseMasqueeParDefaut, TestPhraseMasqueSansLongueur, TestPhraseRemasqueeEnQuittant, TestPhraseCopie, TestPhraseCopieEnEchec

### R-PHR-05 — Phrase générée : cohérente avec le contrôle de force
Une phrase proposée par l'outil passe son propre contrôle de robustesse ;
l'entropie est affichée ; l'écran permet de régénérer, de changer le nombre de
mots (dans les bornes) et de continuer, revenir ou interrompre.

Tests : TestPhraseGenereePasseLeControleDeForce, TestPhraseAfficheEntropie, TestPhraseRegenererEtNombreDeMots, TestPhraseSortiesDeLEcran

### R-PHR-06 — La phrase choisie est celle qui chiffre
La phrase générée chiffre le fichier quand elle est choisie ; un mot de passe
saisi plus tôt puis abandonné ne sert jamais à sa place. Une phrase copiée peut
être collée dans le champ du déchiffrement.

Tests : TestSecretChoisi, TestCollerLeMotDePasseAuDechiffrement

### R-PHR-07 — Indicateur de force réaliste
La force du mot de passe est évaluée avec les dictionnaires (un mot courant est
annoncé faible) ; un mot de passe court reste valide, la faiblesse n'est pas un
refus.

Tests : TestIndicateurDeForceDictionnaire, TestValidatePassword

## PERF — repères de légèreté

### R-PERF-01 — La mémoire d'Argon2 est rendue au système
Le bloc de mémoire d'Argon2 est rendu dès la dérivation finie, au lieu de rester
gardé pendant tout le traitement ; deux dérivations consécutives ne doublent pas
le pic.

Tests : TestArgon2RendSaMemoire

### R-PERF-02 — Un seul tampon de copie par opération d'archivage
L'archivage et l'extraction utilisent un tampon de copie par opération, pas un
par fichier.

Tests : TestArchiveSansTamponParFichier

### R-PERF-03 — Relevé avant suppression en mémoire constante
Le relevé qui détecte un changement de la source tient en mémoire constante
quelle que soit la taille du dossier (une empreinte, pas une liste).

Tests : TestInstantaneMemoireConstante
