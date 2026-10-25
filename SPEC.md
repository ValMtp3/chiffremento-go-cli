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
volontaire par Ctrl+C sort avec le code 130, sans message d'erreur ; la
fermeture du terminal (SIGHUP), avec le code 129. Échap ne
fait pas quitter l'interface guidée (voir R-TUI-04).

Tests : TestScripts, TestE2EInterruption

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

Tests : TestE2EChiffrerPuisDechiffrer

### R-TUI-02 — Déchiffrer depuis l'interface guidée
L'interface guidée déchiffre un `.chto` et restitue le contenu d'origine.

Tests : TestE2EChiffrerPuisDechiffrer

### R-TUI-03 — Vérifier depuis l'interface guidée
L'interface guidée contrôle un `.chto` sans rien écrire.

Tests : TestE2EVerifier

### R-TUI-04 — Abandon par Ctrl+C : code 130, terminal restauré, rien d'écrit
Ctrl+C dans l'interface sort avec le code 130, sans message d'erreur, et rend
le terminal (écho, curseur, écran alternatif quitté) dans son état d'origine. Un abandon avant le
lancement de l'opération laisse le dossier tel qu'il était. Pendant le
chiffrement d'un gros fichier, écran de progression affiché et temporaire
`.chto-tmp-*` déjà présent sur le disque, il sort aussi en 130, rend le
terminal, garde l'original intact, supprime le temporaire et ne laisse aucun
chiffré. Si l'opération a déjà écrit sa sortie quand Ctrl+C arrive (fin de
l'animation), les résumés imprimés à la sortie le disent : « ✓ <sortie> écrit
avant l'interruption ». Avant de sortir (Ctrl+C, SIGHUP, panique), la
session attend la fin de l'opération en cours, qui met à zéro ses copies du
mot de passe, au plus 3 s ; au-delà, elle sort quand même.

Échap ne fait jamais quitter l'interface. Avant le lancement de l'opération,
il l'abandonne sans rien écrire et ramène au menu ; sur le menu, il ne fait
rien ; dans l'explorateur, il remonte d'un dossier. Après l'écriture, sur la
question de suppression ou de renommage, il vaut « garder » et ne compte pas
comme un échec.

Tests : TestE2EInterruption, TestE2EInterruptionPendantOperation, TestE2EInterruptionApresEcriture, TestCtrlCApresEcritureLeDit, TestCtrlCAttendQueLeParcoursEfface, TestSortieMalgreUnParcoursBloque, TestE2ECtrlCAvecPhraseGardee, TestEchapAvantLancementRevientAuMenu, TestEchapDansUnChampTexteRevientAuMenu, TestEchapSurLeMenuNeFaitRien, TestEchapApresEcritureGarde, TestEchapRemonteDansLExplorateur

### R-TUI-05 — Mauvaise phrase de passe dans l'interface
Une mauvaise phrase de passe donne un message clair, et rien n'est écrit. En
plein écran, comme tout échec, elle s'affiche dans le cadre : la cause, puis
« quoi faire ». Le conseil porté par le message passe en premier, et seul ;
sinon les erreurs courantes ont un conseil court : mauvaise phrase (vérifier
majuscules, séparateurs, disposition du clavier), fichier abîmé ou qui n'est
pas un fichier chiffremento (repartir d'une copie intacte ; sur un fichier
d'ancien format, une mauvaise phrase donne la même erreur), droits refusés
(vérifier les droits ou choisir un autre emplacement), destination apparue
entre la question et l'écriture (la déplacer ou la renommer — l'interface ne
propose pas -force). `entrée` revient au menu.

Tests : TestE2EMauvaisePhrase, TestEcranErreurMauvaisePhrase, TestEcranErreurQuoiFaire, TestFichierAbime, TestContenuNonAuthentifie

### R-TUI-06 — Grammaire de navigation
`↑↓` parcourent les réponses, `→` ou `entrée` valident, `←` revient à la
décision précédente en gardant les réponses déjà données ; dans un champ texte
et dans l'explorateur, le retour se fait avec `shift+tab`.

Tests : TestAuditValidationAuClavier, TestAuditRetourEnArriere, TestAuditDeplacementDansLesListes, TestAuditExplorateurFleches, TestRetourDepuis, TestRetourDepuisUneListe, TestRetourDepuisUneSaisie, TestRetourDepuisLexplorateur, TestPasDeRetourDepuisLesQuestionsSuivantes, TestEcranMotDePasseRevientEnArriere, TestOptionsSurviventAuRetour, TestFlecheDroiteValideLeDernierChamp, TestFlecheDroiteValideUneQuestionUnique, TestEntreeValideAussiLeDernierChamp, TestFlecheDroiteNeSoumetPasTropTot, TestTouchesExplorateurFerme, TestPremierChampLuApresInit

### R-TUI-07 — Changement de mot de passe réservé à la v4
L'interface refuse de changer le mot de passe d'un fichier d'un ancien format,
avec un message qui l'explique.

Tests : TestTuiPasswdRefuseLesAnciensFormats

### R-TUI-08 — Écran de progression
L'écran de progression dure au moins la durée d'animation prévue, mais la barre
ne dépasse jamais l'avancement réel. En plein écran, il s'affiche dans le cadre
de l'écran hôte : toutes ses lignes ont la largeur du cadre, qu'elles suivent
au redimensionnement, sans couleur ni emoji. Échap n'abandonne pas une écriture
déjà lancée ; l'aide peut s'ouvrir par-dessus sans arrêter l'opération.
Ctrl+C l'interrompt. Un travail sans progression (lecture de l'en-tête,
changement de mot de passe) n'affiche son écran « en cours » qu'au-delà de
100 ms : une lecture d'en-tête ne fait pas clignoter le cadre.

Tests : TestEnCoursRapideSansEcran, TestEnCoursPendantLeTravail, TestEnCoursCtrlCAttendLeTravail, TestAnimationVisible, TestAnimationNeDepassePasLeReel, TestDureeEcranReelle, TestRenduLargeurConstante, TestProgressionSuitLeCadre, TestProgressionDansLeCadreDeLHote, TestProgressionAutonomeLargeurFixe, TestRenduSansCouleur, TestCtrlCInterromptLaProgression, TestEchapPendantEcritureIgnore, TestAidePendantProgression, TestRunJobDansLHote, TestRunJobCtrlCDansLHote

### R-TUI-09 — Écrasement d'un dossier jamais proposé
L'interface peut demander confirmation avant d'écraser un fichier, jamais un
dossier : une destination libre n'autorise rien, un dossier existant est
refusé sans question.

Tests : TestConfirmerEcrasementDossier

### R-TUI-10 — Changer le mot de passe depuis l'interface guidée
L'interface guidée change le mot de passe d'un `.chto` v4 : ensuite, l'ancien
mot de passe est refusé, le nouveau ouvre le fichier et le contenu est intact.

Tests : TestE2EChangerMotDePasse

### R-TUI-11 — Menu persistant, quitter et code de sortie
En plein écran, le menu revient après chaque opération, réussie, abandonnée ou
ratée. Une opération réussie finit sur une carte résultat (le ✓, le fichier
produit, puis la question de suppression ou de renommage, « garder » par
défaut) ; un échec, sur l'écran d'erreur ; `entrée` revient au menu. Refuser d'écraser une
destination (« annuler ») est un choix, pas un échec. On quitte par la ligne
« quitter » du menu ou par la touche `q`, qui n'agit que sur le menu, jamais
pendant une saisie. Le code de sortie de la session vaut 0 si tout a réussi, 1
si au moins une opération a échoué, 130 sur Ctrl+C, 129 si le terminal est
fermé (SIGHUP). Les résumés des
opérations faites, ceux-là mêmes qu'affiche la carte, s'impriment une fois
l'écran alternatif quitté, y compris sur Ctrl+C pendant une opération
suivante. Hors plein écran (TERM=dumb), une seule opération est menée et le
menu garde ses quatre lignes, sans « quitter ». Une panique dans le parcours
ne laisse ni l'écran alternatif ni le terminal en mode brut ni de
temporaire : la phrase est oubliée, le terminal rendu, puis la panique est
imprimée (« erreur interne : … » et la pile) et la session sort en 2.

Tests : TestQuitterDepuisLeMenu, TestMenuSansQuitterEnTermDumb, TestHoteDuCadreEnTermDumb, TestAfficherPrefereLaReponseDeposee, TestPaniqueDuParcoursRendLeTerminal, TestParcoursSansPaniqueNeRendRien, TestQSansEffetPendantSaisie, TestCodeSortieApresEchec, TestAnnulerLEcrasementNEstPasUnEchec, TestCtrlCTermineLaSession, TestSortieExterneLibereLeParcours, TestE2EChiffrerPuisDechiffrer, TestE2EMauvaisePhrase, TestE2EInterruptionGardeLesResumes, TestCarteResultatRevientAuMenu, TestQuestionSuppressionDansLaCarte, TestResumesImprimesALaSortie

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
le test exprès ; elle exige une nouvelle version de format. La lecture des
anciens fichiers est gardée par les fichiers de référence de `testdata/`
(TestCompatibiliteV1, TestCompatibiliteV2), qui échouent s'ils disparaissent.

Tests : TestFormatV4Fige, TestMarshalEnteteV2Exact

### R-FMT-05 — En-tête incohérent ou hostile refusé
Un en-tête qui se contredit (deux façons de décrire la compression, drapeau
inconnu pour la version), ou qui annonce des paramètres Argon2 hors bornes
(jusqu'à 4 Tio de mémoire), est refusé avant toute allocation ou dérivation.

Tests : TestHeaderIncoherentRefuse, TestDrapeauMetadataRefuseAvantV3, TestParametresArgonHorsBornes, TestHeaderMemoireHostile, TestHeaderV3AvecRemplissageResteLisible, TestHeaderDrapeauCompressionSelonLaVersion

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
le signale. Aucune sortie n'est laissée. (FuzzAllerRetour ne couvre que le
refus du déchiffrement d'un chiffré altéré, pas `verify` ni l'absence de sortie.)

Tests : TestHeaderFalsifie, TestV4EnTeteAltere, TestCorpsFalsifie, FuzzAllerRetour

### R-CRY-03 — Aller-retour exact quelles que soient les options
Chiffrer puis déchiffrer rend exactement le contenu d'origine, pour chaque
algorithme (AES-GCM, ChaCha20-Poly1305, cascade), avec ou sans compression
zstd, remplissage, métadonnées, et pour chaque profil de dérivation testé. (FuzzAllerRetour n'utilise qu'un seul
profil de dérivation, la clé maître étant dérivée une fois ; les autres profils
reposent sur les autres tests cités.)

Tests : TestRoundTrip, TestV4RoundTrip, TestRoundTripDossier, TestFluxAllerRetour, FuzzAllerRetour

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

Tests : TestRemplissageMasqueLaTaille, TestPadPalierSuitLeRemplissageReel, TestPadFenetreNePrometPasCeQuElleNeTientPas, TestPadFenetreDegenereAuPlafond, TestMetadataAvecRemplissage, TestPadmeAuxPetitesTailles, TestWritePaddingZero, TestWritePaddingAcceptePlafondExact, TestPadFenetreValeursExactes

### R-CRY-09 — Le remplissage et la compression s'excluent
`-pad` avec `-comp` est refusé à l'écriture, et un fichier qui annonce les deux
est refusé à la lecture.

Tests : TestRemplissageEtCompressionSExcluent, TestRemplissageAvecCompressionEnLecture, TestOptionsValidate

### R-CRY-10 — Les clés sont effacées de la mémoire après usage
Une fois la lecture terminée, la fermeture de la chaîne de déchiffrement
efface les clés : elles ne restent pas en mémoire après chaque opération.

Tests : TestMonterLectureEffaceLesClesALaFermeture

### R-CRY-11 — Une erreur de scellement n'est jamais avalée
En mode cascade, une erreur sur l'une ou l'autre des deux couches lors de la
fermeture remonte à l'appelant, et les deux couches sont toujours fermées :
on n'annonce jamais « succès » sur un fichier dont le dernier bloc manque.

Tests : TestCascadeFermeLesDeuxCouchesEtRemonteLErreur

### R-CRY-12 — La progression suit le travail réel
La progression n'avance que sur des octets réellement lus, finit à 100 %, et au
déchiffrement son total est la taille moins l'en-tête déjà consommé (nul, jamais
négatif, quand la taille d'entrée est inconnue).

Tests : TestProgression, TestProgressionDossier, TestProgressReaderIgnoreLesLecturesVides, TestProgressionDechiffrementSuitLeReste

## FS — fichiers, écrasement, suppression

### R-FS-01 — Destination existante sans `-force` : refus, destination intacte
Une destination qui existe déjà est refusée au chiffrement comme au
déchiffrement, y compris sur le chemin des flux, et son contenu n'est pas
touché. `-force` est le seul moyen de la remplacer.

Tests : TestRefusEcrasementCLI, TestDestinationExistanteRefusee, TestOpenDestRefuseFichierExistant

### R-FS-02 — Aucun fichier partiel après une erreur ou un abandon
Après une erreur de déchiffrement, une destination déjà présente n'est pas
détruite, aucun `.chto-tmp-*` ne reste, et aucun dossier à moitié extrait
n'apparaît. L'interruption nettoie les temporaires en cours. Un abandon dans
l'interface avant le lancement de l'opération n'écrit rien ; un abandon pendant
l'écriture, temporaire `.chto-tmp-*` déjà créé, le supprime et ne laisse aucun
chiffré. Après le nettoyage d'une interruption, l'opération qui tourne encore
jusqu'à la sortie du processus ne peut plus rien créer ni installer : aucune
sortie, aucun temporaire, aucun dossier d'extraction recréé. La fermeture du
terminal (SIGHUP) est une interruption comme les autres, en plein écran comme
en `-mode` : mêmes nettoyages, sortie en 129 (128 + SIGHUP). Une
suppression de temporaire qui échoue (Windows : fichier tout juste fermé)
est réessayée une fois, après 30 ms.

Tests : TestEchecNeDetruitPasLaCible, TestDecryptFluxMauvaisMotDePasseGardeLaDestination, TestDecryptFluxMauvaisMotDePasseNeLaissePasDeFichier, TestNettoyageTemporaires, TestDossierMauvaisMotDePasse, TestE2EInterruption, TestE2EInterruptionPendantOperation, TestNettoyageFermeLeDescripteur, TestEncryptDossierIllisibleRemonteLErreur, TestCommitApresNettoyageRefuse, TestFermerTemporairesRefuseLesNouveaux, TestFermerTemporairesSupprimeCeQuiArrive, TestExtractionInterrompueNeLaisseRien, TestDechiffrementApresFermetureNeLaisseRien, TestExtractionFermeLeFichierOuvert, TestChangePasswordSauvegardeNettoyeeNeTouchePasLEntete, TestE2EInterruptionPendantExtraction, TestCLIRaccrochePendantExtraction, TestCodeDuSignal, TestSurRaccrochageSArrete, TestNettoyageReessaieUneFois, TestNettoyageUnSeulEssaiSiReussi, TestRunJobApresFermetureNeLancePasLOperation

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

Tests : TestMetadataAllerRetour, TestMetadataNomHostile, TestMetadataNomAvecDeuxPointsAllerRetour, TestMetadataNomIllisibleRefuseALEcriture, TestMetadataNomTropLong, TestMetadataBlocCorrompu, TestSansMetadataParDefaut, TestMetadataNomALaLimite

### R-FS-14 — Nom utilisable selon la plateforme
Un nom d'origine restitué est adapté aux règles de la plateforme (caractères
interdits et espaces de fin sous Windows) avant tout renommage.

Tests : TestAdapterNomReglesWindows, TestNomUtilisableAdapteSousWindows, TestNomUtilisableIdentiteSousUnix

### R-TUI-12 — Phrase gardée pour la session, sur demande
En plein écran, après une opération réussie (chiffrer, déchiffrer, vérifier)
dont la phrase a été tapée ou générée, l'interface demande « garder cette
phrase pour la session ? », « ne pas la garder » par défaut ; Échap vaut non.
Rien n'est gardé sans oui. Une phrase gardée est signalée par « ● phrase en
mémoire » en haut, et proposée à la saisie suivante (« utiliser la phrase en
mémoire », par défaut, ou « la saisir ») ; l'utiliser au chiffrement saute la
génération, la saisie et la confirmation ; au chiffrement, la question
montre sous elle le même verdict de force que l'indicateur habituel, calculé
sur une copie mise à zéro ensuite (pas au déchiffrement ni à la
vérification). La question de la garder n'est pas
reposée quand la phrase venait de la session. Changer de mot de passe demande
toujours une saisie.

La phrase est oubliée, octets mis à zéro et indicateur éteint, après 5 min
sans touche (sur n'importe quel écran, progression comprise), par la touche
`o` (hors d'un champ texte), et à la sortie, normale ou par Ctrl+C, avant la
fin du processus. Le délai court à la fois sur l'heure murale et sur
l'horloge monotone : ni une heure qui recule (réglage, NTP) ni une mise en
veille ne prolongent la phrase, et le premier message reçu après l'échéance
l'efface. Seule la phrase est gardée, jamais une clé dérivée. Un seul
minuteur est en attente quand une phrase est gardée, aucun sinon.

La phrase gardée vit dans une page verrouillée en mémoire vive, au mieux
(`mlock` sous macOS et Linux, `VirtualLock` sous Windows) : elle n'est pas
écrite dans le fichier d'échange du système. Si le verrouillage est refusé
(limite `RLIMIT_MEMLOCK`, phrase plus longue qu'une page, autre système), la
phrase est gardée quand même et une note le dit une fois, à la sortie. La
page est mise à zéro puis déverrouillée à l'oubli.

Limite qui reste : pendant la saisie, huh tient le mot de passe dans des
chaînes Go (`string`), immuables, qui ne peuvent pas être mises à zéro : elles
vivent jusqu'au passage du ramasse-miettes et ne sont pas verrouillées. Seules
les copies en `[]byte` (opération, phrase gardée) sont effacées.

Tests : TestPrendreRendUneCopie, TestPhraseOublieeApresDelai, TestPhraseOublieeMemeSiLHorlogeBouge, TestToucheOOublie, TestPhraseOublieeALaSortie, TestUnSeulMinuteur, TestGarderDemandeAccord, TestPhraseProposeeALaSaisie, TestForcePhraseSession, TestPhraseGardeeVerrouillee, TestPhraseNonVerrouilleeContinue, TestPhraseTropLonguePourUnePage, TestVerrouillageDeLaPlateforme, TestPasswdNeProposePasLaPhrase, TestE2EPhraseGardeePourLaSession

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

### R-PHR-08 — Dictionnaires français dans l'indicateur de force
L'indicateur de force connaît le français : les mots de la liste des phrases de
passe (tous au même rang, celui d'un tirage dans cette liste), et les 10 000
prénoms et 10 000 noms de famille les plus fréquents de l'Insee, avec ou sans
accent (le nom « lefèvre » vaut « lefevre », une saisie décomposée collée
depuis le Finder vaut la forme composée) et quelle que soit la casse. Un mot,
un prénom ou un nom courant est annoncé faible, même suivi d'une année.

Tests : TestMotFrancaisFaible, TestMotsFrancaisRangFixe, TestListesFrancaises, TestNomsAccentuesReconnus, TestPrenomDecomposeReconnu, TestPrenomFinissantParUnAccent, TestPrenomInverseAvecAccent

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

## Outils de vérification

Ce ne sont pas des règles du produit : ce sont les filets qui vérifient les
règles ci-dessus.

- **Traçabilité de la spec** : `TestSpec` relie chaque règle `### R-…` à ses
  tests nommés ; une règle sans test fait échouer la suite. En local :
  `go test -run TestSpec .`
- **testscript** : les scripts de `testdata/script` rejouent le vrai binaire
  (drapeaux, codes de sortie). En local : `go test -run TestScripts .`
- **Bout en bout par pseudo-terminal** : `e2e_pty_test.go` pilote l'interface
  dans un vrai pty. En local : `go test -run E2E .`
- **Fuzzing** (3 fuzzers : `FuzzReadHeader`, `FuzzSafeArchivePath`,
  `FuzzAllerRetour`) : `go test ./pkg -run '^$' -fuzz FuzzReadHeader -fuzztime 30s`
  (remplacer le nom du fuzzer).
- **Planchers de couverture** : `.couverture-min` fixe un minimum par paquet ;
  la CI échoue en dessous. En local : `make couverture`
- **Tests de mutation hebdomadaires** : gremlins modifie le code de `pkg/` et
  vérifie que les tests le remarquent (workflow `mutation.yml`, le lundi, deux
  périmètres : `coeur` et `crypto`). En local : `make mutation` (~30 min sur
  10 cœurs, ~1 h sur 4) et `make mutation-crypto` (~11 min sur 10 cœurs,
  ~20 min sur 4).
