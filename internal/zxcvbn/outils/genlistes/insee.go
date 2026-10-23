package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"chiffremento-cli/internal/zxcvbn/frequency"
)

// Fichiers de l'Insee, téléchargés à la main (curl) hors du dépôt. Le
// générateur lit le fichier DÉZIPPÉ et refuse celui dont l'empreinte SHA-256
// diffère : une édition plus récente change les rangs, donc le résultat.
const (
	// Fichier des prénoms, édition de juillet 2025 (données jusqu'à 2024),
	// fichier national, CSV : prenoms-2024-nat.csv dans l'archive.
	urlPrenoms = "https://www.insee.fr/fr/statistiques/fichier/8894961/prenoms-2024-nat_csv.zip"
	shaPrenoms = "d6f2be15a8408fd9477b40eaba95e0be7931704e56b2df26a382629e9d63c3a0"

	// Fichier des noms de famille, édition de mai 2018 (naissances 1891-2000),
	// fichier national, texte : noms2008nat_txt.txt dans l'archive.
	urlNoms = "https://www.insee.fr/fr/statistiques/fichier/3536630/noms2008nat_txt.zip"
	shaNoms = "a2e9f96883e787171abd9ce664889426484479b0bbb1db4c78965e7a49304fb4"
)

const (
	entetePrenoms  = "sexe;prenom;periode;valeur"
	enteteNomsFin  = "_1991_2000"
	colonnesNoms   = 12 // nom + 11 décennies
	prenomsRares   = "_PRENOMS_RARES"
	autresNoms     = "AUTRES NOMS" // ligne de total des noms rares, pas un nom
	nbEntreesInsee = 10000
)

// effectif est un nom (en majuscules, comme dans le fichier) et son total.
type effectif struct {
	nom   string
	total int
}

// verifierEmpreinte refuse un fichier dont le SHA-256 n'est pas celui attendu.
func verifierEmpreinte(nom string, contenu []byte, attendu string) error {
	somme := sha256.Sum256(contenu)
	if obtenu := hex.EncodeToString(somme[:]); obtenu != attendu {
		return fmt.Errorf("%s : empreinte SHA-256 %s, attendue %s : ce n'est pas le fichier prévu (autre édition ?)", nom, obtenu, attendu)
	}
	return nil
}

// classerPrenoms additionne `valeur` par prénom (tous sexes, toutes années),
// sans _PRENOMS_RARES, du plus fréquent au moins fréquent.
func classerPrenoms(r io.Reader) ([]effectif, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != entetePrenoms {
		return nil, fmt.Errorf("fichier des prénoms : en-tête %q attendu", entetePrenoms)
	}
	totaux := make(map[string]int)
	for ligne := 2; sc.Scan(); ligne++ {
		texte := strings.TrimRight(sc.Text(), "\r")
		if texte == "" {
			continue
		}
		champs := strings.Split(texte, ";")
		if len(champs) != 4 {
			return nil, fmt.Errorf("fichier des prénoms, ligne %d : 4 colonnes attendues, %d trouvées", ligne, len(champs))
		}
		valeur, err := strconv.Atoi(champs[3])
		if err != nil || valeur < 0 {
			return nil, fmt.Errorf("fichier des prénoms, ligne %d : valeur %q illisible", ligne, champs[3])
		}
		if champs[1] == prenomsRares {
			continue
		}
		totaux[champs[1]] += valeur
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return trier(totaux), nil
}

// classerNoms additionne les 11 décennies de chaque nom de famille.
func classerNoms(r io.Reader) ([]effectif, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return nil, fmt.Errorf("fichier des noms : en-tête attendu")
	}
	entete := strings.Split(strings.TrimRight(sc.Text(), "\r"), "\t")
	if len(entete) != colonnesNoms || entete[0] != "NOM" || entete[colonnesNoms-1] != enteteNomsFin {
		return nil, fmt.Errorf("fichier des noms : en-tête inattendu (NOM puis 11 décennies finissant par %s attendus)", enteteNomsFin)
	}
	totaux := make(map[string]int)
	for ligne := 2; sc.Scan(); ligne++ {
		texte := strings.TrimRight(sc.Text(), "\r")
		if texte == "" {
			continue
		}
		champs := strings.Split(texte, "\t")
		if len(champs) != colonnesNoms {
			return nil, fmt.Errorf("fichier des noms, ligne %d : %d colonnes attendues, %d trouvées", ligne, colonnesNoms, len(champs))
		}
		if champs[0] == autresNoms {
			continue
		}
		for _, c := range champs[1:] {
			valeur, err := strconv.Atoi(c)
			if err != nil || valeur < 0 {
				return nil, fmt.Errorf("fichier des noms, ligne %d : effectif %q illisible", ligne, c)
			}
			totaux[champs[0]] += valeur
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return trier(totaux), nil
}

// trier : total décroissant ; à égalité, ordre alphabétique.
func trier(totaux map[string]int) []effectif {
	liste := make([]effectif, 0, len(totaux))
	for nom, total := range totaux {
		liste = append(liste, effectif{nom, total})
	}
	sort.Slice(liste, func(i, j int) bool {
		if liste[i].total != liste[j].total {
			return liste[i].total > liste[j].total
		}
		return liste[i].nom < liste[j].nom
	})
	return liste
}

// lignesFrancais garde les n premiers, en minuscules. Si la forme sans accent
// diffère, elle suit sur une ligne marquée (même rang), sauf si elle existe
// déjà dans la liste : jamais de doublon.
func lignesFrancais(effectifs []effectif, n int) ([]string, error) {
	if len(effectifs) < n {
		return nil, fmt.Errorf("%d entrées dans le fichier, %d demandées", len(effectifs), n)
	}
	gardes := make(map[string]bool, n)
	for _, e := range effectifs[:n] {
		gardes[strings.ToLower(e.nom)] = true
	}
	lignes := make([]string, 0, n+n/10)
	for _, e := range effectifs[:n] {
		mot := strings.ToLower(e.nom)
		lignes = append(lignes, mot)
		if variante := frequency.SansAccent(mot); variante != mot && !gardes[variante] {
			gardes[variante] = true
			lignes = append(lignes, frequency.MarqueVariante+variante)
		}
	}
	return lignes, nil
}
