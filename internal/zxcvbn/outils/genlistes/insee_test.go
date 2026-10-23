package main

import (
	"reflect"
	"strings"
	"testing"
)

const enteteNoms = "NOM\t_1891_1900\t_1901_1910\t_1911_1920\t_1921_1930\t_1931_1940\t_1941_1950\t_1951_1960\t_1961_1970\t_1971_1980\t_1981_1990\t_1991_2000"

func TestClasserPrenoms(t *testing.T) {
	// CRLF comme dans le fichier réel ; _PRENOMS_RARES est exclu ; les lignes
	// d'un même prénom (sexes et années différents) s'additionnent ; à égalité,
	// l'ordre alphabétique décide.
	csv := "sexe;prenom;periode;valeur\r\n" +
		"1;JEAN;2000;10\r\n" +
		"2;JEAN;2001;5\r\n" +
		"2;ALICE;2000;15\r\n" +
		"1;BOB;2000;15\r\n" +
		"1;_PRENOMS_RARES;2000;999\r\n" +
		"1;ZOE;2000;1\r\n"
	got, err := classerPrenoms(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	want := []effectif{{"ALICE", 15}, {"BOB", 15}, {"JEAN", 15}, {"ZOE", 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClasserPrenomsEnteteInattendu(t *testing.T) {
	_, err := classerPrenoms(strings.NewReader("prenom;sexe;valeur\r\n"))
	if err == nil || !strings.Contains(err.Error(), "en-tête") {
		t.Errorf("erreur claire sur l'en-tête attendue, obtenu : %v", err)
	}
}

func TestClasserPrenomsValeurIllisible(t *testing.T) {
	_, err := classerPrenoms(strings.NewReader("sexe;prenom;periode;valeur\r\n1;JEAN;2000;beaucoup\r\n"))
	if err == nil || !strings.Contains(err.Error(), "ligne 2") {
		t.Errorf("erreur avec le numéro de ligne attendue, obtenu : %v", err)
	}
}

// « AUTRES NOMS » regroupe tous les noms rares : ce n'est pas un nom.
func TestClasserNoms(t *testing.T) {
	txt := enteteNoms + "\r\n" +
		"DUPONT\t1\t1\t1\t1\t1\t1\t1\t1\t1\t1\t1\r\n" +
		"MARTIN\t5\t0\t0\t0\t0\t0\t0\t0\t0\t0\t7\r\n" +
		"AUTRES NOMS\t900\t900\t900\t900\t900\t900\t900\t900\t900\t900\t900\r\n"
	got, err := classerNoms(strings.NewReader(txt))
	if err != nil {
		t.Fatal(err)
	}
	want := []effectif{{"MARTIN", 12}, {"DUPONT", 11}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestClasserNomsEnteteInattendu(t *testing.T) {
	_, err := classerNoms(strings.NewReader("NOM\tTOTAL\r\n"))
	if err == nil || !strings.Contains(err.Error(), "en-tête") {
		t.Errorf("erreur claire sur l'en-tête attendue, obtenu : %v", err)
	}
}

func TestClasserNomsColonnesManquantes(t *testing.T) {
	_, err := classerNoms(strings.NewReader(enteteNoms + "\r\nDUPONT\t1\t2\r\n"))
	if err == nil || !strings.Contains(err.Error(), "ligne 2") {
		t.Errorf("erreur avec le numéro de ligne attendue, obtenu : %v", err)
	}
}

func TestLignesFrancaisVariantesSansAccent(t *testing.T) {
	effectifs := []effectif{{"HÉLÈNE", 9}, {"JEAN-LUC", 8}, {"ŒDIPE", 7}, {"HELENE", 6}, {"D'ARTAGNAN", 5}, {"ÆLFRED", 4}}
	got, err := lignesFrancais(effectifs, 4)
	if err != nil {
		t.Fatal(err)
	}
	// 4 entrées gardées ; variante juste après, marquée par une tabulation ;
	// « helene » existe déjà comme entrée à part : pas de variante en double.
	want := []string{"hélène", "jean-luc", "œdipe", "\toedipe", "helene"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLignesFrancaisTropCourt(t *testing.T) {
	if _, err := lignesFrancais([]effectif{{"A", 1}}, 2); err == nil {
		t.Error("une erreur est attendue quand il y a moins d'entrées que demandé")
	}
}

func TestSansAccent(t *testing.T) {
	for entree, attendu := range map[string]string{
		"élève": "eleve", "où": "ou", "noël": "noel", "maïs": "mais", "garçon": "garcon",
		"cœur": "coeur", "æon": "aeon", "ÿ": "y", "plain": "plain", "ñandu": "ñandu",
	} {
		if got := sansAccent(entree); got != attendu {
			t.Errorf("sansAccent(%q) = %q, attendu %q", entree, got, attendu)
		}
	}
}

func TestVerifierEmpreinte(t *testing.T) {
	// SHA-256 de "abc"
	const sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if err := verifierEmpreinte("f.csv", []byte("abc"), sha); err != nil {
		t.Errorf("empreinte correcte refusée : %v", err)
	}
	err := verifierEmpreinte("f.csv", []byte("abd"), sha)
	if err == nil || !strings.Contains(err.Error(), "empreinte") {
		t.Errorf("refus clair attendu, obtenu : %v", err)
	}
}

func TestVersTexteRefuseLaMarqueDeVariante(t *testing.T) {
	if _, err := versTexte("anglais", []string{"ok", "\tpas-ok"}); err == nil {
		t.Error("un mot anglais qui commence par une tabulation doit être refusé")
	}
	if _, err := versTexteLignes("fr", []string{"hélène", "\thelene"}); err != nil {
		t.Errorf("une ligne de variante est valide en français : %v", err)
	}
	if _, err := versTexteLignes("fr", []string{"a\tb"}); err == nil {
		t.Error("une tabulation au milieu d'une ligne doit être refusée")
	}
}
