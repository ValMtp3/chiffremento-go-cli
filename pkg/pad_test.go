package pkg

import "testing"

// Le remplissage annoncé à l'écran doit être celui que le chiffrement écrit.
// Les deux calculs ont divergé une fois : PadPalier ignorait le plafond de
// maxPadding que paddingFor applique, si bien qu'au-delà de 4 Gio de
// remplissage l'écran promettait un palier que le fichier n'atteignait jamais.

// TestPadPalierSuitLeRemplissageReel : sur toute la plage, y compris au-delà du
// plafond, la taille annoncée est exactement celle qui sort.
func TestPadPalierSuitLeRemplissageReel(t *testing.T) {
	tailles := []int64{
		0, 1, 1023, 1 << 20, 7_500_000, 1 << 30,
		4 << 30,   // le plafond commence à mordre en profil maximum
		8<<30 + 1, // 8 Gio + 1 octet : le cas qui annonçait 16 Gio et sortait à 12
		34 << 30,  // là où le plafond mord jusqu'en profil standard
		64 << 30,
	}
	for _, profil := range []PadProfile{PadStandard, PadFort, PadMaximum} {
		for _, taille := range tailles {
			attendu := taille + padHeaderSize + paddingFor(taille, profil)
			if got := PadPalier(taille, profil); got != attendu {
				t.Errorf("PadPalier(%d, %q) = %d, mais le chiffrement produit %d",
					taille, profil, got, attendu)
			}
		}
	}
}

// TestPadFenetreNePrometPasCeQuElleNeTientPas : la fenêtre annoncée est la
// promesse de confidentialité — « tout ce qui pèse de X à Y sort identique ».
// Chacune de ses deux bornes doit réellement sortir à la même taille.
func TestPadFenetreNePrometPasCeQuElleNeTientPas(t *testing.T) {
	tailles := []int64{1, 1 << 20, 7_500_000, 1 << 30, 8<<30 + 1, 34 << 30, 64 << 30}
	for _, profil := range []PadProfile{PadStandard, PadFort, PadMaximum} {
		for _, taille := range tailles {
			bas, haut := PadFenetre(taille, profil)
			if bas > taille || haut < taille {
				t.Errorf("PadFenetre(%d, %q) = (%d, %d) : le fichier n'est pas dans sa propre fenêtre",
					taille, profil, bas, haut)
			}
			cible := PadPalier(taille, profil)
			if got := PadPalier(bas, profil); got != cible {
				t.Errorf("profil %q, taille %d : la borne basse %d sort à %d, pas à %d",
					profil, taille, bas, got, cible)
			}
			if got := PadPalier(haut, profil); got != cible {
				t.Errorf("profil %q, taille %d : la borne haute %d sort à %d, pas à %d",
					profil, taille, haut, got, cible)
			}
		}
	}
}

// TestPadFenetreDegenereAuPlafond : au-delà du plafond, plus aucun fichier n'en
// confond un autre. La fenêtre doit se réduire au fichier lui-même plutôt que
// d'annoncer une protection qui n'existe plus.
func TestPadFenetreDegenereAuPlafond(t *testing.T) {
	const taille = 8<<30 + 1 // 8 Gio + 1 octet, profil maximum : plafond atteint
	if paddingFor(taille, PadMaximum) != maxPadding {
		t.Fatalf("le cas de test ne touche plus le plafond : %d", paddingFor(taille, PadMaximum))
	}
	bas, haut := PadFenetre(taille, PadMaximum)
	if bas != taille || haut != taille {
		t.Errorf("PadFenetre = (%d, %d), attendu (%d, %d) : une fenêtre plus large serait une promesse fausse",
			bas, haut, taille, taille)
	}
}
