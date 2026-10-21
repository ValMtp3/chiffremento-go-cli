package pkg

import "testing"

// TestFormatV4Fige fige la disposition binaire du format v4, octet par octet.
// Des fichiers .chto v4 existent déjà chez les utilisateurs : si une de ces
// valeurs bouge, ils deviennent illisibles ou, pire, mal interprétés.
//
// Ce test doit casser exprès quand on change la disposition de l'en-tête v4.
// Dans ce cas : ne pas simplement mettre les chiffres à jour. Il faut une
// nouvelle version de format avec son chemin de lecture pour l'ancienne. Le
// travail sur la v5 ajoutera son propre test figé, et celui-ci restera pour
// protéger la lecture des fichiers v4.
//
// Il complète TestProtocolSafety_Tripwire, dont la branche qui devait échouer
// sur un changement de structure ne peut plus se déclencher depuis la v4.
func TestFormatV4Fige(t *testing.T) {
	entiers := []struct {
		nom      string
		obtenu   int
		attendu  int
		commente string
	}{
		{"magicSize", magicSize, 8, "magic"},
		{"versionSize", versionSize, 1, "version"},
		{"flagsSize", flagsSize, 1, "drapeaux"},
		{"algoIDSize", algoIDSize, 1, "algorithme"},
		{"argonParamsSize", argonParamsSize, 9, "temps 4 + mémoire 4 + parallélisme 1"},
		{"compAlgoSize", compAlgoSize, 1, "algorithme de compression"},
		{"saltSize", saltSize, 16, "sel"},
		{"commitSize", commitSize, 32, "engagement sur la clé"},
		{"wrappedSize", wrappedSize, 48, "clé du fichier scellée (32 + tag 16)"},
		{"headerSizeV1", headerSizeV1, 27, "en-tête v1"},
		{"headerSizeV2", headerSizeV2, 36, "en-tête v2"},
		{"headerSizeV3", headerSizeV3, 37, "en-tête v3"},
		{"headerSizeV4", headerSizeV4, 117, "en-tête v4"},
	}
	for _, c := range entiers {
		if c.obtenu != c.attendu {
			t.Fatalf("%s (%s) = %d, figé à %d : la disposition du format v4 a changé", c.nom, c.commente, c.obtenu, c.attendu)
		}
	}

	octets := []struct {
		nom     string
		obtenu  byte
		attendu byte
	}{
		{"versionV1", versionV1, 1},
		{"versionV2", versionV2, 2},
		{"versionV3", versionV3, 3},
		{"versionV4", versionV4, 4},
		{"currentVersion", currentVersion, 4},
		{"FlagCompressed", FlagCompressed, 1 << 0},
		{"FlagArchive", FlagArchive, 1 << 1},
		{"FlagPadded", FlagPadded, 1 << 2},
		{"FlagMetadata", FlagMetadata, 1 << 3},
		{"knownFlags", knownFlags, 0x0f},
		{"AlgoAES", AlgoAES, 1},
		{"AlgoChaCha", AlgoChaCha, 2},
		{"AlgoCascade", AlgoCascade, 3},
		{"CompNone", CompNone, 0},
		{"CompGzip", CompGzip, 1},
		{"CompZstd", CompZstd, 2},
	}
	for _, c := range octets {
		if c.obtenu != c.attendu {
			t.Fatalf("%s = %d, figé à %d : la disposition du format v4 a changé", c.nom, c.obtenu, c.attendu)
		}
	}

	if magicNumber != "CHFRMT03" {
		t.Fatalf("magicNumber = %q, figé à %q : la disposition du format v4 a changé", magicNumber, "CHFRMT03")
	}
}
