package scoring_test

import (
	"os"
	"testing"

	"chiffremento-cli/internal/zxcvbn/scoring"
)

// anneeReferenceAmont : année des tests amont (2019). zxcvbn compare les
// dates à l'année en cours ; sans ce réglage, ces tests cassent chaque janvier.
const anneeReferenceAmont = 2019

func TestMain(m *testing.M) {
	scoring.ReferenceYear = anneeReferenceAmont
	os.Exit(m.Run())
}
