package pkg

import "fmt"

type KDFProfile string

const (
	KDFStandard KDFProfile = "standard"
	KDFFort     KDFProfile = "fort"
	KDFParano   KDFProfile = "parano"
)

func ParseKDFProfile(s string) (KDFProfile, error) {
	switch KDFProfile(s) {
	case "", KDFStandard:
		return KDFStandard, nil
	case KDFFort:
		return KDFFort, nil
	case KDFParano:
		return KDFParano, nil
	default:
		return "", fmt.Errorf("profil KDF inconnu %q (attendu standard, fort ou parano)", s)
	}
}

func (p KDFProfile) argonParams() argonParams {
	switch p {
	case KDFFort:
		return argonParams{Time: 4, Memory: 384 * 1024, Threads: defaultArgonThreads}
	case KDFParano:
		return argonParams{Time: 5, Memory: 512 * 1024, Threads: defaultArgonThreads}
	default:
		return defaultArgonParams()
	}
}

func KDFLabelForProfile(p KDFProfile) string {
	return "argon2id  " + p.argonParams().String()
}

