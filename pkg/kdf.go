package pkg

import "fmt"

// Profils de dérivation de clé.
//
// Les paramètres Argon2 sont inscrits dans l'en-tête depuis le format v2, donc
// ajustables sans casser les fichiers existants. Ces profils les exposent sous
// des noms plutôt que sous des chiffres à retenir.
//
// Le nom « parano » est volontairement évité : le drapeau -parano désigne déjà
// le double chiffrement en cascade. Deux sens différents pour un même mot dans
// la même ligne de commande auraient été un piège.
type KDFProfile string

const (
	KDFStandard KDFProfile = "standard"
	KDFFort     KDFProfile = "fort"
	KDFMaximum  KDFProfile = "maximum"
)

// Paramètres de chaque profil, mesurés sur une machine de bureau récente.
//
// Le plafond de lecture est de 2 GiB (voir maxArgonMemory) : les profils
// doivent rester dessous, sinon un fichier produit ici serait refusé par son
// propre déchiffrement.
//
// Le déchiffrement exige la même mémoire que le chiffrement. Un fichier scellé
// en « maximum » sur une machine à 32 Gio sera indéchiffrable sur un appareil
// qui n'a pas 1 Gio à consacrer à la dérivation. C'est le compromis à
// annoncer, et la commande benchmark est là pour le mesurer avant de choisir.
func (p KDFProfile) argonParams() argonParams {
	switch p {
	case KDFFort:
		// ~400 ms : pour des données sensibles ou un mot de passe moyen.
		return argonParams{Time: 4, Memory: 512 * 1024, Threads: defaultArgonThreads}
	case KDFMaximum:
		// ~1,2 s : secret durable face à un attaquant motivé.
		return argonParams{Time: 4, Memory: 1024 * 1024, Threads: defaultArgonThreads}
	default:
		// ~144 ms : le défaut, imperceptible à la saisie.
		return defaultArgonParams()
	}
}

// AllKDFProfiles liste les profils dans l'ordre croissant de coût.
func AllKDFProfiles() []KDFProfile {
	return []KDFProfile{KDFStandard, KDFFort, KDFMaximum}
}

func ParseKDFProfile(s string) (KDFProfile, error) {
	switch KDFProfile(s) {
	case "", KDFStandard:
		return KDFStandard, nil
	case KDFFort:
		return KDFFort, nil
	case KDFMaximum:
		return KDFMaximum, nil
	default:
		return "", fmt.Errorf("profil KDF inconnu %q (attendu standard, fort ou maximum)", s)
	}
}

// KDFLabel décrit un profil pour l'interface, paramètres réels compris.
func (p KDFProfile) KDFLabel() string {
	return "argon2id  " + p.argonParams().String()
}

// MemoryMiB est la mémoire exigée par le profil, en Mio — à afficher pour que
// l'utilisateur sache ce qu'il faudra pour déchiffrer.
func (p KDFProfile) MemoryMiB() uint32 { return p.argonParams().Memory / 1024 }
