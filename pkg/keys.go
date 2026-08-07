package pkg

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Étiquettes de domaine préfixant l'info HKDF. Elles garantissent que deux
// usages différents de la même clé maîtresse ne produisent jamais le même
// matériel.
const (
	infoKeyV2     = "chiffremento-v2-key"
	infoCascadeV2 = "chiffremento-v2-cascade"
	infoCascadeV1 = "chiffrement-cascade"
)

// keySet regroupe le matériel de chiffrement d'un fichier. Selon l'algorithme,
// soit Key est renseignée, soit la paire Inner/Outer.
type keySet struct {
	Key   []byte
	Inner []byte
	Outer []byte
}

// wipe efface les clés de la mémoire dès qu'elles ne servent plus.
func (k *keySet) wipe() {
	wipe(k.Key)
	wipe(k.Inner)
	wipe(k.Outer)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveKey applique Argon2id. Le sel doit être fourni : une version
// précédente en générait un aléatoirement quand il était vide, sans le
// renvoyer — la clé était alors irreproductible et le fichier perdu.
func deriveKey(password, salt []byte, p argonParams) ([]byte, error) {
	if len(salt) != saltSize {
		return nil, fmt.Errorf("sel invalide : %d octets (attendu %d)", len(salt), saltSize)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, argonKeyLen), nil
}

// deriveKeys produit le matériel de chiffrement correspondant à un en-tête,
// en aiguillant sur sa version.
func deriveKeys(password []byte, h *header) (*keySet, error) {
	if h.Version == versionV1 {
		return deriveKeysV1(password, h)
	}
	return deriveKeysV2(password, h)
}

// deriveKeysV2 : un seul Argon2id, puis HKDF-Expand pour obtenir les
// sous-clés.
//
// L'ordre compte. La v1 faisait l'inverse en mode cascade (HKDF gratuit sur le
// mot de passe, puis deux Argon2) : l'utilisateur payait deux dérivations
// coûteuses alors que l'attaquant, lui, n'en avait besoin que d'une seule pour
// attaquer la couche externe. Le mode « parano » était donc, à temps CPU égal,
// deux fois plus faible que le mode standard.
//
// L'en-tête complet entre dans l'info HKDF : modifier un seul de ses octets
// (version, flags, algo, paramètres Argon2, sel) change la clé, et le
// déchiffrement échoue sur l'authentification AEAD. L'en-tête est ainsi lié à
// la clé sans avoir besoin d'un champ d'authentification supplémentaire.
func deriveKeysV2(password []byte, h *header) (*keySet, error) {
	master, err := deriveKey(password, h.Salt, h.Argon)
	if err != nil {
		return nil, err
	}
	defer wipe(master)

	if h.Algo == AlgoCascade || h.Algo == AlgoCascadeReverse {
		out, err := hkdf.Expand(sha256.New, master, infoCascadeV2+string(h.Raw), 64)
		if err != nil {
			return nil, fmt.Errorf("dérivation des sous-clés: %w", err)
		}
		return &keySet{Inner: out[:32], Outer: out[32:]}, nil
	}

	key, err := hkdf.Expand(sha256.New, master, infoKeyV2+string(h.Raw), 32)
	if err != nil {
		return nil, fmt.Errorf("dérivation de la clé: %w", err)
	}
	return &keySet{Key: key}, nil
}

// deriveKeysV1 reproduit à l'identique la dérivation des fichiers .chto
// produits par les versions 1.x. Conservée uniquement pour la relecture :
// ne pas s'en inspirer pour du code neuf.
func deriveKeysV1(password []byte, h *header) (*keySet, error) {
	if h.Algo != AlgoCascade {
		key, err := deriveKey(password, h.Salt, h.Argon)
		if err != nil {
			return nil, err
		}
		return &keySet{Key: key}, nil
	}

	// v1 : HKDF sur le mot de passe brut, puis un Argon2 par sous-mot-de-passe.
	sub, err := hkdf.Key(sha256.New, password, nil, infoCascadeV1, 64)
	if err != nil {
		return nil, fmt.Errorf("dérivation des sous-mots-de-passe (v1): %w", err)
	}
	defer wipe(sub)

	inner, err := deriveKey(sub[:32], h.Salt, h.Argon)
	if err != nil {
		return nil, fmt.Errorf("clé interne (v1): %w", err)
	}
	outer, err := deriveKey(sub[32:], h.Salt, h.Argon)
	if err != nil {
		wipe(inner)
		return nil, fmt.Errorf("clé externe (v1): %w", err)
	}
	return &keySet{Inner: inner, Outer: outer}, nil
}
