package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
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

	// v4 : la clé maîtresse ne chiffre plus rien directement. Elle sert à
	// produire l'engagement et à sceller la clé de fichier, chacun avec sa
	// propre étiquette.
	infoCommitV4  = "chiffremento-v4-commit"
	infoWrapV4    = "chiffremento-v4-wrap"
	infoKeyV4     = "chiffremento-v4-key"
	infoCascadeV4 = "chiffremento-v4-cascade"
)

// wrapNonceSize est la taille du nonce d'AES-GCM. Il n'est pas stocké : il se
// dérive de la clé maîtresse, donc du couple (mot de passe, sel). Un nonce
// constant dans le code aurait invité à le réutiliser sous une même clé le jour
// où quelqu'un aurait réemployé un sel ; dérivé, il change avec lui.
const wrapNonceSize = 12

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
	switch {
	case h.Version == versionV1:
		return deriveKeysV1(password, h)
	case h.Version >= versionV4:
		return deriveKeysV4(password, h)
	default:
		return deriveKeysV2(password, h)
	}
}

// ErrBadPassword est rendue quand l'engagement de l'en-tête ne correspond pas à
// la clé dérivée. Avant la v4, un mauvais mot de passe se manifestait par un
// « sio: authentication failed » quelque part au milieu du déchiffrement :
// exact, mais illisible, et découvert seulement après avoir lu le fichier.
var ErrBadPassword = errors.New("mot de passe incorrect")

// masterV4 regroupe ce que la clé maîtresse produit en v4 : l'engagement qu'on
// compare à l'en-tête, et de quoi ouvrir l'enveloppe.
type masterV4 struct {
	commit []byte
	kek    []byte
	nonce  []byte
}

func (m *masterV4) wipe() {
	wipe(m.commit)
	wipe(m.kek)
	wipe(m.nonce)
}

// deriveMasterV4 applique Argon2id puis sépare le résultat en trois usages
// distincts, chacun sous son étiquette : deux emplois de la même clé ne doivent
// jamais produire le même matériel.
func deriveMasterV4(password []byte, h *header) (*masterV4, error) {
	master, err := deriveKey(password, h.Salt, h.Argon)
	if err != nil {
		return nil, err
	}
	defer wipe(master)

	commit, err := hkdf.Expand(sha256.New, master, infoCommitV4, commitSize)
	if err != nil {
		return nil, fmt.Errorf("dérivation de l'engagement: %w", err)
	}
	// La clé d'enveloppe et son nonce sortent du même tirage : ils vont
	// toujours ensemble, et les séparer n'apporterait qu'un appel de plus.
	wrap, err := hkdf.Expand(sha256.New, master, infoWrapV4, 32+wrapNonceSize)
	if err != nil {
		return nil, fmt.Errorf("dérivation de la clé d'enveloppe: %w", err)
	}
	return &masterV4{commit: commit, kek: wrap[:32], nonce: wrap[32:]}, nil
}

// deriveKeysV4 vérifie l'engagement, ouvre l'enveloppe, puis dérive les clés du
// contenu de la clé de fichier qu'elle contient.
//
// L'ordre est le point de tout le chantier : l'engagement est comparé **avant**
// de toucher à quoi que ce soit d'autre. Une clé qui ne correspond pas est
// rejetée là, en temps constant, et il devient impossible de fabriquer un
// chiffré qui s'ouvrirait validement sous deux clés différentes — c'est ce que
// les attaques par oracle de partitionnement exploitent.
func deriveKeysV4(password []byte, h *header) (*keySet, error) {
	if len(h.Commit) != commitSize || len(h.Wrapped) != wrappedSize {
		return nil, fmt.Errorf("en-tête v4 incomplet : engagement de %d octets, enveloppe de %d",
			len(h.Commit), len(h.Wrapped))
	}

	m, err := deriveMasterV4(password, h)
	if err != nil {
		return nil, err
	}
	defer m.wipe()

	if !constantTimeEqual(m.commit, h.Commit) {
		return nil, ErrBadPassword
	}

	dek, err := unwrapDEK(m, h)
	if err != nil {
		return nil, err
	}
	defer wipe(dek)

	return keysFromDEK(dek, h.Algo)
}

// constantTimeEqual compare deux engagements sans laisser fuiter, par le temps
// de réponse, jusqu'où ils coïncident.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// keysFromDEK tire les clés du contenu de la clé de fichier.
//
// L'en-tête n'entre pas dans le calcul, contrairement à la v2 : c'est ce qui
// permet de changer le mot de passe sans re-chiffrer. Il reste authentifié, mais
// par les données associées de l'enveloppe (voir marshalScelle).
func keysFromDEK(dek []byte, algo byte) (*keySet, error) {
	if algo == AlgoCascade {
		out, err := hkdf.Expand(sha256.New, dek, infoCascadeV4, 64)
		if err != nil {
			return nil, fmt.Errorf("dérivation des sous-clés: %w", err)
		}
		return &keySet{Inner: out[:32], Outer: out[32:]}, nil
	}
	key, err := hkdf.Expand(sha256.New, dek, infoKeyV4, 32)
	if err != nil {
		return nil, fmt.Errorf("dérivation de la clé: %w", err)
	}
	return &keySet{Key: key}, nil
}

// newDEK tire la clé de fichier. Elle est aléatoire et ne quitte jamais
// l'enveloppe : le mot de passe ne la détermine pas, il l'ouvre.
func newDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("génération de la clé de fichier: %w", err)
	}
	return dek, nil
}

// wrapDEK scelle la clé de fichier avec la clé dérivée du mot de passe, en
// authentifiant au passage tout l'en-tête qui précède.
func wrapDEK(m *masterV4, h *header, dek []byte) ([]byte, error) {
	gcm, err := gcmDe(m.kek)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, m.nonce, dek, h.marshalScelle()), nil
}

// unwrapDEK fait l'inverse. Un échec ici après un engagement validé ne peut
// venir que d'un en-tête modifié : la clé est la bonne, mais les données
// authentifiées ne correspondent plus.
func unwrapDEK(m *masterV4, h *header) ([]byte, error) {
	gcm, err := gcmDe(m.kek)
	if err != nil {
		return nil, err
	}
	dek, err := gcm.Open(nil, m.nonce, h.Wrapped, h.marshalScelle())
	if err != nil {
		return nil, errors.New("en-tête altéré : la clé de fichier ne s'ouvre pas")
	}
	return dek, nil
}

func gcmDe(kek []byte) (cipher.AEAD, error) {
	bloc, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("clé d'enveloppe invalide: %w", err)
	}
	gcm, err := cipher.NewGCM(bloc)
	if err != nil {
		return nil, fmt.Errorf("mode GCM indisponible: %w", err)
	}
	return gcm, nil
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

	if h.Algo == AlgoCascade {
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
