package pkg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
)

// Masquage de la taille réelle.
//
// Un .chto révèle la taille du clair à quelques octets près. Sur un ensemble de
// documents connus, ça suffit parfois à identifier lequel a été chiffré. Le seul
// remède est d'ajouter du remplissage et de l'assumer.
//
// Où le mettre. Pas après le flux scellé : sio ne s'arrête pas à son dernier
// paquet et lirait les octets suivants comme un en-tête de paquet (« invalid
// payload size »). Le remplissage vit donc *à l'intérieur* du chiffrement, en
// tête de la charge utile :
//
//	[padLen uint32 big-endian][padLen octets aléatoires][charge utile]
//
// En tête et non en queue, parce que la longueur doit être écrite avant les
// données quand on ne peut pas revenir en arrière — c'est tout l'intérêt d'un
// format en streaming. À la lecture, on lit quatre octets, on saute padLen, et
// le reste est la charge utile.
//
// Pourquoi il exclut la compression. La garantie voulue est « la taille du
// fichier ne dit rien de plus que le palier ». Avec la compression, la taille
// observée dépend de la compressibilité du contenu, que le remplissage ne cache
// pas : les deux options combinées se contredisent, donc elles s'excluent.

// padHeaderSize est la taille du champ de longueur.
const padHeaderSize = 4

// maxPadding borne le remplissage qu'on accepte de *produire* comme de *lire* :
// sans cette borne, un fichier hostile annonçant 4 Gio de remplissage ferait
// tourner le déchiffrement dans le vide.
const maxPadding = int64(math.MaxUint32)

// PadProfile règle la grossièreté du remplissage.
//
// Le paramètre est unique : le nombre de chiffres binaires significatifs que
// Padmé conserve. En retirer un double la largeur du palier, donc le nombre de
// fichiers qui sortent à la même taille — et double le surcoût maximal. C'est
// le seul arbitrage qui vaille ici, et il n'a pas de bonne réponse universelle :
// masquer un document de traitement de texte et masquer un film ne coûtent pas
// le même prix.
//
// Rien de tout cela ne s'écrit dans le fichier. Le déchiffrement lit la
// longueur du remplissage dans la charge utile ; le profil ne concerne que
// l'écriture, et un ancien fichier se relit sans rien savoir de ces niveaux.
type PadProfile string

const (
	// PadStandard : Padmé tel que publié. Palier d'environ 3 % de la taille au
	// delà du mégaoctet, surcoût plafonné à ~12 %.
	PadStandard PadProfile = "standard"
	// PadFort : un chiffre significatif de moins. Palier deux fois plus large,
	// surcoût plafonné à ~25 %.
	PadFort PadProfile = "fort"
	// PadMaximum : arrondi à la puissance de deux supérieure. Tous les fichiers
	// d'une octave sortent à la même taille — de 4 à 8 Mio, une seule valeur —
	// au prix d'un fichier qui peut doubler.
	PadMaximum PadProfile = "maximum"
)

// AllPadProfiles liste les profils dans l'ordre croissant de masquage.
func AllPadProfiles() []PadProfile {
	return []PadProfile{PadStandard, PadFort, PadMaximum}
}

func ParsePadProfile(s string) (PadProfile, error) {
	switch PadProfile(s) {
	case "", PadStandard:
		return PadStandard, nil
	case PadFort:
		return PadFort, nil
	case PadMaximum:
		return PadMaximum, nil
	default:
		return "", fmt.Errorf("niveau de remplissage inconnu %q (attendu standard, fort ou maximum)", s)
	}
}

// padme arrondit une taille à un palier, selon le schéma Padmé.
//
// Padmé (« Reducing Metadata Leakage from Encrypted Files and Communication
// with PURBs », 2019) est un compromis entre l'arrondi à la puissance de deux —
// jusqu'à 100 % de disque perdu — et l'absence d'arrondi. Il ne garde qu'une
// poignée de chiffres binaires significatifs et met le reste à zéro.
//
// Ce que ça donne en « standard », concrètement : deux fichiers dont les
// tailles diffèrent de moins de quelques pour cent deviennent indistinguables,
// et le surcoût reste plafonné à ~12 % — atteint sur les petites tailles,
// négligeable au-delà. Ce n'est pas un arrondi grossier au mégaoctet : la taille
// reste connue à quelques pour cent près, ce qui suffit à noyer un document
// parmi ses voisins, pas à cacher l'ordre de grandeur. Les profils plus élevés
// élargissent le palier, et c'est tout ce qui les distingue.
//
// Le palier reste proportionnel à la taille à tous les niveaux, y compris en
// « maximum ». Un pas fixe — arrondir tout le monde au multiple de 10 Mo
// supérieur — ferait l'inverse : il gonflerait un fichier de 3 Ko d'un facteur
// mille, et ne masquerait plus rien à 1,4 Go, où 10 Mo ne sont plus que 0,7 %.
func padme(size int64, profile PadProfile) int64 {
	if size <= 0 {
		return 0
	}
	// e : exposant de la taille, soit floor(log2(size)).
	// s : nombre de chiffres significatifs conservés, soit floor(log2(e)) + 1,
	// duquel le profil retranche.
	e := bits.Len64(uint64(size)) - 1
	if e < 3 {
		return size
	}
	s := chiffresSignificatifs(e, profile)
	lastBits := e - s
	if lastBits <= 0 {
		return size
	}
	mask := int64(1)<<lastBits - 1
	return (size + mask) & ^mask
}

// chiffresSignificatifs dit combien de chiffres binaires le profil conserve.
//
// « fort » n'en retire un qu'au-delà de deux : en dessous, il tomberait sur
// l'arrondi à la puissance de deux, qui est déjà le profil « maximum » — deux
// noms pour le même comportement induiraient en erreur sur le coût.
func chiffresSignificatifs(e int, profile PadProfile) int {
	s := bits.Len64(uint64(e))
	switch profile {
	case PadFort:
		return max(s-1, 2)
	case PadMaximum:
		return 0
	default:
		return s
	}
}

// PadPalier donne la taille à laquelle sortirait une charge utile de size
// octets, remplissage compris. L'interface s'en sert pour montrer le coût réel
// sur le fichier qu'on est en train de chiffrer, plutôt qu'un pourcentage
// abstrait. La taille du .chto y ajoute encore l'en-tête et les tampons des
// paquets scellés : c'est un ordre de grandeur, pas une promesse à l'octet.
func PadPalier(size int64, profile PadProfile) int64 {
	total := size + padHeaderSize
	return padme(total, profile)
}

// PadFenetre donne l'intervalle de tailles de clair qui sortent exactement à la
// même taille que size. C'est la seule mesure qui dise quelque chose de la
// protection obtenue : un palier n'est utile que par le nombre de fichiers
// qu'il confond, pas par sa largeur en octets.
//
// La borne basse se cherche par dichotomie plutôt que par soustraction du pas :
// à cheval sur une puissance de deux, le palier précédent est deux fois plus
// serré, et le calcul direct se tromperait.
func PadFenetre(size int64, profile PadProfile) (bas, haut int64) {
	total := PadPalier(size, profile)
	if total <= padHeaderSize {
		return 0, 0
	}
	lo, hi := int64(1), total
	for lo < hi {
		mid := lo + (hi-lo)/2
		if padme(mid, profile) >= total {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	bas = lo - padHeaderSize
	if bas < 0 {
		bas = 0
	}
	return bas, total - padHeaderSize
}

// paddingFor renvoie le nombre d'octets de remplissage à insérer pour qu'une
// charge utile de payloadSize octets atteigne le palier supérieur du profil,
// en-tête de remplissage compris.
func paddingFor(payloadSize int64, profile PadProfile) int64 {
	total := payloadSize + padHeaderSize
	pad := padme(total, profile) - total
	if pad < 0 {
		return 0
	}
	if pad > maxPadding {
		return maxPadding
	}
	return pad
}

// writePadding écrit l'en-tête de remplissage puis les octets aléatoires.
//
// Le remplissage est tiré au hasard et non mis à zéro : il est chiffré comme le
// reste, donc indistinguable de la charge utile pour qui n'a pas la clé, mais
// des zéros seraient triviaux à repérer si un jour le clair fuitait par ailleurs.
func writePadding(w io.Writer, pad int64) error {
	if pad < 0 || pad > maxPadding {
		return fmt.Errorf("remplissage hors bornes : %d octets", pad)
	}
	var hdr [padHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(pad))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("écriture de l'en-tête de remplissage: %w", err)
	}
	if pad == 0 {
		return nil
	}
	if _, err := io.CopyN(w, rand.Reader, pad); err != nil {
		return fmt.Errorf("écriture du remplissage: %w", err)
	}
	return nil
}

// skipPadding consomme l'en-tête de remplissage et les octets qui le suivent,
// de sorte que le lecteur renvoyé commence sur la charge utile.
func skipPadding(r io.Reader) error {
	var hdr [padHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("lecture de l'en-tête de remplissage: %w", err)
	}
	pad := int64(binary.BigEndian.Uint32(hdr[:]))
	if pad == 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, r, pad); err != nil {
		return fmt.Errorf("lecture du remplissage: %w", err)
	}
	return nil
}
