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

// padme arrondit une taille à un palier, selon le schéma Padmé.
//
// Padmé (« Reducing Metadata Leakage from Encrypted Files and Communication
// with PURBs », 2019) est un compromis entre l'arrondi à la puissance de deux —
// jusqu'à 100 % de disque perdu — et l'absence d'arrondi. Il ne garde qu'une
// poignée de chiffres binaires significatifs et met le reste à zéro.
//
// Ce que ça donne, concrètement : deux fichiers dont les tailles diffèrent de
// moins de quelques pour cent deviennent indistinguables, et le surcoût reste
// plafonné à ~12 % — atteint sur les petites tailles, négligeable au-delà. Ce
// n'est pas un arrondi grossier au mégaoctet : la taille reste connue à
// quelques pour cent près, ce qui suffit à noyer un document parmi ses voisins,
// pas à cacher l'ordre de grandeur.
func padme(size int64) int64 {
	if size <= 0 {
		return 0
	}
	// e : exposant de la taille, soit floor(log2(size)).
	// s : nombre de chiffres significatifs conservés, soit floor(log2(e)) + 1.
	e := bits.Len64(uint64(size)) - 1
	if e < 3 {
		return size
	}
	s := bits.Len64(uint64(e))
	lastBits := e - s
	if lastBits <= 0 {
		return size
	}
	mask := int64(1)<<lastBits - 1
	return (size + mask) & ^mask
}

// paddingFor renvoie le nombre d'octets de remplissage à insérer pour qu'une
// charge utile de payloadSize octets atteigne le palier Padmé supérieur,
// en-tête de remplissage compris.
func paddingFor(payloadSize int64) int64 {
	total := payloadSize + padHeaderSize
	pad := padme(total) - total
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
