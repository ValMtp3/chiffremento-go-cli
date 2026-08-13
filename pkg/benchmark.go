package pkg

import (
	"crypto/rand"
	"fmt"
	"io"
	"runtime"
	"time"
)

// Mesure des coûts sur la machine hôte.
//
// Deux questions auxquelles on ne peut pas répondre depuis le code : combien
// coûte chaque profil KDF ici, et lequel d'AES ou de ChaCha est le plus rapide.
// La seconde n'est pas rhétorique — sans accélération AES matérielle, ChaCha20
// est nettement devant, et ça ne se devine pas.

// KDFMeasure est le coût d'un profil sur cette machine.
type KDFMeasure struct {
	Profile   KDFProfile
	Label     string
	MemoryMiB uint32
	Duration  time.Duration
}

// AEADMeasure est le débit d'un algorithme de chiffrement.
type AEADMeasure struct {
	Algo  byte
	Name  string
	Bytes int64
	// BytesPerSec vaut 0 si la mesure a échoué.
	BytesPerSec int64
	Err         error
}

// BenchmarkReport rassemble tout ce que la commande affiche.
type BenchmarkReport struct {
	CPUs     int
	KDF      []KDFMeasure
	AEAD     []AEADMeasure
	Advised  KDFProfile
	Advisory string
}

// benchTargetMax est la durée au-delà de laquelle un profil devient pénible à
// l'usage quotidien. Elle sert de plafond à la recommandation, pas de limite
// dure : rien n'empêche de choisir plus lourd en connaissance de cause.
const benchTargetMax = 1200 * time.Millisecond

// benchAdviseMaxMemMiB plafonne la mémoire d'un profil *recommandé*.
//
// Une machine de développement encaisse 1 Gio sans broncher, mais le fichier
// produit exigera autant pour être relu. Conseiller le maximum parce que la
// machine du jour le supporte fabrique des fichiers indéchiffrables ailleurs —
// sur un serveur contraint, un téléphone, un vieux portable. Le profil reste
// choisissable explicitement, il n'est simplement pas conseillé d'office.
const benchAdviseMaxMemMiB = uint32(512)

// benchPayload est la taille du bloc chiffré pour mesurer un débit. Assez grand
// pour amortir la mise en place du flux, assez petit pour rester instantané.
const benchPayload = 16 << 20 // 16 Mio

// Benchmark mesure les profils KDF puis le débit des algorithmes, et recommande
// un profil.
func Benchmark() BenchmarkReport {
	rep := BenchmarkReport{CPUs: runtime.NumCPU()}

	password := []byte("mesure-de-reference")
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		// Un sel non aléatoire ne fausse pas une mesure de durée.
		for i := range salt {
			salt[i] = byte(i)
		}
	}

	// La recommandation est le profil le plus lourd qui tient sous le plafond.
	// Si aucun n'y tient — machine lente, précisément le cas où ça compte — on
	// retombe sur le plus léger. Une version antérieure de ce code recommandait
	// alors le dernier profil mesuré, donc le plus lourd : exactement l'inverse.
	advised := KDFStandard
	var trouve bool

	for _, p := range AllKDFProfiles() {
		params := p.argonParams()
		start := time.Now()
		key, err := deriveKey(password, salt, params)
		d := time.Since(start)
		wipe(key)
		if err != nil {
			// Un profil hors bornes ne devrait pas exister, mais s'il apparaît on
			// ne le recommande pas et on continue.
			continue
		}
		rep.KDF = append(rep.KDF, KDFMeasure{
			Profile:   p,
			Label:     "argon2id  " + params.String(),
			MemoryMiB: params.Memory / 1024,
			Duration:  d,
		})
		if d <= benchTargetMax && params.Memory/1024 <= benchAdviseMaxMemMiB {
			advised = p
			trouve = true
		}
	}

	rep.Advised = advised
	switch {
	case !trouve:
		rep.Advisory = fmt.Sprintf("profil conseillé : %s — aucun profil ne tient sous %s sur cette machine",
			advised, benchTargetMax.Round(time.Millisecond))
	case advised == AllKDFProfiles()[len(AllKDFProfiles())-1]:
		rep.Advisory = fmt.Sprintf("profil conseillé : %s", advised)
	default:
		rep.Advisory = fmt.Sprintf(
			"profil conseillé : %s — les profils plus lourds tiennent peut-être ici, mais exigeraient "+
				"plus de %d Mio à chaque déchiffrement, y compris sur une machine moins bien dotée",
			advised, benchAdviseMaxMemMiB)
	}

	for _, algo := range []byte{AlgoAES, AlgoChaCha, AlgoCascade} {
		rep.AEAD = append(rep.AEAD, measureAEAD(algo))
	}
	return rep
}

// measureAEAD chiffre un bloc vers io.Discard et en déduit un débit.
func measureAEAD(algo byte) AEADMeasure {
	m := AEADMeasure{Algo: algo, Name: AlgoName(algo), Bytes: benchPayload}

	// Des clés fixes : on mesure le chiffrement, pas la dérivation. Elles ne
	// protègent rien, le ciphertext part dans io.Discard.
	keys := &keySet{
		Key:   make([]byte, 32),
		Inner: make([]byte, 32),
		Outer: make([]byte, 32),
	}
	for i := range keys.Key {
		keys.Key[i] = byte(i)
		keys.Inner[i] = byte(i + 1)
		keys.Outer[i] = byte(i + 2)
	}

	w, err := initCipherWriter(writerOnly{io.Discard}, algo, keys)
	if err != nil {
		m.Err = err
		return m
	}

	// Un bloc de zéros suffit : AES-GCM et ChaCha20 ne sont pas sensibles au
	// contenu, et tirer 16 Mio d'aléa coûterait plus cher que la mesure.
	bloc := make([]byte, 1<<20)
	start := time.Now()
	for reste := int64(benchPayload); reste > 0; {
		n := int64(len(bloc))
		if n > reste {
			n = reste
		}
		if _, err := w.Write(bloc[:n]); err != nil {
			m.Err = err
			w.Close()
			return m
		}
		reste -= n
	}
	if err := w.Close(); err != nil {
		m.Err = err
		return m
	}
	d := time.Since(start)

	if d > 0 {
		m.BytesPerSec = int64(float64(benchPayload) / d.Seconds())
	}
	return m
}
