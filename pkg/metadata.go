package pkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// Métadonnées du fichier d'origine.
//
// Sans elles, `secret-medical.pdf.chto` annonce son contenu et il n'existe
// aucun moyen de restituer le nom si on chiffre vers une sortie neutre. Le nom
// et la date vivent donc *à l'intérieur* du chiffrement, en tête de la charge
// utile, exactement comme le remplissage :
//
//	[padLen][remplissage]?[bloc métadonnées]?[contenu]
//
// Le bloc est couvert par l'AEAD, donc authentifié : il n'est pas falsifiable
// sans faire échouer le déchiffrement.
//
// Les dossiers n'en ont pas besoin — leur charge utile est un tar, qui porte
// déjà noms, dates et permissions de chaque entrée.
type MetadataMode string

const (
	// MetadataNone : rien n'est écrit. C'est le défaut, le comportement
	// historique — le nom de sortie est déduit de celui du fichier chiffré.
	MetadataNone MetadataMode = "none"
	// MetadataMinimal : nom d'origine et date de modification arrondie.
	MetadataMinimal MetadataMode = "minimal"
)

func ParseMetadataMode(s string) (MetadataMode, error) {
	switch MetadataMode(s) {
	case "", MetadataNone:
		return MetadataNone, nil
	case MetadataMinimal:
		return MetadataMinimal, nil
	default:
		return "", fmt.Errorf("mode de métadonnées inconnu %q (attendu none ou minimal)", s)
	}
}

const (
	metaMagic = "CHTMETA1"
	// maxMetaName borne ce qu'on accepte de lire : sans plafond, un fichier
	// hostile annonçant un nom de 4 Gio ferait allouer d'autant.
	maxMetaName = 1024
	// metaPrefixSize : magic + longueur du nom (uint16) + date (int64).
	metaPrefixSize = len(metaMagic) + 2 + 8
	// metaTimeGrain : granularité de la date conservée. Une date à la seconde
	// corrèle un fichier chiffré avec des journaux système ou d'autres fichiers ;
	// arrondir à l'heure garde l'information utile — « ce document date de mardi
	// après-midi » — en cassant cette corrélation fine.
	metaTimeGrain = time.Hour
)

// FileMetadata est ce qu'on restitue au déchiffrement.
type FileMetadata struct {
	Name    string
	ModTime time.Time
}

func newFileMetadata(path string, modTime time.Time) *FileMetadata {
	return &FileMetadata{
		Name:    filepath.Base(path),
		ModTime: modTime.UTC().Truncate(metaTimeGrain),
	}
}

// marshalMetadata sérialise le bloc. La longueur précède le nom : on ne revient
// pas en arrière dans un flux.
func marshalMetadata(m *FileMetadata) ([]byte, error) {
	name := []byte(m.Name)
	if len(name) == 0 {
		return nil, errors.New("métadonnées : nom de fichier vide")
	}
	if len(name) > maxMetaName {
		return nil, fmt.Errorf("métadonnées : nom de %d octets, maximum %d", len(name), maxMetaName)
	}
	buf := make([]byte, 0, metaPrefixSize+len(name))
	buf = append(buf, metaMagic...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(name)))
	buf = binary.BigEndian.AppendUint64(buf, uint64(m.ModTime.Unix()))
	return append(buf, name...), nil
}

// readMetadata relit le bloc et assainit le nom.
//
// Le nom vient d'un fichier qu'on n'a pas produit : même authentifié, il a été
// écrit par quelqu'un d'autre. On en retire donc tout élément de chemin, sans
// quoi un nom comme « ../../.ssh/authorized_keys » ferait écrire hors du
// répertoire visé le jour où l'appelant s'en sert pour nommer sa sortie.
func readMetadata(r io.Reader) (*FileMetadata, error) {
	prefix := make([]byte, metaPrefixSize)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("lecture des métadonnées: %w", err)
	}
	if string(prefix[:len(metaMagic)]) != metaMagic {
		return nil, errors.New("métadonnées absentes ou corrompues")
	}
	nameLen := binary.BigEndian.Uint16(prefix[len(metaMagic) : len(metaMagic)+2])
	if nameLen == 0 || int(nameLen) > maxMetaName {
		return nil, fmt.Errorf("métadonnées : longueur de nom invalide (%d)", nameLen)
	}
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, fmt.Errorf("lecture du nom d'origine: %w", err)
	}

	clean, err := sanitizeMetaName(string(name))
	if err != nil {
		return nil, err
	}
	return &FileMetadata{
		Name:    clean,
		ModTime: time.Unix(int64(binary.BigEndian.Uint64(prefix[len(metaMagic)+2:])), 0).UTC(),
	}, nil
}

// sanitizeMetaName réduit un nom stocké à un nom de fichier sûr.
func sanitizeMetaName(name string) (string, error) {
	// Les séparateurs Windows aussi : un fichier produit là-bas, ou forgé pour
	// l'occasion, peut en contenir alors que filepath.Base ne les coupe pas sur
	// un système Unix.
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(filepath.Clean("/" + name))
	switch name {
	case "", ".", "..", "/":
		return "", errors.New("métadonnées : nom d'origine inutilisable")
	}
	return name, nil
}
