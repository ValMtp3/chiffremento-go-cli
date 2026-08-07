package pkg

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

type MetadataMode string

const (
	MetadataNone    MetadataMode = "none"
	MetadataMinimal MetadataMode = "minimal"
)

const (
	metadataMagic     = "CHTMETA1"
	metadataPrefixLen = len(metadataMagic) + 2 + 8
	maxMetadataName   = 1024
)

type fileMetadata struct {
	Name       string
	ModTimeSec int64
}

func ParseMetadataMode(s string) (MetadataMode, error) {
	switch MetadataMode(s) {
	case "", MetadataNone:
		return MetadataNone, nil
	case MetadataMinimal:
		return MetadataMinimal, nil
	default:
		return "", fmt.Errorf("mode metadata inconnu %q (attendu none ou minimal)", s)
	}
}

func metadataForInput(path string, modTime time.Time) *fileMetadata {
	return &fileMetadata{
		Name:       filepath.Base(path),
		ModTimeSec: modTime.UTC().Truncate(time.Minute).Unix(),
	}
}

func marshalMinimalMetadata(m *fileMetadata) ([]byte, error) {
	name := []byte(m.Name)
	if len(name) == 0 || len(name) > maxMetadataName {
		return nil, fmt.Errorf("nom de fichier metadata invalide : %d octets", len(name))
	}
	buf := make([]byte, 0, metadataPrefixLen+len(name))
	buf = append(buf, metadataMagic...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(name)))
	buf = binary.BigEndian.AppendUint64(buf, uint64(m.ModTimeSec))
	buf = append(buf, name...)
	return buf, nil
}

func unmarshalMinimalMetadata(r io.Reader) (*fileMetadata, error) {
	prefix := make([]byte, metadataPrefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("lecture des metadata: %w", err)
	}
	if string(prefix[:len(metadataMagic)]) != metadataMagic {
		return nil, fmt.Errorf("metadata absentes ou corrompues")
	}
	nameLen := binary.BigEndian.Uint16(prefix[len(metadataMagic) : len(metadataMagic)+2])
	if nameLen == 0 || nameLen > maxMetadataName {
		return nil, fmt.Errorf("taille de nom metadata invalide : %d", nameLen)
	}
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, fmt.Errorf("lecture du nom metadata: %w", err)
	}
	return &fileMetadata{
		Name:       string(name),
		ModTimeSec: int64(binary.BigEndian.Uint64(prefix[len(metadataMagic)+2:])),
	}, nil
}

