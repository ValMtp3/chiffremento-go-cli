package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Brouillage du nom et de la date du fichier chiffré.
//
// Chiffrer `rapport-medical.pdf` en `rapport-medical.pdf.chto` annonce le
// contenu à qui liste le dossier, et la date du fichier dit quand il a été
// scellé. Les deux fuient à côté du chiffrement, pas à travers.
//
// Ça ne devient possible qu'avec le nom et la date conservés *à l'intérieur* du
// chiffré : sans eux, un nom tiré au hasard serait une perte sèche — plus
// personne ne saurait ce que contient `7f3a9c21.chto`. L'interface ne propose
// donc le brouillage qu'une fois les métadonnées gardées, et le déchiffrement
// rend son nom au fichier (voir restituerNom).

// dateNeutre est la date posée sur le fichier chiffré : le 1er janvier 2000, en
// UTC pour ne pas dépendre du fuseau de la machine.
//
// Une date fixe plutôt qu'une date tirée au hasard : elle ne raconte rien et ne
// dirige personne vers une fausse piste. Elle annonce en revanche clairement
// qu'une date a été effacée — un hasard plausible le cacherait mieux, mais
// mentirait sur la vie du fichier, et un lot entier de dates incohérentes se
// repère de toute façon.
var dateNeutre = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// tiragesNomBrouille borne la recherche d'un nom libre. Une collision sur 8
// octets aléatoires ne se produira jamais ; la boucle existe pour le cas où le
// dossier serait, lui, impossible à lire.
const tiragesNomBrouille = 8

// nomBrouille tire pour le chiffré un nom sans rapport avec sa source, dans le
// dossier de celle-ci.
//
// L'aléa est cryptographique, comme partout ailleurs dans le projet : un nom
// prédictible à partir de l'heure ou du nom d'origine rendrait le brouillage
// décoratif.
func nomBrouille(source string) (string, error) {
	dir := filepath.Dir(source)
	for range tiragesNomBrouille {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("tirage du nom de sortie: %w", err)
		}
		candidat := filepath.Join(dir, hex.EncodeToString(buf)+extension)
		_, err := os.Lstat(candidat)
		if errors.Is(err, fs.ErrNotExist) {
			return candidat, nil
		}
		if err != nil {
			// Ni un fichier, ni une absence franche : insister ne servirait
			// qu'à retomber sur la même erreur au tirage suivant.
			return "", fmt.Errorf("vérification de %s: %w", candidat, err)
		}
	}
	return "", errors.New("aucun nom libre trouvé pour le fichier chiffré")
}

// brouillerDate pose la date neutre sur le fichier chiffré.
//
// La portée est celle du système de fichiers, et il faut la dire : Chtimes
// écrit les dates d'accès et de modification, celles que montrent `ls`, un
// explorateur ou une copie par rsync ou tar. La date de création — birthtime
// sur macOS, crtime sur ext4 — et le ctime restent ceux de l'écriture réelle :
// aucun appel en espace utilisateur ne les change. Le brouillage cache donc la
// date au regard ordinaire, pas à l'examen du disque.
func brouillerDate(chemin string) error {
	if err := os.Chtimes(chemin, dateNeutre, dateNeutre); err != nil {
		return fmt.Errorf("date du fichier chiffré: %w", err)
	}
	return nil
}
