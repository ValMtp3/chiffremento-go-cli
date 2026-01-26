package main

import (
	"chiffremento-cli/pkg"
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "dev"

func main() {
	// Définition des flags
	showVersion := flag.Bool("version", false, "Afficher la version")
	mode := flag.String("mode", "", "enc ou dec")
	fileIn := flag.String("in", "", "Fichier d'entrée")
	password := flag.String("key", "", "Mot de passe")
	compress := flag.Bool("comp", false, "Compresser les données avant chiffrement")
	chacha := flag.Bool("chacha", false, "Utiliser ChaCha20-Poly1305 au lieu d'AES-GCM")
	parano := flag.Bool("parano", false, "Mode Parano : Double chiffrement (Cascade AES + ChaCha20), plus lent mais plus robuste")

	flag.Parse()
	if *showVersion {
		fmt.Printf("Chiffremento CLI version %s\n", version)
		os.Exit(0)
	}
	if *mode == "" || *fileIn == "" || *password == "" {
		fmt.Println("Erreur : mode, in et key sont obligatoires")
		flag.Usage()
		os.Exit(1)
	}

	if *mode == "dec" && !strings.HasSuffix(*fileIn, ".chto") {
		fmt.Println("Erreur : Le fichier à déchiffrer doit avoir l'extension .chto")
		os.Exit(1)
	}
	var fileOut string
	if *mode == "enc" {
		fileOut = *fileIn + ".chto"
	} else {
		fileOut = strings.TrimSuffix(*fileIn, ".chto")
	}
	fmt.Println("Fichier de sortie :", fileOut)

	var err error
	switch *mode {
	case "enc":
		err = pkg.Encrypt(*fileIn, fileOut, []byte(*password), *compress, *chacha, *parano)
	case "dec":
		err = pkg.Decrypt(*fileIn, fileOut, []byte(*password))
	default:
		fmt.Println("Erreur : mode inconnu, utiliser 'enc' ou 'dec'")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Erreur :", err)
		os.Exit(1)
	}

	fmt.Println("Opération réussie")
}
