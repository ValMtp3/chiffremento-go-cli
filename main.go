package main

import (
	"chiffremento-cli/pkg"
	"flag"
	"fmt"
	"os"
)

func main() {
	// Définition des flags
	mode := flag.String("mode", "", "enc ou dec")
	fileIn := flag.String("in", "", "Fichier d'entrée")
	fileOut := flag.String("out", "", "Fichier de sortie")
	password := flag.String("key", "", "Mot de passe")
	compress := flag.Bool("comp", false, "Compresser les données avant chiffrement")
	chacha := flag.Bool("chacha", false, "Utiliser ChaCha20-Poly1305 au lieu d'AES-GCM")
	parano := flag.Bool("parano", false, "Mode Parano : Double chiffrement (Cascade AES + ChaCha20), plus lent mais plus robuste")

	flag.Parse()
	if *mode == "" || *fileIn == "" || *fileOut == "" || *password == "" {
		fmt.Println("Erreur : tous les paramètres sont obligatoires")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	switch *mode {
	case "enc":
		err = pkg.Encrypt(*fileIn, *fileOut, []byte(*password), *compress, *chacha, *parano)
	case "dec":
		err = pkg.Decrypt(*fileIn, *fileOut, []byte(*password))
	default:
		fmt.Println("Erreur: mode inconnu, utiliser 'enc' ou 'dec'")
		os.Exit(1)
	}

	if err != nil {
		fmt.Println("Erreur:", err)
		os.Exit(1)
	}

	fmt.Println("Opération réussie")
}
