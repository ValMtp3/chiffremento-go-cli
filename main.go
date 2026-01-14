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
	if *mode == "" || *fileIn == "" || *password == "" {
		fmt.Println("Erreur : mode, in et key sont obligatoires")
		flag.Usage()
		os.Exit(1)
	}

	if *fileOut == "" {
		if *mode == "enc" {
			*fileOut = *fileIn + ".chto"
		} else if *mode == "dec" {
			if len(*fileIn) > 5 && (*fileIn)[len(*fileIn)-5:] == ".chto" {
				*fileOut = (*fileIn)[:len(*fileIn)-5]
			} else {
				*fileOut = *fileIn + ".dec"
			}
		}
		fmt.Println("Sortie par défaut :", *fileOut)

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
