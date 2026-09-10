package main

import "strings"

// Adaptation du nom d'origine aux règles du système de fichiers courant.
//
// sanitizeMetaName (pkg/metadata.go) traite la sécurité : plus de séparateur,
// plus de « .. », plus d'octet nul. Il en reste un nom sûr partout, mais pas
// forcément utilisable partout : Windows refuse « < > " | ? * », les caractères
// de contrôle, une poignée de noms de périphériques, et rogne les points et
// espaces de fin. Or ces noms sont légaux sous Unix, et un fichier chiffré là-bas
// peut parfaitement s'appeler « rapport 2024?.pdf ».
//
// D'où ce découpage : la sécurité ne dépend pas du système, l'utilisabilité si.
// Sous Unix, nomUtilisable rend le nom inchangé — aucun renommage ne change de
// comportement. Sous Windows, il remplace ce qui empêcherait le renommage, et
// l'interface propose le nom adapté, que l'utilisateur voit avant d'accepter.

// caracteresInterditsWindows liste ce que Win32 refuse dans un nom de fichier.
// Le « / », le « \ », le « : » et l'octet nul sont déjà écartés par
// sanitizeMetaName, qui les traite comme un risque et non comme une gêne.
const caracteresInterditsWindows = `<>"|?*`

// nomsReservesWindows sont des noms de périphériques : un fichier qui les porte
// est inaccessible, extension comprise — « aux.txt » ouvre le périphérique aux.
var nomsReservesWindows = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// adapterNom remplace par « _ » ce que le système refuse, et rend le nom tel
// quel s'il n'y a rien à corriger.
//
// Le remplacement plutôt que le refus : le but de la fonctionnalité est de
// rendre son nom au fichier. « rapport_.pdf » approche l'intention, alors qu'un
// refus laisse « a3f9c2.chto » et n'apprend rien à personne. L'interface montre
// de toute façon le nom proposé avant de renommer.
func adapterNom(nom, interdits string, reserves map[string]bool, rognerFin bool) string {
	if nom == "" {
		return nom
	}
	var b strings.Builder
	b.Grow(len(nom))
	for _, r := range nom {
		switch {
		case strings.ContainsRune(interdits, r):
			b.WriteRune('_')
		case r < 0x20 || r == 0x7f:
			// Les caractères de contrôle passent la validation de sécurité mais
			// rendent un nom illisible, et Windows les refuse.
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	adapte := b.String()

	// Windows rogne silencieusement les points et espaces de fin : « note. »
	// devient « note », et un renommage vers « note. » n'aboutit pas là où on
	// l'attend. On tranche donc nous-mêmes, plutôt que de laisser le système le
	// faire dans notre dos.
	if rognerFin {
		adapte = strings.TrimRight(adapte, " .")
		if adapte == "" {
			return "_"
		}
	}

	// Un nom de périphérique reste inaccessible même avec une extension : c'est
	// la base, avant le premier point, qui compte.
	if len(reserves) > 0 {
		base := adapte
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		if reserves[strings.ToLower(base)] {
			adapte = "_" + adapte
		}
	}
	return adapte
}
