package pkg

// rouvrirTemporaires annule FermerTemporaires, pour les tests seulement : en
// production, la fermeture précède la sortie du processus et n'est jamais
// levée.
func rouvrirTemporaires() { fermes.Store(false) }

// nettoyerTemporaires supprime les temporaires en cours sans fermer le
// registre, pour les tests seulement : la production passe toujours par
// FermerTemporaires, juste avant la sortie du processus.
func nettoyerTemporaires() {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	nettoyerRegistre()
}
