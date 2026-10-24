package pkg

// rouvrirTemporaires annule FermerTemporaires, pour les tests seulement : en
// production, la fermeture précède la sortie du processus et n'est jamais
// levée.
func rouvrirTemporaires() { fermes.Store(false) }
