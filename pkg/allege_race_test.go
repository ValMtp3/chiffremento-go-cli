package pkg

import (
	"os"
	"testing"
)

// Sous -race, chaque accès mémoire est instrumenté : une dérivation Argon2 de
// 256 Mio à 1 Gio coûte alors cinq à dix fois plus cher. La suite en fait des
// centaines sans que ce soit leur sujet (chiffrer, archiver, changer de mot de
// passe...), et le runner macOS de la CI frôlait sa limite de 25 minutes.
//
// Sous -race, les nouveaux fichiers sont donc écrits avec les paramètres les
// plus légers (voir argonAlege). Sans -race, rien ne change : les profils
// réels restent exercés par toute la suite. Les tests dont le sujet EST un
// profil lourd, ou la valeur inscrite dans le header, le réclament avec
// profilReel.
func TestMain(m *testing.M) {
	argonAlegeDesTests.Store(raceEnabled)
	os.Exit(m.Run())
}

// profilReel rend aux nouveaux fichiers les paramètres réels de leur profil
// pour la durée du test. À appeler en tête d'un test qui vérifie ce que le
// profil écrit ou qui doit réellement dériver à cette taille. Ne pas l'utiliser
// avec t.Parallel : le réglage est partagé par tout le paquet. Aucune garde
// peu coûteuse n'existe (Go ne dit pas à un helper si son test est parallèle) ;
// aucun test de pkg n'appelle t.Parallel aujourd'hui.
func profilReel(t *testing.T) {
	t.Helper()
	avant := argonAlegeDesTests.Swap(false)
	t.Cleanup(func() { argonAlegeDesTests.Store(avant) })
}
