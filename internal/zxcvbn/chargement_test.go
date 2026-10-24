package zxcvbn

import (
	"os"
	"sync"
	"testing"
)

// nbChargementsAuDemarrage garde la valeur du compteur avant le premier test :
// importer le paquet ne doit rien charger.
var nbChargementsAuDemarrage int32

func TestMain(m *testing.M) {
	nbChargementsAuDemarrage = nbChargements.Load()
	os.Exit(m.Run())
}

func TestAucunChargementAuDemarrage(t *testing.T) {
	if nbChargementsAuDemarrage != 0 {
		t.Fatalf("%d chargement(s) avant le premier appel, 0 attendu", nbChargementsAuDemarrage)
	}
}

// Le préchargement en arrière-plan et la première frappe peuvent arriver en
// même temps : une seule construction, aucune course (à lancer avec -race).
func TestPrechargerConcurrent(t *testing.T) {
	const nbGoroutines = 8
	var attente sync.WaitGroup
	depart := make(chan struct{})
	for i := 0; i < nbGoroutines; i++ {
		attente.Add(1)
		go func() {
			defer attente.Done()
			<-depart
			Precharger()
			PasswordStrength("azerty123", nil)
		}()
	}
	close(depart)
	attente.Wait()

	if n := nbChargements.Load(); n != 1 {
		t.Fatalf("%d chargements, 1 attendu", n)
	}
}
