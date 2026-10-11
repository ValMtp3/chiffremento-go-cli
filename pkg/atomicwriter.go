package pkg

// AtomicWriter expose l'écriture atomique aux appelants qui produisent les
// octets eux-mêmes — le CLI, quand l'entrée est un flux mais la sortie un
// fichier. Sans elle, ce chemin passait par os.Create : la destination était
// tronquée avant que l'en-tête ou le mot de passe soient vérifiés, et le clair
// partiel restait sur le disque en 0644 après un échec.
//
// Mêmes garanties qu'Encrypt et Decrypt : temporaire 0600 voisin, suivi par
// CleanupTemporaries en cas de Ctrl+C, fsync puis rename au Commit. Tant que
// Commit n'a pas réussi, la destination n'est pas touchée.
type AtomicWriter struct {
	a *atomicFile
}

// CreateAtomic prépare l'écriture de dest. Sauf force, une destination qui
// existe déjà est refusée avec ErrDestinationExistante.
func CreateAtomic(dest string, force bool) (*AtomicWriter, error) {
	a, err := newAtomicFile(dest, force)
	if err != nil {
		return nil, err
	}
	return &AtomicWriter{a: a}, nil
}

func (w *AtomicWriter) Write(p []byte) (int, error) {
	return w.a.f.Write(p)
}

// Commit rend l'écriture définitive : après un succès, dest contient un
// fichier complet, synchronisé sur le disque.
func (w *AtomicWriter) Commit() error {
	return w.a.commit()
}

// Abort retire le temporaire si Commit n'a pas eu lieu. Sans effet après un
// Commit réussi : il s'appelle en defer.
func (w *AtomicWriter) Abort() {
	w.a.cleanup()
}
