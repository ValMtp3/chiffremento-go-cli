package pkg

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Archivage tar d'un dossier, en streaming.
//
// Le tar est écrit directement dans le flux de chiffrement : aucun fichier
// intermédiaire, donc chiffrer un dossier de 100 Go ne consomme pas plus de
// RAM ni de disque que chiffrer un fichier. Le drapeau FlagArchive de
// l'en-tête indique au déchiffrement qu'il doit extraire au lieu d'écrire un
// fichier — et comme l'en-tête entre dans la dérivation de clé, ce drapeau ne
// peut pas être retourné par un attaquant.
//
// Les permissions et dates des entrées sont restaurées, mais jamais les bits
// setuid/setgid/sticky. Le dossier racine extrait, lui, reste en 0700 : c'est
// le pendant du 0600 d'un fichier déchiffré, la sortie est un secret.
//
// Contenus acceptés : dossiers et fichiers réguliers. Les liens symboliques
// sont refusés à l'archivage plutôt que suivis : les suivre embarquerait des
// données situées hors du dossier (voire une boucle infinie), et les stocker
// tels quels ouvrirait la porte au grand classique de l'extraction — un lien
// vers ../.. suivi d'un fichier écrit à travers lui.

const (
	// maxRecursionDepth borne la profondeur d'arborescence, à l'archivage
	// comme à l'extraction. C'est l'anti-DoS récursif : sans lui, une archive
	// hostile de quelques kilo-octets peut annoncer a/a/a/… sur cent mille
	// niveaux et faire exploser la pile, l'inode ou le chemin maximal du
	// système de fichiers de la victime.
	maxRecursionDepth = 64

	// maxArchiveEntries borne le nombre d'entrées, pour la même raison : une
	// archive compressée minuscule peut décrire des millions de fichiers vides.
	maxArchiveEntries = 500_000
)

// InputSize renvoie le volume qu'un chiffrement va réellement lire : la taille
// du fichier, ou la somme des fichiers réguliers d'un dossier. La taille d'un
// dossier renvoyée par Stat ne décrit que son inode, elle ne veut rien dire
// pour une barre de progression.
func InputSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return info.Size(), nil
	}
	plan, err := scanDirectory(path)
	if err != nil {
		return 0, err
	}
	return plan.total, nil
}

// archiveEntry est une entrée retenue par le scan préalable.
type archiveEntry struct {
	abs  string
	rel  string // relatif à la racine, séparateurs '/'
	info fs.FileInfo
}

// archivePlan est le résultat du parcours du dossier : la liste des entrées et
// le volume total à traiter.
type archivePlan struct {
	entries []archiveEntry
	total   int64
}

// scanDirectory parcourt root avant toute écriture.
//
// Faire ce parcours d'abord coûte un aller-retour sur les métadonnées, mais il
// donne deux choses qu'on ne peut pas obtenir en streaming : le total exact
// pour la barre de progression, et un échec *avant* que le moindre octet ne
// soit écrit quand l'arborescence contient quelque chose qu'on refuse.
func scanDirectory(root string) (*archivePlan, error) {
	plan := &archivePlan{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if pathDepth(rel) > maxRecursionDepth {
			return fmt.Errorf("arborescence trop profonde (plus de %d niveaux) : %s", maxRecursionDepth, rel)
		}
		if len(plan.entries) >= maxArchiveEntries {
			return fmt.Errorf("dossier trop volumineux : plus de %d entrées", maxArchiveEntries)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
		case info.Mode().IsRegular():
			plan.total += info.Size()
		default:
			return fmt.Errorf("%s : type non supporté (%s) — liens symboliques, sockets et périphériques sont refusés",
				rel, info.Mode().Type())
		}

		plan.entries = append(plan.entries, archiveEntry{abs: p, rel: rel, info: info})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("parcours du dossier: %w", err)
	}
	return plan, nil
}

// progressWriter compte les octets écrits, pour que la progression d'un dossier
// suive le volume réellement archivé et pas le nombre de fichiers.
type progressWriter struct {
	w  io.Writer
	fn func(n int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 && p.fn != nil {
		p.fn(int64(n))
	}
	return n, err
}

// tarHeaderFor construit l'en-tête tar d'une entrée. Partagé par l'écriture et
// par le calcul de taille, pour qu'ils ne puissent pas décrire deux archives
// différentes.
func tarHeaderFor(e archiveEntry) *tar.Header {
	hdr := &tar.Header{
		Name:    e.rel,
		Mode:    int64(e.info.Mode().Perm()),
		ModTime: e.info.ModTime(),
		Format:  tar.FormatPAX, // noms longs et dates précises, sans troncature
	}
	if e.info.IsDir() {
		hdr.Typeflag = tar.TypeDir
		hdr.Name = e.rel + "/"
		return hdr
	}
	hdr.Typeflag = tar.TypeReg
	hdr.Size = e.info.Size()
	return hdr
}

// countingWriter ne retient que le nombre d'octets qu'on lui a donnés.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(b []byte) (int, error) {
	c.n += int64(len(b))
	return len(b), nil
}

// tarSize calcule la taille exacte du tar que writeArchive produira, sans lire
// le contenu des fichiers : seuls les en-têtes sont réellement sérialisés, le
// contenu est compté.
//
// C'est ce qui permet au remplissage de viser un palier exact sur un dossier :
// sans cette taille, il faudrait soit deviner, soit construire l'archive deux
// fois.
func tarSize(plan *archivePlan) (int64, error) {
	var total int64
	for _, e := range plan.entries {
		hdr := tarHeaderFor(e)
		c := &countingWriter{}
		// Un tar.Writer neuf par entrée : on ne veut que les octets d'en-tête,
		// et il n'est jamais refermé, donc aucun bloc de fin n'est émis ici.
		if err := tar.NewWriter(c).WriteHeader(hdr); err != nil {
			return 0, fmt.Errorf("calcul de taille de %s: %w", e.rel, err)
		}
		total += c.n
		if hdr.Typeflag == tar.TypeReg {
			total += roundUpBlock(hdr.Size)
		}
	}
	// Deux blocs de zéros terminent toute archive tar.
	return total + 2*tarBlockSize, nil
}

const tarBlockSize = 512

func roundUpBlock(n int64) int64 {
	if r := n % tarBlockSize; r != 0 {
		return n + tarBlockSize - r
	}
	return n
}

// writeArchive sérialise le plan en tar dans w.
func writeArchive(w io.Writer, plan *archivePlan, progress func(done, total int64)) error {
	tw := tar.NewWriter(w)

	var done int64
	count := func(n int64) {
		done += n
		if progress != nil {
			progress(done, plan.total)
		}
	}

	for _, e := range plan.entries {
		hdr := tarHeaderFor(e)
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("écriture de l'entrée %s: %w", e.rel, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := copyEntry(tw, e, count); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("finalisation de l'archive: %w", err)
	}
	return nil
}

// copyEntry recopie un fichier dans le tar. La taille annoncée dans l'en-tête
// tar a été lue au scan : si le fichier a changé entre-temps, l'archive serait
// silencieusement incohérente. On préfère échouer.
func copyEntry(tw *tar.Writer, e archiveEntry, count func(int64)) error {
	f, err := os.Open(e.abs)
	if err != nil {
		return fmt.Errorf("lecture de %s: %w", e.rel, err)
	}
	defer f.Close()

	n, err := io.Copy(&progressWriter{w: tw, fn: count}, f)
	if err != nil {
		if errors.Is(err, tar.ErrWriteTooLong) {
			return fmt.Errorf("%s a grossi pendant l'archivage", e.rel)
		}
		return fmt.Errorf("archivage de %s: %w", e.rel, err)
	}
	if n != e.info.Size() {
		return fmt.Errorf("%s a changé de taille pendant l'archivage (%d octets attendus, %d lus)",
			e.rel, e.info.Size(), n)
	}
	return nil
}

// walkArchive parcourt un tar en validant chaque entrée, et délègue le
// traitement à handle. Toute la validation vit ici, pour que l'extraction et la
// vérification ne puissent pas diverger sur ce qu'elles acceptent.
func walkArchive(r io.Reader, handle func(hdr *tar.Header, rel string, body io.Reader) error) error {
	tr := tar.NewReader(r)

	for count := 0; ; count++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("lecture de l'archive: %w", err)
		}
		if count >= maxArchiveEntries {
			return fmt.Errorf("archive trop volumineuse : plus de %d entrées", maxArchiveEntries)
		}

		rel, err := safeArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("%s : entrée de type non supporté dans l'archive (%c)", rel, hdr.Typeflag)
		}
		if err := handle(hdr, rel, tr); err != nil {
			return err
		}
	}
}

// extractArchive déroule un tar dans dest, qui doit déjà exister.
//
// Chaque nom est validé avant d'être joint à dest : une archive ne peut donc
// rien écrire ailleurs que sous dest, même si elle a été fabriquée pour ça.
func extractArchive(r io.Reader, dest string) error {
	return walkArchive(r, func(hdr *tar.Header, rel string, body io.Reader) error {
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, dirPerm(hdr.FileInfo().Mode())); err != nil {
				return fmt.Errorf("création de %s: %w", rel, err)
			}
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return fmt.Errorf("création du dossier parent de %s: %w", rel, err)
		}
		return extractFile(body, target, rel, hdr)
	})
}

// checkArchive contrôle qu'un tar est lisible de bout en bout et qu'il ne
// contient rien que l'extraction refuserait, sans écrire un octet sur le
// disque.
func checkArchive(r io.Reader) error {
	return walkArchive(r, func(_ *tar.Header, _ string, body io.Reader) error {
		_, err := io.Copy(io.Discard, body)
		return err
	})
}

func extractFile(tr io.Reader, target, rel string, hdr *tar.Header) error {
	// O_EXCL : une archive qui décrit deux fois le même chemin ne doit pas
	// écraser en silence ce que la première entrée a écrit.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm(hdr.FileInfo().Mode()))
	if err != nil {
		return fmt.Errorf("création de %s: %w", rel, err)
	}
	if _, err := io.Copy(f, tr); err != nil {
		f.Close()
		return fmt.Errorf("extraction de %s: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fermeture de %s: %w", rel, err)
	}
	// Best effort : une date non restaurée n'invalide pas le contenu.
	os.Chtimes(target, hdr.ModTime, hdr.ModTime)
	return nil
}

// safeArchivePath valide un nom lu dans une archive et le renvoie nettoyé.
func safeArchivePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("entrée sans nom dans l'archive")
	}
	if strings.ContainsRune(name, 0) || strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("chemin refusé dans l'archive : %q", name)
	}

	clean := path.Clean(name)
	if path.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("chemin refusé dans l'archive : %q", name)
	}
	// Sur Windows, "C:evil" n'est ni absolu ni préfixé de ".." mais désigne
	// quand même un autre volume.
	if filepath.VolumeName(filepath.FromSlash(clean)) != "" {
		return "", fmt.Errorf("chemin refusé dans l'archive : %q", name)
	}
	if pathDepth(clean) > maxRecursionDepth {
		return "", fmt.Errorf("arborescence trop profonde dans l'archive (plus de %d niveaux) : %q",
			maxRecursionDepth, name)
	}
	return clean, nil
}

func pathDepth(rel string) int {
	return strings.Count(rel, "/") + 1
}

// filePerm et dirPerm : on repart des permissions d'origine mais sans jamais
// restaurer setuid/setgid/sticky, et en garantissant que le propriétaire peut
// relire ce qu'il vient d'extraire.
func filePerm(m fs.FileMode) fs.FileMode {
	return m.Perm() | 0600
}

func dirPerm(m fs.FileMode) fs.FileMode {
	return m.Perm() | 0700
}
