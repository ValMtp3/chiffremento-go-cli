package pkg

import (
	"crypto/rand"
	"fmt"
	"time"
)

type KDFBenchmarkResult struct {
	Profile  KDFProfile
	KDFLabel string
	Duration time.Duration
	Err      error
}

type KDFBenchmarkReport struct {
	Results     []KDFBenchmarkResult
	Recommended KDFProfile
}

func BenchmarkKDF(password []byte) KDFBenchmarkReport {
	profiles := []KDFProfile{KDFStandard, KDFFort, KDFParano}
	results := make([]KDFBenchmarkResult, 0, len(profiles))
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return KDFBenchmarkReport{
			Results: []KDFBenchmarkResult{{
				Profile:  KDFStandard,
				KDFLabel: KDFLabelForProfile(KDFStandard),
				Err:      fmt.Errorf("génération du sel: %w", err),
			}},
			Recommended: KDFStandard,
		}
	}

	recommended := KDFStandard
	var bestBelowTarget KDFProfile
	var foundBelowTarget bool
	const targetMax = 1200 * time.Millisecond

	for _, profile := range profiles {
		params := profile.argonParams()
		start := time.Now()
		_, err := deriveKey(password, salt, params)
		d := time.Since(start)
		results = append(results, KDFBenchmarkResult{
			Profile:  profile,
			KDFLabel: "argon2id  " + params.String(),
			Duration: d,
			Err:      err,
		})
		if err == nil {
			recommended = profile
			if d <= targetMax {
				bestBelowTarget = profile
				foundBelowTarget = true
			}
		}
	}
	if foundBelowTarget {
		recommended = bestBelowTarget
	}

	return KDFBenchmarkReport{Results: results, Recommended: recommended}
}

