package nlp

import (
	"bufio"
	"io"
	"math"
	"strconv"
	"strings"
)

// Ngram holds a n-gram text with the log probability used for scoring
// e.g. {"TION", -1.0}
type Ngram struct {
	Floor  float64
	KeyLen int
	Index  map[string]float64
}

// NewNgram creates a map of n-grams used for scoring
func NewNgram(r io.ReadSeeker, i int) Ngram {
	// line count
	scanner := bufio.NewScanner(r)
	n := 0
	for scanner.Scan() {
		n++
	}
	count := float64(n)

	ng := Ngram{
		KeyLen: i,
		Index:  make(map[string]float64, n),
		Floor:  math.Log10(0.01 / count),
	}

	// rewind
	r.Seek(0, 0)
	scanner = bufio.NewScanner(r)
	line := make([]string, 2)
	for scanner.Scan() {
		line = strings.Split(scanner.Text(), " ")
		p, _ := strconv.Atoi(line[1])
		ng.Index[line[0]] = math.Log10(float64(p) / count)
	}

	return ng
}

// Score computes the probability score of containing an n-gram
func (ng *Ngram) Score(text string) float64 {
	score := 0.0
	for _, s := range strings.Split(text, " ") {
		// Db is in uppercase
		s = strings.ToUpper(s)
		sl := len(s) - ng.KeyLen + 1
		for i := 0; i < sl; i++ {
			// move up ngram length
			end := i + ng.KeyLen
			if end > len(s) {
				end = sl
			}

			token := s[i:end]
			val, exists := ng.Index[token]
			if exists {
				score += val
			} else {
				score += ng.Floor
			}
		}
	}
	return score
}

// TopN will return up to the top N matches above the minScore
func (ng *Ngram) TopN(possibles []string, minScore float64, max int) ([]float64, []string) {
	topN := make([]float64, max)
	for i := range topN {
		topN[i] = minScore
	}
	matches := make([]string, max)
	for _, p := range possibles {
		score := ng.Score(p)
		if score >= minScore {
			for i, s := range topN {
				if score > s {
					insertFloat(&topN, score, i)
					insertString(&matches, p, i)
					break
				}
			}
		}
	}
	return topN, matches
}

// trims the last element when inserting
func insertString(a *[]string, s string, i int) {
	l := len(*a) - 1
	copy((*a)[i+1:], (*a)[i:l])
	(*a)[i] = s
}

// trims the last element when inserting
func insertFloat(a *[]float64, f float64, i int) {
	l := len(*a) - 1
	copy((*a)[i+1:], (*a)[i:l])
	(*a)[i] = f
}
