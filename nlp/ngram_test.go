package nlp

import (
	"os"
	"testing"
)

var newtests = []struct {
	path       string
	len        int
	indexCount int
}{
	{"..\\resources\\english_quadgrams.txt", 4, 389373},
}

func TestNewNgram(t *testing.T) {
	for _, tt := range newtests {
		ng := NewNgram(openDb(tt.path, t), tt.len)
		if ng.Floor > 0.0 {
			t.Errorf("NewNgram(%q, %q) => Floor is > 0.0, ng.Floor == %q", tt.path, tt.len, ng.Floor)
		}
		if ng.KeyLen != tt.len {
			t.Errorf("NewNgram(%q, %q) => ng.KeyLen(%q) != %q", tt.path, tt.len, ng.KeyLen, tt.len)
		}
		if len(ng.Index) != tt.indexCount {
			t.Errorf("NewNgram(%q, %q) => ng.Index length(%q) != %q", tt.path, tt.len, len(ng.Index), tt.indexCount)
		}
	}
}

func openDb(path string, t *testing.T) *os.File {
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Could not open ngram file: %s", path)
	}
	return file
}

var EPSILON = 0.00000001

// validates float is within a margin of error
// taken from math/all_test.go
func floatEquals(a, b float64) bool {
	e := 1e-14
	d := a - b
	if d < 0 {
		d = -d
	}

	// note: b is correct (expected) value, a is actual value.
	// make error tolerance a fraction of b, not a.
	if b != 0 {
		e = e * b
		if e < 0 {
			e = -e
		}
	}
	return d < e
}

var scoretests = []struct {
	path     string
	len      int
	text     string
	expected float64
}{
	{"..\\resources\\english_quadgrams.txt", 4, "Cooking MC's like a pound of bacon", -7.915516584015444},
	{"..\\resources\\english_quadgrams.txt", 4, "GnnbkJla ka!asd91", -61.95057548880238},
}

func TestScore(t *testing.T) {
	for _, tt := range scoretests {
		ng := NewNgram(openDb(tt.path, t), tt.len)
		score := ng.Score(tt.text)
		if !floatEquals(score, tt.expected) {
			t.Errorf("ng.Score(%q) => %g, want %g", tt.text, score, tt.expected)
		}
	}
}

var top5tests = []struct {
	path     string
	len      int
	max      int
	minScore float64
	text     []string
}{
	{"..\\resources\\english_quadgrams.txt",
		4,
		5,
		-50.0,
		[]string{"Cooking MC's like a pound of bacon", "9018231akjz aksjagb", "bungholio pirate parties", "abc1 23451 lalala", "there's no place like home", "nobody likes a pushover"},
	},
}

func TestTopN(t *testing.T) {
	for _, tt := range top5tests {
		ng := NewNgram(openDb(tt.path, t), tt.len)
		scores, texts := ng.TopN(tt.text, tt.minScore, tt.max)
		if len(scores) != tt.max {
			t.Errorf("TopN(%q,%q,%q) => %q, want %q", tt.text, tt.minScore, tt.max, tt.max)
		}
		for i := 0; i < len(scores)-1; i++ {
			if scores[i] < scores[i+1] {
				t.Errorf("scores are not sorted. %g > %g", scores[i], scores[i+1])
				t.FailNow()
			}
		}
		t.Logf("%g, %g\n", scores, texts)
	}
}
