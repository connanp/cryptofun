package cryptofun

import (
	"bufio"
	"bytes"
	"os"
	"testing"

	"github.com/connanp/cryptofun/nlp"
)

type tt struct {
	in  string
	out string
}

var convtests = []tt{
	{"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"},
}

func TestHex2B64(t *testing.T) {
	for _, tt := range convtests {
		result, err := Hex2B64(tt.in)
		if err != nil {
			t.Errorf("Hex2B64(%q) => %q", err, result)
		}
		if string(result) != tt.out {
			t.Errorf("Hex2B64(%q) => %q, want %q", tt.in, result, tt.out)
		}
	}
}

var xortests = []struct {
	in  []string
	out string
}{
	{[]string{"1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"}, "746865206b696420646f6e277420706c6179"},
}

func TestXOR(t *testing.T) {
	for _, tt := range xortests {
		result, err := HexXOR(tt.in[0], tt.in[1])
		if err != nil {
			t.Errorf("HexXOR(%q) => %q", err, result)
		}
		if string(result) != tt.out {
			t.Errorf("HexXOR(%q) => %q, want %q", tt.in, result, tt.out)
		}
	}
}

var xorciphertests = []tt{
	{"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "Cooking MC's like a pound of bacon"},
}

func TestXORCipher(t *testing.T) {
	for _, tt := range xorciphertests {
		result, _ := DecryptSubXOR(tt.in, nlp.MostFreqSingleChars)
		var found bool
		for i, s := range result {
			if s == tt.out {
				found = true
				t.Logf("Found match at index %q", i)
			}
		}
		if !found {
			t.Errorf("SubXOR(%q) => want %q", tt.in, tt.out)
		}
	}
}

var xorcipherbestests = []struct {
	in       string
	chars    string
	expected string
	minScore float64
	max      int
}{
	{"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
		nlp.MostFreqSingleChars,
		"Cooking MC's like a pound of bacon",
		-50.0,
		5,
	},
}

func TestBestMatchXORCipher(t *testing.T) {
	path := "resources\\english_quadgrams.txt"
	f, err := os.Open(path)
	if err != nil {
		t.Error("Failed to open file " + path)
	}
	defer f.Close()

	ng := nlp.NewNgram(f, 4)
	for _, tt := range xorcipherbestests {
		match, _ := BestMatchXORSub(tt.in, tt.chars, &ng, tt.minScore, tt.max)
		if match != tt.expected {
			t.Errorf("BestMatchXORSub() => \"%s\", want \"%s\"", match, tt.expected)
		}
	}
}

func TestBruteForceFileSubXOR(t *testing.T) {
	path := "resources\\english_quadgrams.txt"
	f, err := os.Open(path)
	if err != nil {
		t.Error("Failed to open file " + path)
	}
	defer f.Close()

	ng := nlp.NewNgram(f, 4)
	tpath := "resources\\4.txt"
	testfile, err := os.Open(tpath)
	if err != nil {
		t.Error("Failed to open file " + tpath)
	}
	defer testfile.Close()

	scanner := bufio.NewScanner(testfile)
	n := 0
	for scanner.Scan() {
		n++
	}

	matches := make([]string, 1, n)
	testfile.Seek(0, 0)
	scanner = bufio.NewScanner(testfile)
	for scanner.Scan() {
		m, err := BestMatchXORSub(scanner.Text(), nlp.MostFreqSingleChars, &ng, -15.0, 5)
		if err != nil {
			matches = append(matches, m)
		}
	}
}

var encryptxortests = []tt{
	{
		"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
		"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
	},
	{
		"I like big butts and I cannot lie\nYou other brothers can't deny\nThat when a girl walks in with an itty bitty waist",
		"00632920282069212c2e63273c37313a6324272765006326282d2b263765252a20431a2a3c6326372d2c31652b312a3d2b203b30652a222b6e37652d262b30491121223169342d2c2d6528632e2a37256332282f2e3a632c27633220372d69222b692a313d3a652b2a313d3a653e222c3a37",
	},
}

func TestEncryptSubXOR(t *testing.T) {
	for _, tt := range encryptxortests {
		r := bytes.NewReader([]byte(tt.in))
		var out bytes.Buffer
		w := bufio.NewWriter(&out)
		EncryptSubXOR(r, r.Size(), w, "ICE")
		if out.String() != tt.out {
			t.Errorf("%s does not match expected: %s", out.String(), tt.out)
		}
	}
}
