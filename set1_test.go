package cryptofun

import (
	"testing"
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
			t.Error("Hex2B64(%q) => %q", err)
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
			t.Error("HexXOR(%q) => %q", err)
		}
		if string(result) != tt.out {
			t.Errorf("HexXOR(%q) => %q, want %q", tt.in, result, tt.out)
		}
	}
}

var xorciphertests = []tt{
	{"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", "ETAOIN SHRDLU"},
}

func TestXORCipher(t *testing.T) {
	for _, tt := range xorciphertests {
		result, _ := SubXOR(tt.in, tt.out)
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
