package cryptofun

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"runtime"
	"unsafe"

	"github.com/connanp/cryptofun/nlp"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64"

var b64 = base64.StdEncoding

// Hex2B64 takes a string of hexadecimal and converts it to a base64 encoded byte array
func Hex2B64(in string) ([]byte, error) {
	hbytes, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	}
	final := make([]byte, b64.EncodedLen(len(hbytes)))
	b64.Encode(final, hbytes)
	return final, nil
}

// from crypto/cipher/xor.go
// fastXORBytes xors in bulk. It only works on architectures that
// support unaligned read/writes.
func fastXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	w := n / wordSize
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))
		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}

	for i := (n - n%wordSize); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// xorBytes xors the bytes in a and b. The destination is assumed to have enough
// space. Returns the number of bytes xor'd.
func xorBytes(dst, a, b []byte) int {
	if supportsUnaligned {
		return fastXORBytes(dst, a, b)
	}
	return safeXORBytes(dst, a, b)
}

// HexXOR takes 2 hexadecimal strings and returns the resulting bytes of XORing them
func HexXOR(s1 string, s2 string) ([]byte, error) {
	b1, err := hex.DecodeString(s1)
	b2, err := hex.DecodeString(s2)
	if err != nil {
		return nil, err
	}
	x := make([]byte, len(b1))
	xorBytes(x, b1, b2)
	final := make([]byte, hex.EncodedLen(len(x)))
	hex.Encode(final, x)
	return final, nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func xorKey(dst, b []byte, i int) {
	r := byte(rune(i))
	n := len(b)
	for i := 0; i < n; i++ {
		dst[i] = b[i] ^ r
	}
}

func encodeStringToHexBytes(s string) []byte {
	encoded := make([]byte, hex.EncodedLen(len(s)))
	hex.Encode(encoded, []byte(s))
	return encoded
}

// EncryptFileSubXOR takes a key and does a repeating XOR substitution on a file
func EncryptFileSubXOR(f *os.File, w io.Writer, key string) {
	fi, _ := f.Stat()
	EncryptSubXOR(f, fi.Size(), w, key)
}

// EncryptSubXOR takes a key and does a repeating XOR substitution on the result
func EncryptSubXOR(r io.Reader, rlen int64, w io.Writer, key string) {
	k := encodeStringToHexBytes(key)
	kl := len(key)
	kl64 := int64(len(key))

	// FIXME this won't handle large files
	bsize := int(rlen / kl64)
	buf := make([]byte, bsize)
	dst := make([]byte, bsize)

	// one more iteration for the remainder
	if rlen%kl64 > 0 {
		kl++
	}
	for i := 0; i < kl; i++ {
		if n, err := io.ReadAtLeast(r, buf, bsize); err != nil {
			buf = buf[:n]
			dst = dst[:n]
		}
		xorBytes(dst, buf, k)
		w.Write(dst)
	}
}

// DecryptSubXOR attempts to decrypt the string and returns all possible matches.
// Will check matches against a character class of chars provided by the caller.
// A recommended set of chars would be "ETAOIN SHRDLU"
func DecryptSubXOR(enc, chars string) ([]string, error) {
	b1, err := hex.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	n1 := len(b1)

	re := regexp.MustCompile(fmt.Sprintf("(?i)[%s]", regexp.QuoteMeta(chars)))

	matches := make([]string, 1)
	x := make([]byte, n1)
	for i := 0; i < 255; i++ {
		zeroBytes(x)
		xorKey(x, b1, i)
		found := re.FindAllIndex(x, -1)
		if found != nil {
			agg := 0
			for j := range found {
				agg += len(found[j])
			}
			if agg > 20 {
				matches = append(matches, string(x[:]))
			}
		}
	}
	return matches, nil
}

// BestMatchXORSub brute forces the single cipher and prints the best matches
func BestMatchXORSub(enc, chars string, ng *nlp.Ngram, minScore float64, max int) (string, error) {
	potentials, err := DecryptSubXOR(enc, chars)
	if err != nil {
		return "", err
	}
	scores, matches := ng.TopN(potentials, minScore, max)
	for i := 0; i < len(scores); i++ {
		if matches[i] != "" {
			log.Printf("match: \"%s\" with score %g", matches[i], scores[i])
		}
	}

	if matches[0] == "" {
		return "", errors.New("no useful matches found")
	}
	return matches[0], nil
}
