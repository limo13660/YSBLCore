package outbound

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDecodeJuicityCertHash(t *testing.T) {
	want := bytes.Repeat([]byte{0xfb, 0xff}, 16)
	for name, value := range map[string]string{
		"hex":        hex.EncodeToString(want),
		"upper hex":  strings.ToUpper(hex.EncodeToString(want)),
		"base64":     base64.StdEncoding.EncodeToString(want),
		"raw base64": base64.RawStdEncoding.EncodeToString(want),
		"url base64": base64.URLEncoding.EncodeToString(want),
		"raw url":    base64.RawURLEncoding.EncodeToString(want),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeJuicityCertHash(value)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("decode hash = %x, %v; want %x", got, err, want)
			}
		})
	}
}

func TestDecodeJuicityCertHashRejectsInvalidHashes(t *testing.T) {
	for _, value := range []string{
		"",
		"invalid!",
		hex.EncodeToString(bytes.Repeat([]byte{0xfb}, 31)),
		hex.EncodeToString(bytes.Repeat([]byte{0xfb}, 33)),
		base64.StdEncoding.EncodeToString(make([]byte, 31)),
		base64.StdEncoding.EncodeToString(make([]byte, 33)),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 48)),
	} {
		if _, err := decodeJuicityCertHash(value); err == nil {
			t.Errorf("accepted invalid hash %q", value)
		}
	}
}
