package dangerous

import (
	"bytes"
	"crypto/sha512"
	"strings"
	"testing"
	"time"
)

var (
	signer = Signer{Secret: "secret-key"}
	value  = "value"
)

func Test_signer(t *testing.T) {
	signed := signer.Sign(value)
	if !signer.Validate(string(signed)) {
		t.Fatalf("Validate failed.")
	}
	if unsigned, err := signer.UnSign(string(signed)); err != nil || string(unsigned) != value {
		t.Fatalf("Unsign failed.")
	}
}

func Test_no_separator(t *testing.T) {
	signed := signer.Sign(value)
	signed = bytes.Replace(signed, []byte(DefaultSep), []byte("*"), -1)
	if signer.Validate(string(signed)) {
		t.Fatalf("Validate failed.")
	}
	if _, err := signer.UnSign(string(signed)); !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf("Unsign failed.")
	}
}

func Test_broken_signature(t *testing.T) {
	signed := signer.Sign(value)
	signed = signed[:len(signed)-1]
	_, badsig := RSplit(signed, []byte(DefaultSep))
	if signer.VerifySignature([]byte(value), badsig) {
		t.Fatalf("Verify Signature failed.")
	}
	if _, err := signer.UnSign(string(signed)); !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf("Unsign failed.")
	}
}

func Test_changed_value(t *testing.T) {
	signed := signer.Sign(value)
	signed = bytes.Replace(signed, []byte("v"), []byte("V"), 1)
	if signer.VerifySignature([]byte(value), signed) {
		t.Fatalf("Verify Signature failed.")
	}
	if _, err := signer.UnSign(string(signed)); !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf("Unsign failed.")
	}
}

func Test_invalid_separator(t *testing.T) {
	_signer := Signer{Secret: "secret-key", Sep: "-"}
	_signer.Sign(value)
}

func Test_key_derivation(t *testing.T) {
	for _, i := range []string{"concat", "django-concat", "hmac", "none"} {
		_signer := Signer{Secret: "secret-key", KeyDerivation: i}
		signed := _signer.Sign(value)
		if v, err := _signer.UnSign(string(signed)); err != nil || string(v) != value {
			t.Fatalf("Unsign failed.")
		}
	}
}

func Test_invalid_key_derivation(t *testing.T) {
	_signer := Signer{Secret: "secret-key", KeyDerivation: "inv"}
	_, err := _signer.DeriveKey()
	if err == nil {
		t.Fatalf("Using invalid algorithm, but script is still running")
	}
}

func Test_digest_method(t *testing.T) {
	_signer := Signer{Secret: "secret-key", DigestMethod: sha512.New384}
	signed := _signer.Sign(value)
	if v, err := _signer.UnSign(string(signed)); err != nil || string(v) != value {
		t.Fatalf("Unsign failed.")
	}
}

type _ReverseAlgorithm struct {
	SigningAlgorithm
}

func (re _ReverseAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return ByteCompare(sig, re.GetSignature(key, value))
}

func (re _ReverseAlgorithm) GetSignature(key, value []byte) (a []byte) {
	a = append(key, value...)
	for left, right := 0, len(a)-1; left < right; left, right = left+1, right-1 {
		a[left], a[right] = a[right], a[left]
	}
	return
}

func Test_algorithm(t *testing.T) {

	for _, i := range []Signature{SigningAlgorithm{}, HMACAlgorithm{DigestMethod: sha512.New}, _ReverseAlgorithm{}} {
		_signer := Signer{Secret: "secret-key", Algorithm: i}
		signed := _signer.Sign(value)
		if v, err := _signer.UnSign(string(signed)); err != nil || string(v) != value {
			t.Fatalf("Unsign failed.")
		}
	}
}

// timed
func Test_max_age(t *testing.T) {
	signed := signer.SignTimestamp(value)
	_, _, err := signer.UnSignTimestamp(string(signed), 2)
	if err != nil {
		t.Fatalf("Unexpected error occurred when loads data. Error:%s", err)
	}
	time.Sleep(2 * time.Second)
	payload, _, err2 := signer.UnSignTimestamp(string(signed), 1)
	if err2 == nil {
		t.Fatalf("Load failed. Did not receive expected error.")
	}
	if string(payload) != value {
		t.Fatalf("Load failed. Unexpected payload.")
	}
}

func Test_return_timestamp(t *testing.T) {
	signed := signer.SignTimestamp(value)
	_, ts, err := signer.UnSignTimestamp(string(signed), 0)
	if err != nil || time.Now().UTC().Unix()-ts > 5 {
		t.Fatalf("Cant not get the timestamp")
	}
}

func Test_timestamp_missing(t *testing.T) {
	signed := signer.Sign(value)
	_, _, err := signer.UnSignTimestamp(string(signed), 10)
	if !strings.Contains(err.Error(), "BadTimeSignature") {
		t.Fatalf("Unexpected error occurred when loads data. Error:%s", err)
	}
}

func Test_malformed_timestamp(t *testing.T) {
	signed := signer.Sign(value + ".____________")
	_, _, err := signer.UnSignTimestamp(string(signed), 10)
	if !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Unexpected error occurred when loads data. Error:%s", err)
	}
}
