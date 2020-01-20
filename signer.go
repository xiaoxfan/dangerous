package dangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"time"
)

var blank_bytes = []byte("")

type Signature interface {
	GetSignature(key, value []byte) []byte
	VerifySignature(key, value, sig []byte) bool
}

type SigningAlgorithm struct {
}

func (sa SigningAlgorithm) GetSignature(key, value []byte) []byte {
	return blank_bytes
}
func (sa SigningAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return ByteCompare(sig, sa.GetSignature(key, value))
}

type NoneAlgorithm struct {
	SigningAlgorithm
}

type HMACAlgorithm struct {
	DigestMethod func() hash.Hash
}

func (ha HMACAlgorithm) GetSignature(key, value []byte) []byte {
	_hmac := hmac.New(ha.DigestMethod, key)
	_hmac.Write(value)
	return _hmac.Sum(nil)
}

func (ha HMACAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return ByteCompare(sig, ha.GetSignature(key, value))
}

type SignerAPI interface {
	GetSignature(value []byte) []byte
	Sign(value string) []byte
	VerifySignature(value []byte, sig []byte) bool
	UnSign(signed_values string) ([]byte, error)
	Validate(signed_value string) bool
	SignTimestamp(values string) []byte
	UnSignTimestamp(values string, max_age int64) ([]byte, error)
	ValidateTimestamp(signed_value string, max_age int64) bool
}

type Signer struct {
	Secret        string
	Salt          string
	Sep           string
	SecretBytes   []byte
	SaltBytes     []byte
	SepBytes      []byte
	KeyDerivation string // concat, django-concat, hmac
	DigestMethod  func() hash.Hash
	Algorithm     Signature // HMACAlgorithm, NoneAlgorithm
}

func (sign *Signer) SetDefault() {
	sign.SecretBytes = WantBytes(sign.Secret)
	if sign.Salt == "" {
		sign.Salt = "itsdangerous.Signer"
	}
	if sign.Sep == "" {
		sign.Sep = "."
	}
	sign.SepBytes = WantBytes(sign.Sep)
	sign.SaltBytes = WantBytes(sign.Salt)

	if bytes.Contains(Base64_alphabet, sign.SepBytes) {
		panic(
			"The given separator cannot be used because it may be" +
				" contained in the signature itself. Alphanumeric" +
				" characters and `-_=` must not be used.")
	}
	if sign.KeyDerivation == "" {
		sign.KeyDerivation = "django-concat"
	}
	if sign.DigestMethod == nil {
		sign.DigestMethod = sha256.New
	}
	if !IsValidStruct(sign.Algorithm) {
		sign.Algorithm = HMACAlgorithm{DigestMethod: sign.DigestMethod}
	}
}

func IsValidStruct(t interface{}) bool {
	switch t.(type) {
	case HMACAlgorithm:
		return true
	case NoneAlgorithm:
		return true
	default:
		return false
	}
}

func (sign *Signer) DeriveKey() ([]byte, error) {

	if sign.KeyDerivation == "concat" {
		msg, _ := Concentrate(sign.SaltBytes, sign.SecretBytes)
		funcs := sign.DigestMethod()
		funcs.Write(msg)
		return funcs.Sum(nil), nil

	} else if sign.KeyDerivation == "django-concat" {
		msg, _ := Concentrate(sign.SaltBytes, []byte("signer"))
		msg, _ = Concentrate(msg, sign.SecretBytes)
		funcs := sign.DigestMethod()
		funcs.Write(msg)
		return funcs.Sum(nil), nil

	} else if sign.KeyDerivation == "hmac" {
		mac := hmac.New(sign.DigestMethod, sign.SecretBytes)
		mac.Write(sign.SaltBytes)
		return mac.Sum(nil), nil

	} else if sign.KeyDerivation == "none" {
		return sign.SecretBytes, nil

	}
	return []byte("Error"), fmt.Errorf("Unknown key derivation method")
}

func (sign Signer) GetSignature(value []byte) []byte {
	key, err := sign.DeriveKey()
	if err != nil {
		panic(fmt.Sprintf("Signer.GetSignature: %s.", err))
	}
	sig := sign.Algorithm.(Signature).GetSignature(key, value)
	return WantBytes(B64encode(sig))
}

func (sign Signer) Sign(value string) []byte {
	(&sign).SetDefault()
	value_b := WantBytes(value)
	msg, _ := Concentrate(value_b, sign.SepBytes)
	msg, _ = Concentrate(msg, sign.GetSignature(value_b))
	return msg
}
func (sign Signer) VerifySignature(value []byte, sig []byte) bool {
	(&sign).SetDefault()
	key, err := sign.DeriveKey()
	if err != nil {
		return false
	}
	sigb, err := B64decode(sig)
	if err != nil {
		return false
	}
	return sign.Algorithm.(Signature).VerifySignature(key, value, sigb)
}

func (sign Signer) UnSign(signed_values string) ([]byte, error) {
	(&sign).SetDefault()
	signed_value := WantBytes(signed_values)
	sep := sign.SepBytes
	if !bytes.Contains(signed_value, sep) {
		return blank_bytes, fmt.Errorf("BadSignature: No %s found in value", sign.Sep)
	}
	value, sig := RSplit(signed_value, sep)
	if sign.VerifySignature(value, sig) {
		return value, nil
	}
	return blank_bytes, fmt.Errorf("BadSignature: Signature %s does not match. Value: %s", sig, value)
}

func (sign Signer) Validate(signed_value string) bool {
	_, err := sign.UnSign(signed_value)
	if err != nil {
		return false
	}
	return true
}

func (self Signer) get_timestamp() int64 {

	return int64(time.Now().Unix())
}

func (self Signer) SignTimestamp(values string) []byte {
	(&self).SetDefault()
	value := WantBytes(values)
	timestamp := WantBytes(B64encode(Int2Bytes(self.get_timestamp())))
	sep := WantBytes(self.Sep)
	value, _ = Concentrate(value, sep, timestamp)
	value, _ = Concentrate(value, sep, self.GetSignature(value))
	return value
}

func (self Signer) UnSignTimestamp(values string, max_age int64) ([]byte, error) {
	(&self).SetDefault()
	result, err := self.UnSign(values)
	if err != nil {
		return result, err
	}
	sep := WantBytes(self.Sep)
	if !bytes.Contains(result, sep) {
		return result, fmt.Errorf("timestamp missing")
	}
	value, ts := RSplit(result, sep)
	decode, err := B64decode(ts)
	if err != nil {
		return value, err
	}
	timestamp := Bytes2Int(decode)
	if err != nil {
		return value, fmt.Errorf("Malformed timestamp")
	}
	if max_age > 0 {
		age := self.get_timestamp() - timestamp
		if age > max_age {
			return value, fmt.Errorf("Signature age %d > %d seconds", age, max_age)
		}
	}
	return value, nil
}

func (self Signer) ValidateTimestamp(signed_value string, max_age int64) bool {
	(&self).SetDefault()
	_, err := self.UnSignTimestamp(signed_value, max_age)
	if err != nil {
		return false
	}
	return true

}
