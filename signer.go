package dangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"time"
)

var (
	BlankBytes = []byte("")
	DefaultSep = "."
)

type Signature interface {
	GetSignature(key, value []byte) []byte
	VerifySignature(key, value, sig []byte) bool
}

type SigningAlgorithm struct {
}

func (sa SigningAlgorithm) GetSignature(key, value []byte) []byte {
	return []byte{} // panic if empty
}
func (sa SigningAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return ByteCompare(sig, sa.GetSignature(key, value))
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

func (signer *Signer) SetDefault() {
	if signer.Secret == "" {
		panic("Signer secret is empty.")
	}
	signer.SecretBytes = WantBytes(signer.Secret)
	if signer.Salt == "" {
		signer.Salt = "itsdangerous.Signer"
	}
	if signer.Sep == "" {
		signer.Sep = DefaultSep
	}
	signer.SepBytes = WantBytes(signer.Sep)
	signer.SaltBytes = WantBytes(signer.Salt)

	if bytes.Contains(Base64Alphabet, signer.SepBytes) {
		fmt.Println(
			"The given separator cannot be used because it may be" +
				" contained in the signature itself. Alphanumeric" +
				" characters and `-_=` must not be used. Now we set Sep to DefaultSep(.)")
	}
	if signer.KeyDerivation == "" {
		signer.KeyDerivation = "django-concat"
	}
	if signer.DigestMethod == nil {
		signer.DigestMethod = sha256.New
	}
	if !IsValidStruct(signer.Algorithm) {
		signer.Algorithm = HMACAlgorithm{DigestMethod: signer.DigestMethod}
	}
}

func IsValidStruct(t interface{}) bool {
	_, ok := t.(Signature)
	return ok
}

func (signer *Signer) DeriveKey() ([]byte, error) {

	if signer.KeyDerivation == "concat" {
		msg, _ := Concentrate(signer.SaltBytes, signer.SecretBytes)
		funcs := signer.DigestMethod()
		funcs.Write(msg)
		return funcs.Sum(nil), nil

	} else if signer.KeyDerivation == "django-concat" {
		msg, _ := Concentrate(signer.SaltBytes, []byte("signer"))
		msg, _ = Concentrate(msg, signer.SecretBytes)
		funcs := signer.DigestMethod()
		funcs.Write(msg)
		return funcs.Sum(nil), nil

	} else if signer.KeyDerivation == "hmac" {
		mac := hmac.New(signer.DigestMethod, signer.SecretBytes)
		mac.Write(signer.SaltBytes)
		return mac.Sum(nil), nil

	} else if signer.KeyDerivation == "none" {
		return signer.SecretBytes, nil

	}
	return []byte("Error"), fmt.Errorf("Unknown key derivation method")
}

func (signer Signer) GetSignature(value []byte) []byte {
	key, err := signer.DeriveKey()
	if err != nil {
		panic(fmt.Sprintf("Signer.GetSignature: %s.", err))
	}
	sig := signer.Algorithm.(Signature).GetSignature(key, value)
	return WantBytes(B64encode(sig))
}

func (signer Signer) Sign(value string) []byte {
	(&signer).SetDefault()
	valuebyte := WantBytes(value)
	msg, _ := Concentrate(valuebyte, signer.SepBytes)
	msg, _ = Concentrate(msg, signer.GetSignature(valuebyte))
	return msg
}

func (signer Signer) VerifySignature(value []byte, sig []byte) bool {
	(&signer).SetDefault()
	key, err := signer.DeriveKey()
	if err != nil {
		return false
	}
	sigb, err := B64decode(sig)
	if err != nil {
		return false
	}
	return signer.Algorithm.(Signature).VerifySignature(key, value, sigb)
}

func (signer Signer) UnSign(signedvalues string) ([]byte, error) {
	(&signer).SetDefault()
	signedvalue := WantBytes(signedvalues)
	sep := signer.SepBytes
	if !bytes.Contains(signedvalue, sep) {
		return BlankBytes, fmt.Errorf("BadSignature: No %s found in value", signer.Sep)
	}
	value, sig := RSplit(signedvalue, sep)
	if signer.VerifySignature(value, sig) {
		return value, nil
	}
	return BlankBytes, fmt.Errorf("BadSignature: Signature %s does not match. Value: %s", sig, value)
}

func (signer Signer) Validate(signedvalues string) bool {
	_, err := signer.UnSign(signedvalues)
	if err != nil {
		return false
	}
	return true
}

func (signer Signer) GetTimestamp() int64 {
	return time.Now().UTC().Unix()
}

func (signer Signer) SignTimestamp(values string) []byte {
	(&signer).SetDefault()
	value := WantBytes(values)
	timestamp := WantBytes(B64encode(Int2Bytes(signer.GetTimestamp())))
	sep := WantBytes(signer.Sep)
	value, _ = Concentrate(value, sep, timestamp)
	value, _ = Concentrate(value, sep, signer.GetSignature(value))
	return value
}

func (signer Signer) UnSignTimestamp(values string, MaxAge int64) ([]byte, int64, error) {
	(&signer).SetDefault()
	result, err := signer.UnSign(values)
	if err != nil {
		return result, 0, err
	}
	sep := WantBytes(signer.Sep)
	if !bytes.Contains(result, sep) {
		return result, 0, fmt.Errorf("BadTimeSignature-timestamp missing")
	}
	value, ts := RSplit(result, sep)
	decode, err := B64decode(ts)
	if err != nil {
		return value, 0, fmt.Errorf("BadTimeSignature-%s", err)
	}
	timestamp := Bytes2Int(decode)
	if err != nil {
		return value, timestamp, fmt.Errorf("BadTimeSignature-Malformed timestamp")
	}
	if MaxAge >= 0 {
		age := signer.GetTimestamp() - timestamp
		if age > MaxAge {
			return value, timestamp, fmt.Errorf("SignatureExpired-Signature age %d > %d seconds", age, MaxAge)
		}
	}
	return value, timestamp, nil
}

func (signer Signer) ValidateTimestamp(signedvalue string, MaxAge int64) bool {
	(&signer).SetDefault()
	_, _, err := signer.UnSignTimestamp(signedvalue, MaxAge)
	if err != nil {
		return false
	}
	return true

}
