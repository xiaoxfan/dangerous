package dangerous

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"time"
)

var (
	JwsAlgorithms = map[string]interface{}{
		"HS256": HMACAlgorithm{DigestMethod: sha256.New},
		"HS384": HMACAlgorithm{DigestMethod: sha512.New384},
		"HS512": HMACAlgorithm{DigestMethod: sha512.New},
		"none":  SigningAlgorithm{},
	}

	DefaultAlgorithm = "HS512"

	DefaultSerializer = JSON{}

	DefaultExpiresIn int64 = 3600
)

type JSONWebSignatureSerializer struct {
	serializer    Serializer
	Secret        string
	Salt          string
	Serializer    JSONAPI
	Signer        Signer
	Signerkwargs  map[string]interface{}
	AlgorithmName string
	Algorithm     Signature
	ExpiresIn     int64
}

func (jwss *JSONWebSignatureSerializer) SetDefault() {
	if jwss.AlgorithmName == "" {
		jwss.AlgorithmName = DefaultAlgorithm
	}
	if jwss.ExpiresIn == 0 {
		jwss.ExpiresIn = DefaultExpiresIn
	}
	alg := JwsAlgorithms[jwss.AlgorithmName]
	if alg == nil {
		jwss.AlgorithmName = DefaultAlgorithm
		alg = JwsAlgorithms[jwss.AlgorithmName]
		fmt.Println("Invalid_algorithm! Now we will use default algorithm. HS256.")
	}
	jwss.Algorithm = alg.(Signature)
	jwss.Serializer = JSON{}
	ser := &Serializer{
		Secret:       jwss.Secret,
		Salt:         jwss.Salt,
		SerializerOP: jwss.Serializer,
		Signer:       jwss.Signer,
		Signerkwargs: jwss.Signerkwargs}
	ser.SetDefault()
	jwss.serializer = (*ser)
}

func (jwss JSONWebSignatureSerializer) LoadPayload(payload []byte) (interface{}, interface{}, error) {
	null := []byte("")
	sep := []byte(".")
	if !bytes.Contains(payload, sep) {
		return null, null, fmt.Errorf("BadPayload: No '.' found in value, %s", payload)
	}
	v := bytes.SplitN(payload, []byte("."), 2)

	base64dheader, base64dpayload := v[0], v[1]

	JSONheader, err := B64decode(base64dheader)
	if err != nil {
		return JSONheader, null, fmt.Errorf("Could not base64 decode the header because of an exception")
	}
	JSONpayload, err := B64decode(base64dpayload)
	if err != nil {
		return null, JSONpayload, fmt.Errorf("Could not base64 decode the payload because of an exception")
	}
	header, err := jwss.serializer.LoadPayload(JSONheader)
	if err != nil {
		return header, null, fmt.Errorf("Could not unserialize header because it was malformed")
	}
	_, ok := header.(map[string]interface{})
	if !ok {
		return header, null, fmt.Errorf("Header payload is not a JSON object")
	}
	payloadr, err := jwss.serializer.LoadPayload(JSONpayload)
	return header, payloadr, err
}

func (jwss JSONWebSignatureSerializer) DumpPayload(header, obj interface{}) ([]byte, error) {
	h, err := jwss.Serializer.(JSONAPI).Dump(header)
	if err != nil {
		return BlankBytes, err
	}
	base64dheader := B64encode([]byte(h))
	p, err := jwss.Serializer.(JSONAPI).Dump(obj)
	if err != nil {
		return BlankBytes, err
	}
	base64dpayload := B64encode([]byte(p))
	sep := WantBytes(".")
	result, err := Concentrate(WantBytes(base64dheader), sep, WantBytes(base64dpayload))
	return result, err
}

func (jwss JSONWebSignatureSerializer) MakeSigner() Signer {
	keyderivation := ""
	if jwss.Salt == "" {
		keyderivation = "none"
	}
	SIGNER := &Signer{
		Secret:        jwss.Secret,
		Salt:          jwss.Salt,
		Sep:           ".",
		KeyDerivation: keyderivation,
		Algorithm:     jwss.Algorithm,
	}
	SIGNER.SetDefault()
	return (*SIGNER)

}

func (jwss JSONWebSignatureSerializer) MakeHeader(headerfields map[string]interface{}) map[string]interface{} {
	headerfields["alg"] = jwss.AlgorithmName
	return headerfields

}

func (jwss JSONWebSignatureSerializer) Dumps(obj interface{}, args ...interface{}) ([]byte, error) {
	(&jwss).SetDefault()
	headerfields := map[string]interface{}{}
	if len(args) == 1 {
		headerfields, _ = args[0].(map[string]interface{})
	}
	header := jwss.MakeHeader(headerfields)
	signer := jwss.MakeSigner()
	payload, err := jwss.DumpPayload(header, obj)
	if err != nil {
		return payload, err
	}
	return signer.Sign(string(payload)), nil
}

func (jwss JSONWebSignatureSerializer) Loads(s string) (interface{}, interface{}, error) {
	(&jwss).SetDefault()
	signer := jwss.MakeSigner()
	b, err := signer.UnSign(s)
	if err != nil {
		return nil, nil, err
	}
	h, payload, err := jwss.LoadPayload(b)
	header, _ := h.(map[string]interface{})
	if header["alg"].(string) != jwss.AlgorithmName {
		err = fmt.Errorf(`BadHeader: Algorithm mismatch, header:%v, payload=%v`, header, payload)
	}
	return header, payload, err
}

func (jwss JSONWebSignatureSerializer) TimedMakeHeader(headerfields map[string]interface{}) map[string]interface{} {
	header := jwss.MakeHeader(headerfields)
	iat := jwss.now()
	exp := iat + jwss.ExpiresIn
	header["iat"] = iat
	header["exp"] = exp
	return header
}

func (jwss JSONWebSignatureSerializer) TimedDumps(obj interface{}, args ...interface{}) ([]byte, error) {
	(&jwss).SetDefault()
	headerfields := map[string]interface{}{}
	if len(args) == 1 {
		headerfields, _ = args[0].(map[string]interface{})
		fmt.Println("get")
	}
	header := jwss.TimedMakeHeader(headerfields)
	return jwss.Dumps(obj, header)
}

func (jwss JSONWebSignatureSerializer) TimedLoads(s string) (map[string]interface{}, interface{}, error) {
	(&jwss).SetDefault()
	header, payload, err := jwss.Loads(s)
	if err != nil {
		return nil, payload, err
	}
	headers := header.(map[string]interface{})
	if ok := headers["exp"]; ok == nil {
		return headers, payload, fmt.Errorf("BadSignature-Missing expiry date")
	}

	IntDateError := fmt.Errorf(`BadHeader-Expiry date is not an IntDate, payload:%v`, payload)

	expfloat, ok := headers["exp"].(float64)
	if !ok {
		return headers, payload, IntDateError
	}
	exp := int64(expfloat)
	if exp < 0 {
		return headers, payload, IntDateError
	}

	if exp < jwss.now() {
		err := fmt.Errorf(`Signature expired, expired at %s`, jwss.GetIssueDate(exp))
		return headers, payload, err
	}
	return headers, payload, nil

}

func (jwss JSONWebSignatureSerializer) now() int64 {
	return time.Now().UTC().Unix()
}

func (jwss JSONWebSignatureSerializer) GetIssueDate(t int64) string {
	return fmt.Sprintf("%s", time.Unix(t, 0).UTC())
}
