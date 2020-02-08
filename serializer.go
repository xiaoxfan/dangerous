package dangerous

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"strings"
)

var (
	Sep                      = []byte(".")
	default_fallback_signers = []map[string]interface{}{{"DigestMethod": sha512.New}}
)

type Serializer struct {
	Secret          string
	Salt            string
	SerializerOP    JsonAPI // Can override it becomes easier
	Signer          Signer
	Signerkwargs    map[string]interface{}
	FallbackSigners []map[string]interface{}
}

func (self *Serializer) SetDefault() {
	if self.Secret == "" {
		panic("Secret is necessary")
	}
	if self.Salt == "" {
		self.Salt = "itsdangerous"
	}
	if self.SerializerOP == nil {
		self.SerializerOP = Json{}
	}
	if self.Signer.Secret == "" {
		self.Signer = Signer{Secret: self.Secret, Salt: self.Salt}
	}
	ApplyKwargs(&self.Signer, self.Signerkwargs)
	if len(self.FallbackSigners) == 0 {
		self.FallbackSigners = default_fallback_signers
	}

}

func (self Serializer) LoadPayload(payload []byte) (interface{}, error) {
	return self.SerializerOP.Load(payload)
}

func (self Serializer) DumpPayload(vx interface{}) (string, error) {
	return self.SerializerOP.Dump(vx)
}

func (self Serializer) IterUnSigners() []interface{} {
	allfallback := make([]interface{}, len(self.FallbackSigners)+1)
	allfallback[0] = self.Signer
	for p, kw := range self.FallbackSigners {
		fallback := self.Signer
		ApplyKwargs(&fallback, kw)
		allfallback[p+1] = fallback
	}
	return allfallback
}

func (self Serializer) PreDumps(objx interface{}, dumpfunc func(interface{}, interface{}) (string, error)) ([]byte, error) {
	(&self).SetDefault()
	payload_dump, err := dumpfunc(objx, self.SerializerOP)
	rv := self.Signer.Sign(payload_dump)
	return rv, err
}

func (self Serializer) PreLoads(s string, loadfunc func([]byte, interface{}) (interface{}, error)) (interface{}, error) {
	(&self).SetDefault()
	var _err error
	var _result interface{}
	for _, signer := range self.IterUnSigners() {
		unsiged, err := signer.(Signer).UnSign(s)
		if err != nil {
			continue
		}
		result, err := loadfunc(unsiged, self.SerializerOP)
		_result = result
		_err = err
	}
	return _result, _err
}

func (self Serializer) PreTimedDumps(objx interface{}, dumpfunc func(interface{}, interface{}) (string, error)) ([]byte, error) {
	(&self).SetDefault()
	payload_dump, err := dumpfunc(objx, self.SerializerOP)
	rv := self.Signer.SignTimestamp(payload_dump)
	return rv, err
}

// totally different from function `PreLoads`
func (self Serializer) PreTimedLoads(s string, max_age int64, loadfunc func([]byte, interface{}) (interface{}, error)) (interface{}, error) {
	(&self).SetDefault()
	var _payload interface{}
	var _err error
	for _, signer := range self.IterUnSigners() {
		base64d, _, err := signer.(Signer).UnSignTimestamp(s, max_age)
		_err = err
		if err != nil && !strings.Contains(err.Error(), "BadTimeSignature") && !strings.Contains(err.Error(), "SignatureExpired") {

			continue
		}
		payload, err_load := loadfunc(base64d, self.SerializerOP)
		_payload = payload
		if err_load != nil {
			_err = fmt.Errorf("%s AND %s", err.Error(), err_load.Error())
		}
		break
	}
	return _payload, _err

}

func (self Serializer) Dumps(objx interface{}) ([]byte, error) {
	return self.PreDumps(objx, DumpPayload)
}

func (self Serializer) Loads(s string) (interface{}, error) {
	return self.PreLoads(s, LoadPayload)
}

func (self Serializer) TimedDumps(objx interface{}) ([]byte, error) {
	return self.PreTimedDumps(objx, DumpPayload)
}

func (self Serializer) TimedLoads(s string, max_age int64) (interface{}, error) {
	return self.PreTimedLoads(s, max_age, LoadPayload)
}

func (self Serializer) URLSafeDumps(objx interface{}) ([]byte, error) {
	return self.PreDumps(objx, URLSafeDumpPayload)
}

func (self Serializer) URLSafeLoads(s string) (interface{}, error) {
	return self.PreLoads(s, URLSafeLoadPayload)
}

func (self Serializer) URLSafeTimedDumps(objx interface{}) ([]byte, error) {
	return self.PreTimedDumps(objx, URLSafeDumpPayload)
}

func (self Serializer) URLSafeTimedLoads(s string, max_age int64) (interface{}, error) {
	return self.PreTimedLoads(s, max_age, URLSafeLoadPayload)
}

/*-------------------------------------------------------------------------------*/
// Payload functions
// Ordinary
func LoadPayload(payload []byte, api interface{}) (interface{}, error) {
	data, err := api.(JsonAPI).Load(payload)
	if err != nil {
		err = fmt.Errorf("BadPayload-Could not load the payload because an exception"+
			" occurred on unserializing the data. origin error=`%s`", err)
	}
	return data, err
}

func DumpPayload(vx interface{}, api interface{}) (string, error) {
	return api.(JsonAPI).Dump(vx)
}

// URLSafe
func PreURLSafeLoadPayload(payload []byte) ([]byte, error) {
	decompress := false
	if bytes.HasPrefix(payload, Sep) {
		payload = payload[1:]
		decompress = true
	}
	_json, err := B64decode(payload)
	if err != nil {
		return _json, fmt.Errorf("Could not base64 decode the payload because of an exception, original_error=%s", err)
	}
	if decompress {
		_json, err = UnCompress(_json)
	}
	return _json, err
}

func PreURLSafeDumpPayload(_json []byte) ([]byte, error) {
	var err error
	is_compressed := false
	compressed := Compress(_json)
	if len(compressed) < (len(_json) - 1) {
		_json = compressed
		is_compressed = true
	}
	base64d := WantBytes(B64encode(_json))
	if is_compressed {
		base64d, err = Concentrate(Sep, base64d)
	}
	return base64d, err

}

func URLSafeLoadPayload(payload []byte, api interface{}) (interface{}, error) {
	data, err := PreURLSafeLoadPayload(payload)
	if err != nil {
		return data, err
	}
	return LoadPayload(data, api)
}

func URLSafeDumpPayload(obj interface{}, api interface{}) (string, error) {
	str, err := DumpPayload(obj, api)
	_byte := WantBytes(str)
	if err != nil {
		return str, err
	}
	result, err := PreURLSafeDumpPayload(_byte)
	return string(result), err
}
