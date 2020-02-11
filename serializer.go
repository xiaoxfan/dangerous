package dangerous

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"strings"
)

var (
	Sep                    = []byte(".")
	DefaultFallbackSigners = []map[string]interface{}{{"DigestMethod": sha512.New}}
)

type Serializer struct {
	Secret          string
	Salt            string
	SerializerOP    JSONAPI // Can override it becomes easier
	Signer          Signer
	Signerkwargs    map[string]interface{}
	FallbackSigners []map[string]interface{}
}

func (ser *Serializer) SetDefault() {
	if ser.Secret == "" {
		panic("Secret is necessary")
	}
	if ser.Salt == "" {
		ser.Salt = "itsdangerous"
	}
	if ser.SerializerOP == nil {
		ser.SerializerOP = JSON{}
	}
	if ser.Signer.Secret == "" {
		ser.Signer = Signer{Secret: ser.Secret, Salt: ser.Salt}
	}
	ApplyKwargs(&ser.Signer, ser.Signerkwargs)
	if len(ser.FallbackSigners) == 0 {
		ser.FallbackSigners = DefaultFallbackSigners
	}

}

func (ser Serializer) LoadPayload(payload []byte) (interface{}, error) {
	return ser.SerializerOP.Load(payload)
}

func (ser Serializer) DumpPayload(vx interface{}) (string, error) {
	return ser.SerializerOP.Dump(vx)
}

func (ser Serializer) IterUnSigners() []interface{} {
	allfallback := make([]interface{}, len(ser.FallbackSigners)+1)
	allfallback[0] = ser.Signer
	for p, kw := range ser.FallbackSigners {
		fallback := ser.Signer
		ApplyKwargs(&fallback, kw)
		allfallback[p+1] = fallback
	}
	return allfallback
}

func (ser Serializer) PreDumps(objx interface{}, dumpfunc func(interface{}, interface{}) (string, error)) ([]byte, error) {
	(&ser).SetDefault()
	PayloadDump, err := dumpfunc(objx, ser.SerializerOP)
	rv := ser.Signer.Sign(PayloadDump)
	return rv, err
}

func (ser Serializer) PreLoads(s string, loadfunc func([]byte, interface{}) (interface{}, error)) (interface{}, error) {
	(&ser).SetDefault()
	var _err error
	var _result interface{}
	for _, signer := range ser.IterUnSigners() {
		unsiged, err := signer.(Signer).UnSign(s)
		_err = err
		if _err != nil {
			continue
		}
		result, err := loadfunc(unsiged, ser.SerializerOP)
		_result = result
		_err = err
		break
	}
	return _result, _err
}

func (ser Serializer) PreTimedDumps(objx interface{}, dumpfunc func(interface{}, interface{}) (string, error)) ([]byte, error) {
	(&ser).SetDefault()
	PayloadDump, err := dumpfunc(objx, ser.SerializerOP)
	rv := ser.Signer.SignTimestamp(PayloadDump)
	return rv, err
}

// totally different from function `PreLoads`

func (ser Serializer) PreTimedLoads(s string, MaxAge int64, loadfunc func([]byte, interface{}) (interface{}, error)) (interface{}, error) {
	(&ser).SetDefault()
	var _payload interface{}
	var _err error
	for _, signer := range ser.IterUnSigners() {
		base64d, _, err := signer.(Signer).UnSignTimestamp(s, MaxAge)
		_err = err
		if err != nil && !strings.Contains(err.Error(), "BadTimeSignature") && !strings.Contains(err.Error(), "SignatureExpired") {
			continue
		}
		payload, errload := loadfunc(base64d, ser.SerializerOP)
		_payload = payload
		if errload != nil {
			_err = fmt.Errorf("%s AND %s", err.Error(), errload.Error())
		}
		break
	}
	return _payload, _err

}

func (ser Serializer) Dumps(objx interface{}) ([]byte, error) {
	return ser.PreDumps(objx, DumpPayload)
}

func (ser Serializer) Loads(s string) (interface{}, error) {
	return ser.PreLoads(s, LoadPayload)
}

func (ser Serializer) TimedDumps(objx interface{}) ([]byte, error) {
	return ser.PreTimedDumps(objx, DumpPayload)
}

func (ser Serializer) TimedLoads(s string, MaxAge int64) (interface{}, error) {
	return ser.PreTimedLoads(s, MaxAge, LoadPayload)
}

func (ser Serializer) URLSafeDumps(objx interface{}) ([]byte, error) {
	return ser.PreDumps(objx, URLSafeDumpPayload)
}

func (ser Serializer) URLSafeLoads(s string) (interface{}, error) {
	return ser.PreLoads(s, URLSafeLoadPayload)
}

func (ser Serializer) URLSafeTimedDumps(objx interface{}) ([]byte, error) {
	return ser.PreTimedDumps(objx, URLSafeDumpPayload)
}

func (ser Serializer) URLSafeTimedLoads(s string, MaxAge int64) (interface{}, error) {
	return ser.PreTimedLoads(s, MaxAge, URLSafeLoadPayload)
}

/*-------------------------------------------------------------------------------*/
// Payload functions
// Ordinary

func LoadPayload(payload []byte, api interface{}) (interface{}, error) {
	data, err := api.(JSONAPI).Load(payload)
	if err != nil {
		err = fmt.Errorf("BadPayload-Could not load the payload because an exception"+
			" occurred on unserializing the data. origin error=`%s`", err)
	}
	return data, err
}

func DumpPayload(vx interface{}, api interface{}) (string, error) {
	return api.(JSONAPI).Dump(vx)
}

// URLSafe

func PreURLSafeLoadPayload(payload []byte) ([]byte, error) {
	decompress := false
	if bytes.HasPrefix(payload, Sep) {
		payload = payload[1:]
		decompress = true
	}
	JSONPayload, err := B64decode(payload)
	if err != nil {
		return JSONPayload, fmt.Errorf("Could not base64 decode the payload because of an exception, original_error=%s", err)
	}
	if decompress {
		JSONPayload, err = UnCompress(JSONPayload)
	}
	return JSONPayload, err
}

func PreURLSafeDumpPayload(JSONPayload []byte) ([]byte, error) {
	var err error
	IsCompressed := false
	compressed := Compress(JSONPayload)
	if len(compressed) < (len(JSONPayload) - 1) {
		JSONPayload = compressed
		IsCompressed = true
	}
	base64d := WantBytes(B64encode(JSONPayload))
	if IsCompressed {
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
