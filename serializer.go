package dangerous

import (
	"crypto/sha512"
	"github.com/imdario/mergo"
)

var default_fallback_signers = []Signer{Signer{DigestMethod: sha512.New}} // TODO use dict!

type Serializer struct {
	Secret          string
	Salt            string
	SerializerOP    JsonAPI
	Signer          Signer // SignerAPI
	Signerkwargs    map[string]interface{}
	FallbackSigners []Signer // want to pass value to signer // TODO make it more flexible, simple
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
		self.Signer = Signer{Secret: self.Secret,
			Salt: self.Salt}
	}
	if self.FallbackSigners == nil {
		self.FallbackSigners = default_fallback_signers
	}

}

func (self Serializer) LoadPayload(payload []byte) (interface{}, error) { // TODO add more error
	return self.SerializerOP.Load(payload)
	// if err: "Could not load the payload because an exception"
	//" occurred on unserializing the data."
}

func (self Serializer) DumpPayload(vx interface{}) []byte {
	strs, _ := self.SerializerOP.Dump(vx)
	return WantBytes(strs)
}

func (self Serializer) IterUnSigners() []interface{} {
	// TODO: channel generator https://blog.carlmjohnson.net/post/on-using-go-channels-like-python-generators/
	allfallback := make([]interface{}, len(self.FallbackSigners)+1)
	allfallback[0] = self.Signer
	for p, signer := range self.FallbackSigners {
		fallback := self.Signer
		mergo.Merge(&fallback, signer)
		allfallback[p+1] = fallback
	}
	return allfallback
}

func (self Serializer) Dumps(objx interface{}) []byte {
	(&self).SetDefault()
	payload_dump := self.DumpPayload(objx)
	rv := self.Signer.Sign(string(payload_dump)) // TODO change sign to byte param
	return rv
}

func (self Serializer) Loads(s string) (interface{}, error) {
	(&self).SetDefault()
	sx := WantBytes(s)
	var err error
	var by []byte
	var result interface{}
	for _, signer := range self.IterUnSigners() {
		by, err = signer.(SignerAPI).UnSign(string(sx)) // TODO change param to byte
		if err != nil {
			return result, err
		}
		result, err = self.LoadPayload(by)
		if err != nil {
			return result, err
		}
	}
	return result, err
}
