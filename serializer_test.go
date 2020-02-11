package dangerous

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"testing"
	"time"
)

var (
	serializer = Serializer{Secret: "secret_key"}
)

func TestSerializer(t *testing.T) {
	dump, err := serializer.Dumps(value)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if load, err := serializer.Loads(string(dump)); load.(string) != value || err != nil {
		t.Fatalf("Loading failed. Error:%s", err)
	}
}

func TestChangedValue(t *testing.T) {
	type funcstring func(s string) string
	for _, _func := range []funcstring{
		func(s string) string { return strings.ToUpper(s) },
		func(s string) string { return s + "a" },
		func(s string) string { return s + s[1:] },
		func(s string) string { return strings.Replace(s, ".", "", -1) },
	} {
		signed, _ := serializer.Dumps(value)
		if load, err := serializer.Loads(string(signed)); load.(string) != value || err != nil {
			t.Fatalf("Loading failed. Error:%s", err)
		}
		changed := _func(string(signed))
		if _, err := serializer.Loads(changed); !strings.Contains(err.Error(), "BadSignature") {
			t.Fatalf("Loading failed, because of unexpected error:%s. Expected:BadSignature.", err.Error())
		}
	}
}

func TestBadSignatureException(t *testing.T) {
	dump, _ := serializer.Dumps(value)
	bad_signed := dump[:len(dump)-1]
	if _, err := serializer.Loads(string(bad_signed)); !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf("Loading failed, because of unexpected error:`%s`. Expected:BadSignature.", err.Error())
	}
}

func TestBadPayloadException(t *testing.T) {
	original, _ := serializer.Dumps(value)
	payload, _ := RSplit(original, []byte("."))
	bad := Signer{Secret: "secret_key", Salt: "itsdangerous"}.Sign(string(payload[:len(payload)-1]))
	if _, err := serializer.Loads(string(bad)); !strings.Contains(err.Error(), "BadPayload") {
		t.Fatalf("Test_bad_payload_exception failed, because of unexpected error.")
	}
}

func TestAltSalt(t *testing.T) {
	serializer.Salt = "fresh"
	original, _ := serializer.Dumps("123")

	if _, err := serializer.Loads(string(original)); err != nil {
		t.Fatalf(err.Error())
	}

	serializer.Salt = "changed"
	if _, err := serializer.Loads(string(original)); !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf(err.Error())
	}
	serializer.Salt = ""
}

func TestSignerKwargs(t *testing.T) {
	_ser := Serializer{Secret: "secret_key", Signerkwargs: map[string]interface{}{"KeyDerivation": "hmac"}}
	dump, err := _ser.Dumps(value)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if load, err := _ser.Loads(string(dump)); load.(string) != value || err != nil {
		t.Fatalf("Loading failed. Error:%s", err.Error())
	}
	dump2, err2 := serializer.Dumps(value)
	if err2 != nil {
		t.Fatalf(err2.Error())
	}
	if bytes.Equal(dump, dump2) {
		t.Fatalf("Can not be the same value.")
	}
}

func TestFallbackSigners(t *testing.T) {
	serializer := Serializer{Secret: "secret_key",
		Signerkwargs: map[string]interface{}{"DigestMethod": sha256.New},
	}

	dump, _ := serializer.Dumps(value)

	serializer2 := Serializer{Secret: "secret_key",
		Signerkwargs:    map[string]interface{}{"DigestMethod": sha1.New},
		FallbackSigners: []map[string]interface{}{{"DigestMethod": sha256.New}},
	}

	dump2, err2 := serializer2.Loads(string(dump))
	if err2 != nil {
		t.Fatalf(err2.Error())
	}
	if dump2.(string) != value {
		t.Fatalf("Should be the same value.")
	}
}

func TestDigests(t *testing.T) {
	factory := Serializer{Secret: "dev key", Salt: "dev salt"}
	default_value, _ := factory.Dumps([]int{42})

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha1.New}
	sha1_value, _ := factory.Dumps([]int{42})

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha256.New}
	sha256_value, _ := factory.Dumps([]int{42})

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha512.New}
	sha512_value, _ := factory.Dumps([]int{42})

	if !bytes.Equal(default_value, sha256_value) {
		t.Fatalf("default_value does not equal to sha256_value.")
	}
	if !bytes.Equal(sha1_value, []byte("[42].-9cNi0CxsSB3hZPNCe9a2eEs1ZM")) {
		t.Fatalf("sha1_value does not equal to `[42].-9cNi0CxsSB3hZPNCe9a2eEs1ZM`.")
	}
	if !bytes.Equal(sha256_value, []byte("[42].u5jm88LwiD3aYOixoxwYUWacbKYcSnVL8cnS-4lgb4U")) {
		t.Fatalf("sha256_value does not equal to `[42].u5jm88LwiD3aYOixoxwYUWacbKYcSnVL8cnS-4lgb4U`.")
	}
	if !bytes.Equal(sha512_value, []byte("[42].MKCz_0nXQqv7wKpfHZcRtJRmpT2T5uvs9YQsJEhJimqxc9bCLxG31QzS5uC8OVBI1i6jyOLAFNoKaF5ckO9L5Q")) {
		t.Fatalf("sha512_value does not equal to `[42].MKCz_0nXQqv7wKpfHZcRtJRmpT2T5uvs9YQsJEhJimqxc9bCLxG31QzS5uC8OVBI1i6jyOLAFNoKaF5ckO9L5Q`.")
	}
}

// Timed
func TestMaxAge(t *testing.T) {
	signed, _ := serializer.TimedDumps(value)
	_, err := serializer.TimedLoads(string(signed), 10)
	if err != nil {
		t.Fatalf("Unexpected error occurred when loads data. Error:%s", err)
	}
	time.Sleep(2 * time.Second)
	payload, err2 := serializer.TimedLoads(string(signed), 1)
	if err2 == nil {
		t.Fatalf("Load failed. Did not receive expected error.")
	}
	if payload.(string) != value {
		t.Fatalf("Load failed. Unexpected payload.")
	}

}

func TestTimedDigests(t *testing.T) {
	tser := Serializer{Secret: "dev key", Salt: "dev salt"}
	tryload := `"value".Xjq_FQ._7SrxmrHFESAmzLxOP73vbITuxL0BnWaZJoj8Pxaux8`
	payload, err := tser.TimedLoads(tryload, 0)
	if payload.(string) != value || !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Load failed. Unexpected payload.")
	}

	tryload = `"value".Xjq_FQ._7SrxmrHFESAmzLxOP73vbITuxL0BnWaZJoj8Px1234`
	payload, err = tser.TimedLoads(tryload, 0)
	if payload != nil || !strings.Contains(err.Error(), "BadSignature") {
		t.Fatalf("Load failed. Unexpected payload.")
	}

	tryload = `"value".XjrAxA.rejDXOq0ijt9SyqWvx7onhYyFF4hJlqhYU2vjOTE5l8gKyQwKq8XAw8r8cJp6T7_P1594Ckk1oLlwelVsgxbTQ`
	tser.Signerkwargs = map[string]interface{}{"DigestMethod": sha512.New}
	payload, err = tser.TimedLoads(tryload, 0)
	if payload.(string) != value || !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Load failed. Unexpected payload.")
	}

}

// Url
func TestUrlDigests(t *testing.T) {
	factory := Serializer{Secret: "dev key", Salt: "dev salt"}
	default_value, _ := factory.URLSafeDumps(value)

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha1.New}
	sha1_value, _ := factory.URLSafeDumps(value)

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha256.New}
	sha256_value, _ := factory.URLSafeDumps(value)

	factory.Signerkwargs = map[string]interface{}{"DigestMethod": sha512.New}
	sha512_value, _ := factory.URLSafeDumps(value)

	if !bytes.Equal(default_value, sha256_value) {
		t.Fatalf("default_value does not equal to sha256_value.")
	}
	if !bytes.Equal(sha1_value, []byte("InZhbHVlIg.zsqEp7ga91kJ6rH3MKOepF1Iv9s")) {
		t.Fatalf("sha1_value does not equal to `InZhbHVlIg.zsqEp7ga91kJ6rH3MKOepF1Iv9s`.")
	}
	if !bytes.Equal(sha256_value, []byte("InZhbHVlIg.lv0F8SGBCKGZEZthKqM09WDDjfZPdmMprb0VrkLerE4")) {
		t.Fatalf("sha256_value does not equal to `InZhbHVlIg.lv0F8SGBCKGZEZthKqM09WDDjfZPdmMprb0VrkLerE4`.")
	}
	if !bytes.Equal(sha512_value, []byte("InZhbHVlIg.0yf-GPdnwCJD-e3Ies-TMi6JlI0nb4lHaogQzcWNIR7iRZ8C-xus35bkrbh4VvzdBK2_gN8Pcqda6ONNwUQXHw")) {
		t.Fatalf("sha512_value does not equal to `InZhbHVlIg.0yf-GPdnwCJD-e3Ies-TMi6JlI0nb4lHaogQzcWNIR7iRZ8C-xus35bkrbh4VvzdBK2_gN8Pcqda6ONNwUQXHw`.")
	}
	// InZhbHVlIg.zsqEp7ga91kJ6rH3MKOepF1Iv9s sha1
	// InZhbHVlIg.lv0F8SGBCKGZEZthKqM09WDDjfZPdmMprb0VrkLerE4 sha256
	// InZhbHVlIg.0yf-GPdnwCJD-e3Ies-TMi6JlI0nb4lHaogQzcWNIR7iRZ8C-xus35bkrbh4VvzdBK2_gN8Pcqda6ONNwUQXHw sha512
}

func TestTimedurlDigests(t *testing.T) {
	tser := Serializer{Secret: "dev key", Salt: "dev salt"}

	tryload := `InZhbHVlIg.Xjz2MQ.jMZtbnQCgTRbNpCOwQfOq6GW2qM`
	tser.Signerkwargs = map[string]interface{}{"DigestMethod": sha1.New}
	payload, err := tser.URLSafeTimedLoads(tryload, 0)
	if payload.(string) != value || !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Load failed. Unexpected payload or error.")
	}

	tryload = `InZhbHVlIg.Xjz2JQ.L0cc1AQhoRx5efnPBu6gXwaYV0Onr5Rm_wFRjdDWJeg`
	tser.Signerkwargs = map[string]interface{}{"DigestMethod": sha256.New}
	payload, err = tser.URLSafeTimedLoads(tryload, 0)
	if payload.(string) != value || !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Load failed. Unexpected payload or error.")
	}

	tryload = `InZhbHVlIg.Xjz14A.w69pHzxjZFMg6j8459Dqy-3GqryhHCNrhEW9oFs-cnBNcjyOM_a-y9cmHuMeReXYyxuzFYl8XjJ5xEt1hJqQ2Q`
	tser.Signerkwargs = map[string]interface{}{"DigestMethod": sha512.New}
	payload, err = tser.URLSafeTimedLoads(tryload, 0)
	if payload.(string) != value || !strings.Contains(err.Error(), "SignatureExpired") {
		t.Fatalf("Load failed. Unexpected payload or error.")
	}

}
