package mtctest

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	OIDMTCProof         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	OIDCAID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	OIDMTC_CA           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
	OIDMLDSA44          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)

type Algorithm struct {
	OID               asn1.ObjectIdentifier
	ParametersPresent bool
	Parameters        []byte
}

type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

type Template struct {
	Serial                 *big.Int
	TBSSignature           Algorithm
	OuterSignature         Algorithm
	Issuer                 []byte
	Subject                []byte
	NotBefore              time.Time
	NotAfter               time.Time
	SPKIAlgorithm          Algorithm
	SubjectPublicKey       []byte
	SubjectPublicKeyUnused int
	IssuerUniqueID         []byte
	IssuerUniqueIDUnused   int
	SubjectUniqueID        []byte
	SubjectUniqueIDUnused  int
	Extensions             []Extension
	Signature              []byte
	SignatureUnused        int
}

func ValidSubscriberTemplate() Template {
	return Template{
		Serial:           new(big.Int).SetUint64((1 << 48) | 7),
		TBSSignature:     Algorithm{OID: OIDMTCProof},
		OuterSignature:   Algorithm{OID: OIDMTCProof},
		Issuer:           ValidCAIDNameDER(),
		Subject:          der(0x30, nil),
		NotBefore:        time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC),
		NotAfter:         time.Date(2026, 7, 8, 8, 0, 0, 0, time.UTC),
		SPKIAlgorithm:    Algorithm{OID: OIDMLDSA44},
		SubjectPublicKey: bytes.Repeat([]byte{0x5a}, 32),
		Extensions: []Extension{
			{ID: OIDBasicConstraints, Critical: true, Value: der(0x30, nil)},
		},
		Signature: []byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0},
	}
}

func ValidCQRPSubscriberTemplate() Template {
	return ValidSubscriberTemplate()
}

func ValidCATemplate() Template {
	tpl := ValidSubscriberTemplate()
	tpl.Serial = big.NewInt(42)
	tpl.Subject = ValidCAIDNameDER()
	tpl.Extensions = []Extension{{
		ID:       OIDMTC_CA,
		Critical: true,
		Value:    ValidCAExtensionDER(),
	}}
	tpl.Signature = []byte{0x01, 0x02, 0x03}
	return tpl
}

func Certificate(tpl Template) []byte {
	return der(0x30,
		TBSCertificate(tpl),
		algorithmIdentifier(tpl.OuterSignature),
		bitString(tpl.Signature, tpl.SignatureUnused),
	)
}

func TBSCertificate(tpl Template) []byte {
	fields := [][]byte{
		der(0xa0, integer(big.NewInt(2))),
		integer(tpl.Serial),
		algorithmIdentifier(tpl.TBSSignature),
		clone(tpl.Issuer),
		validity(tpl.NotBefore, tpl.NotAfter),
		clone(tpl.Subject),
		der(0x30,
			algorithmIdentifier(tpl.SPKIAlgorithm),
			bitString(tpl.SubjectPublicKey, tpl.SubjectPublicKeyUnused),
		),
	}
	if tpl.IssuerUniqueID != nil {
		fields = append(fields, implicitBitString(0x81, tpl.IssuerUniqueID, tpl.IssuerUniqueIDUnused))
	}
	if tpl.SubjectUniqueID != nil {
		fields = append(fields, implicitBitString(0x82, tpl.SubjectUniqueID, tpl.SubjectUniqueIDUnused))
	}
	if tpl.Extensions != nil {
		encoded := make([][]byte, 0, len(tpl.Extensions))
		for _, ext := range tpl.Extensions {
			parts := [][]byte{mustMarshal(ext.ID)}
			if ext.Critical {
				parts = append(parts, []byte{0x01, 0x01, 0xff})
			}
			parts = append(parts, der(0x04, ext.Value))
			encoded = append(encoded, der(0x30, parts...))
		}
		fields = append(fields, der(0xa3, der(0x30, encoded...)))
	}
	return der(0x30, fields...)
}

func ValidCAIDNameDER() []byte {
	relativeOID := der(0x0d, []byte{0x88, 0x22, 0x38, 0x03})
	atv := der(0x30, mustMarshal(OIDCAID), relativeOID)
	return der(0x30, der(0x31, atv))
}

func ValidCAExtensionDER() []byte {
	return CAExtensionDER(
		Algorithm{OID: OIDSHA256},
		Algorithm{OID: OIDMLDSA65},
		big.NewInt(100),
		big.NewInt(999),
	)
}

func CAExtensionDER(logHash, signatureAlgorithm Algorithm, minSerial, maxSerial *big.Int) []byte {
	return der(0x30,
		algorithmIdentifier(logHash),
		algorithmIdentifier(signatureAlgorithm),
		integer(minSerial),
		integer(maxSerial),
	)
}

func WriteGeneratedFixtures(dir string) error {
	fixtures := []struct {
		name     string
		pemType  string
		contents []byte
	}{
		{"draft05-ca.pem", "CERTIFICATE", Certificate(ValidCATemplate())},
		{"draft05-subscriber-tbs.pem", "TBS CERTIFICATE", TBSCertificate(ValidSubscriberTemplate())},
		{"cqrp-subscriber.pem", "CERTIFICATE", Certificate(ValidCQRPSubscriberTemplate())},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, fixture := range fixtures {
		encoded := pem.EncodeToMemory(&pem.Block{Type: fixture.pemType, Bytes: fixture.contents})
		if err := os.WriteFile(filepath.Join(dir, fixture.name), encoded, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fixture.name, err)
		}
	}
	return nil
}

func algorithmIdentifier(algorithm Algorithm) []byte {
	parts := [][]byte{mustMarshal(algorithm.OID)}
	if algorithm.ParametersPresent {
		parts = append(parts, clone(algorithm.Parameters))
	}
	return der(0x30, parts...)
}

func validity(notBefore, notAfter time.Time) []byte {
	return der(0x30, mustMarshal(notBefore), mustMarshal(notAfter))
}

func integer(value *big.Int) []byte {
	if value == nil {
		panic("nil integer")
	}
	return mustMarshal(value)
}

func bitString(contents []byte, unused int) []byte {
	return der(0x03, append([]byte{byte(unused)}, contents...))
}

func implicitBitString(tag byte, contents []byte, unused int) []byte {
	return der(tag, append([]byte{byte(unused)}, contents...))
}

func der(tag byte, values ...[]byte) []byte {
	contents := bytes.Join(values, nil)
	return append(append([]byte{tag}, derLength(len(contents))...), contents...)
}

func derLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var encoded [8]byte
	i := len(encoded)
	for length > 0 {
		i--
		encoded[i] = byte(length)
		length >>= 8
	}
	return append([]byte{0x80 | byte(len(encoded)-i)}, encoded[i:]...)
}

func mustMarshal(value any) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func clone(input []byte) []byte {
	return append([]byte(nil), input...)
}
