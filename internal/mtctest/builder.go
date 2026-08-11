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
	OIDMTCProof            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	OIDCAID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	OIDMTC_CA              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
	OIDMLDSA44             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	OIDHashMLDSA44         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 32}
	OIDHashMLDSA65         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 33}
	OIDHashMLDSA87         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 34}
	OIDRSAEncryption       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDUnsigned            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}
	OIDCommonName          = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDIssuerAltName       = asn1.ObjectIdentifier{2, 5, 29, 18}
	OIDCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	OIDExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDServerAuth          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	OIDSCTList             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	OIDOrganizationName    = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDCountryName         = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDPolicyDV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
	OIDPolicyOV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2}
	OIDPolicyIV            = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 3}
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

type ProofExtension struct {
	Type uint16
	Data []byte
}

type ProofSignature struct {
	CosignerID []byte
	Signature  []byte
}

type Proof struct {
	Extensions     []ProofExtension
	Start          uint64
	End            uint64
	InclusionProof []byte
	Signatures     []ProofSignature
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
		SubjectPublicKey: bytes.Repeat([]byte{0x5a}, 1312),
		Extensions: []Extension{
			{ID: OIDBasicConstraints, Critical: true, Value: der(0x30, nil)},
		},
		Signature: ProofBytes(ValidProof()),
	}
}

func ValidCQRPSubscriberTemplate() Template {
	tpl := ValidSubscriberTemplate()
	tpl.Extensions = append(tpl.Extensions,
		Extension{ID: OIDCertificatePolicies, Value: CertificatePoliciesDER(OIDPolicyDV)},
		Extension{ID: OIDExtendedKeyUsage, Value: ExtendedKeyUsageDER(OIDServerAuth)},
	)
	return tpl
}

func ValidCQRPCATemplate() Template {
	tpl := ValidCATemplate()
	tpl.SPKIAlgorithm = Algorithm{OID: OIDMLDSA44}
	return tpl
}

func ValidProof() Proof {
	return Proof{Start: 0, End: 8}
}

func ProofBytes(proof Proof) []byte {
	var extensions bytes.Buffer
	for _, extension := range proof.Extensions {
		writeUint16(&extensions, extension.Type)
		writeVector16(&extensions, extension.Data)
	}

	var signatures bytes.Buffer
	for _, signature := range proof.Signatures {
		if len(signature.CosignerID) > 255 {
			panic("cosigner ID exceeds uint8 length")
		}
		signatures.WriteByte(byte(len(signature.CosignerID)))
		signatures.Write(signature.CosignerID)
		writeVector16(&signatures, signature.Signature)
	}

	var encoded bytes.Buffer
	writeVector16(&encoded, extensions.Bytes())
	writeUint48(&encoded, proof.Start)
	writeUint48(&encoded, proof.End)
	writeVector16(&encoded, proof.InclusionProof)
	writeVector16(&encoded, signatures.Bytes())
	return encoded.Bytes()
}

func MalformedProofBytes() []byte {
	valid := ProofBytes(ValidProof())
	return clone(valid[:len(valid)-1])
}

func ValidCATemplate() Template {
	tpl := ValidSubscriberTemplate()
	tpl.Serial = big.NewInt(42)
	tpl.TBSSignature = Algorithm{OID: OIDMLDSA65}
	tpl.OuterSignature = Algorithm{OID: OIDMLDSA65}
	tpl.Issuer = der(0x30, nil)
	tpl.Subject = ValidCAIDNameDER()
	tpl.Extensions = []Extension{
		{ID: OIDMTC_CA, Critical: true, Value: ValidCAExtensionDER()},
		{ID: OIDKeyUsage, Critical: true, Value: KeyUsageDER(true)},
		{ID: OIDBasicConstraints, Critical: true, Value: BasicConstraintsDER(true)},
	}
	tpl.Signature = []byte{0x01, 0x02, 0x03}
	return tpl
}

func ValidUnsignedCATemplate() Template {
	tpl := ValidCATemplate()
	tpl.TBSSignature = Algorithm{OID: OIDUnsigned}
	tpl.OuterSignature = Algorithm{OID: OIDUnsigned}
	tpl.Issuer = clone(tpl.Subject)
	tpl.Signature = nil
	return tpl
}

func ReplaceExtension(tpl *Template, extension Extension) {
	for i := range tpl.Extensions {
		if tpl.Extensions[i].ID.Equal(extension.ID) {
			tpl.Extensions[i] = extension
			return
		}
	}
	tpl.Extensions = append(tpl.Extensions, extension)
}

func RemoveExtension(tpl *Template, id asn1.ObjectIdentifier) {
	filtered := tpl.Extensions[:0]
	for _, extension := range tpl.Extensions {
		if !extension.ID.Equal(id) {
			filtered = append(filtered, extension)
		}
	}
	tpl.Extensions = filtered
}

func KeyUsageDER(keyCertSign bool) []byte {
	bits := byte(0x80)
	if keyCertSign {
		bits |= 0x04
	}
	return bitString([]byte{bits}, 2)
}

func BasicConstraintsDER(ca bool) []byte {
	if !ca {
		return der(0x30, nil)
	}
	return der(0x30, []byte{0x01, 0x01, 0xff})
}

func SubjectKeyIdentifierDER(id []byte) []byte {
	return der(0x04, clone(id))
}

func CertificatePoliciesDER(ids ...asn1.ObjectIdentifier) []byte {
	policies := make([][]byte, 0, len(ids))
	for _, id := range ids {
		policies = append(policies, der(0x30, mustMarshal(id)))
	}
	return der(0x30, policies...)
}

func ExtendedKeyUsageDER(ids ...asn1.ObjectIdentifier) []byte {
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		encoded = append(encoded, mustMarshal(id))
	}
	return der(0x30, encoded...)
}

type NameAttribute struct {
	ID       asn1.ObjectIdentifier
	Value    string
	RawValue []byte
}

func NameDER(attributes ...NameAttribute) []byte {
	rdns := make([][]byte, 0, len(attributes))
	for _, attribute := range attributes {
		value := attribute.RawValue
		if value == nil {
			value = mustMarshal(attribute.Value)
		}
		atv := der(0x30, mustMarshal(attribute.ID), value)
		rdns = append(rdns, der(0x31, atv))
	}
	return der(0x30, rdns...)
}

func DirectoryNameGeneralNameDER(name []byte) []byte {
	return der(0xa4, clone(name))
}

func GeneralNamesDER(names ...[]byte) []byte {
	return der(0x30, names...)
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
	relativeOID := der(0x0d, ValidCAID())
	atv := der(0x30, mustMarshal(OIDCAID), relativeOID)
	return der(0x30, der(0x31, atv))
}

func ValidCAID() []byte {
	return []byte{0x88, 0x22, 0x38, 0x03}
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

func writeVector16(output *bytes.Buffer, contents []byte) {
	if len(contents) > 65535 {
		panic("vector exceeds uint16 length")
	}
	writeUint16(output, uint16(len(contents)))
	output.Write(contents)
}

func writeUint16(output *bytes.Buffer, value uint16) {
	output.WriteByte(byte(value >> 8))
	output.WriteByte(byte(value))
}

func writeUint48(output *bytes.Buffer, value uint64) {
	if value > (1<<48)-1 {
		panic("value exceeds uint48")
	}
	output.Write([]byte{
		byte(value >> 40),
		byte(value >> 32),
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}
