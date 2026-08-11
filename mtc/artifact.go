package mtc

import (
	"encoding/asn1"
	"math/big"
	"time"
)

type InputKind uint8

const (
	InputCertificate InputKind = iota + 1
	InputTBSCertificate
)

type ArtifactKind uint8

const (
	ArtifactUnknown ArtifactKind = iota
	ArtifactCA
	ArtifactSubscriber
)

type AlgorithmIdentifier struct {
	Raw               []byte
	Algorithm         asn1.ObjectIdentifier
	ParametersPresent bool
	Parameters        asn1.RawValue
}

type SubjectPublicKeyInfo struct {
	Raw              []byte
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey []byte
	UnusedBits       int
}

type Extension struct {
	Raw      []byte
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

type EntryExtension struct {
	Type uint16
	Data []byte
}

type MTCSignature struct {
	CosignerID []byte
	Signature  []byte
}

type Proof struct {
	Extensions     []EntryExtension
	Start          uint64
	End            uint64
	InclusionProof []byte
	Signatures     []MTCSignature
}

type Artifact struct {
	InputKind              InputKind
	Kind                   ArtifactKind
	Raw                    []byte
	RawTBS                 []byte
	SerialNumber           *big.Int
	TBSSignature           AlgorithmIdentifier
	OuterSignature         *AlgorithmIdentifier
	SignatureValue         []byte
	SignatureUnused        int
	IssuerRaw              []byte
	SubjectRaw             []byte
	NotBefore              time.Time
	NotAfter               time.Time
	IssuerUniqueIDPresent  bool
	SubjectUniqueIDPresent bool
	SubjectPublicKey       SubjectPublicKeyInfo
	Extensions             []Extension
	SubjectCAID            []byte
	IssuerCAID             []byte
	CAParameters           *CertificationAuthority
	CAExtensionError       error
	Proof                  *Proof
	ProofParseError        error
}

type CertificationAuthority struct {
	LogHash            AlgorithmIdentifier
	SignatureAlgorithm AlgorithmIdentifier
	MinSerial          *big.Int
	MaxSerial          *big.Int
}
