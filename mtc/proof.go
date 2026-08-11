package mtc

import (
	"encoding/binary"
	"fmt"
)

// ProofTruncationError reports an MTCProof field whose complete encoded value
// was not present in the input.
type ProofTruncationError struct {
	Field     string
	Needed    int
	Available int
}

func (e *ProofTruncationError) Error() string {
	return fmt.Sprintf("truncated MTCProof %s: need %d bytes, have %d", e.Field, e.Needed, e.Available)
}

// ProofTrailingDataError reports bytes following a complete MTCProof.
type ProofTrailingDataError struct {
	Remaining int
}

func (e *ProofTrailingDataError) Error() string {
	return fmt.Sprintf("MTCProof has %d trailing bytes", e.Remaining)
}

// ParseProof decodes the TLS presentation-language encoding of an MTCProof.
// It intentionally performs only syntax parsing; canonical ordering, duplicate
// detection, and other semantic checks belong to the lint rules.
func ParseProof(input []byte) (*Proof, error) {
	reader := proofReader{remaining: input}
	extensionsBytes, err := reader.vector16("extensions")
	if err != nil {
		return nil, err
	}
	extensions, err := parseProofExtensions(extensionsBytes)
	if err != nil {
		return nil, err
	}
	start, err := reader.uint48("start")
	if err != nil {
		return nil, err
	}
	end, err := reader.uint48("end")
	if err != nil {
		return nil, err
	}
	inclusionProof, err := reader.vector16("inclusion_proof")
	if err != nil {
		return nil, err
	}
	signaturesBytes, err := reader.vector16("signatures")
	if err != nil {
		return nil, err
	}
	signatures, err := parseProofSignatures(signaturesBytes)
	if err != nil {
		return nil, err
	}
	if len(reader.remaining) != 0 {
		return nil, &ProofTrailingDataError{Remaining: len(reader.remaining)}
	}
	return &Proof{
		Extensions:     extensions,
		Start:          start,
		End:            end,
		InclusionProof: cloneProofBytes(inclusionProof),
		Signatures:     signatures,
	}, nil
}

func parseProofExtensions(input []byte) ([]EntryExtension, error) {
	reader := proofReader{remaining: input}
	var extensions []EntryExtension
	for len(reader.remaining) != 0 {
		typeBytes, err := reader.take(2, "extension type")
		if err != nil {
			return nil, err
		}
		data, err := reader.vector16("extension data")
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, EntryExtension{
			Type: binary.BigEndian.Uint16(typeBytes),
			Data: cloneProofBytes(data),
		})
	}
	return extensions, nil
}

func parseProofSignatures(input []byte) ([]MTCSignature, error) {
	reader := proofReader{remaining: input}
	var signatures []MTCSignature
	for len(reader.remaining) != 0 {
		idLength, err := reader.take(1, "cosigner ID length")
		if err != nil {
			return nil, err
		}
		cosignerID, err := reader.take(int(idLength[0]), "cosigner ID")
		if err != nil {
			return nil, err
		}
		signature, err := reader.vector16("signature")
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, MTCSignature{
			CosignerID: cloneProofBytes(cosignerID),
			Signature:  cloneProofBytes(signature),
		})
	}
	return signatures, nil
}

type proofReader struct {
	remaining []byte
}

func (r *proofReader) take(length int, field string) ([]byte, error) {
	if len(r.remaining) < length {
		return nil, &ProofTruncationError{Field: field, Needed: length, Available: len(r.remaining)}
	}
	value := r.remaining[:length]
	r.remaining = r.remaining[length:]
	return value, nil
}

func (r *proofReader) vector16(field string) ([]byte, error) {
	lengthBytes, err := r.take(2, field+" length")
	if err != nil {
		return nil, err
	}
	return r.take(int(binary.BigEndian.Uint16(lengthBytes)), field)
}

func (r *proofReader) uint48(field string) (uint64, error) {
	encoded, err := r.take(6, field)
	if err != nil {
		return 0, err
	}
	return uint64(encoded[0])<<40 |
		uint64(encoded[1])<<32 |
		uint64(encoded[2])<<24 |
		uint64(encoded[3])<<16 |
		uint64(encoded[4])<<8 |
		uint64(encoded[5]), nil
}

func cloneProofBytes(input []byte) []byte {
	return append([]byte(nil), input...)
}
