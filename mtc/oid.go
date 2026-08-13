package mtc

import "encoding/asn1"

var (
	OIDMTCProof                  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 0}
	OIDCAID                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	OIDMTCCertificationAuthority = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}
	OIDMTCTlogPrefixURL          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 1}
	OIDSHA256                    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDMLDSA44                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDSA65                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLDSA87                   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
	OIDHashMLDSA44               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 32}
	OIDHashMLDSA65               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 33}
	OIDHashMLDSA87               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 34}
)
