package mtc

func validTrustAnchorIDBinary(input []byte) bool {
	if len(input) == 0 || len(input) > 255 {
		return false
	}
	componentStart := true
	for _, value := range input {
		if componentStart && value == 0x80 {
			return false
		}
		componentStart = value&0x80 == 0
	}
	return componentStart
}
