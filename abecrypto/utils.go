package abecrypto

import "crypto/rand"

// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)

	neededLen := length
	var tmp []byte
	for neededLen > 0 {
		tmp = make([]byte, neededLen)
		// n == len(b) if and only if err == nil.
		n, err := rand.Read(tmp)
		if err != nil {
			continue
		}
		res = append(res, tmp[:n]...)
		neededLen -= n
	}
	return res
}
