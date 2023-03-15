package v1

import (
	"fmt"
	"testing"
)

func TestAddress(t *testing.T) {
	seed, err := CryptoAddressKeySeedGen()
	if err != nil {
		fmt.Sprint(err)
		return
	}
	fmt.Println("AddressKeySeed:", seed)

}
