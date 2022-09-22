package abeutil

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
)

func TestHexEncode(t *testing.T) {
	a := make([]byte, 3)
	a[0] = 64
	a[1] = 63
	a[2] = 255
	b := make([]byte, 3)
	b[0] = 9
	b[1] = 10
	b[2] = 11

	c := hex.EncodeToString(a)
	fmt.Println(c)
	c = c + hex.EncodeToString(b)
	fmt.Println(c)
}

func TestIntStr(t *testing.T) {
	a := 123

	b := "456" + strconv.Itoa(a)
	fmt.Println(b)
}
