package nakamotopowaconcagua

import (
	"fmt"
	"testing"
)

func TestShift(t *testing.T) {
	height := int32(1<<31 - 1)
	y := 1.0 * float64(height) * 256.0 / (3600.0 * 24.0 * 365.0)
	fmt.Printf("%x\n", height)
	fmt.Println(y)

	x := uint64(height) << 32
	fmt.Printf("%x\n", x)

	i := uint32(1<<30 - 1)
	NonceExt := uint64(height)<<32 | uint64(i)
	fmt.Printf("%x\n", NonceExt)

	Height := int32(NonceExt >> 32)
	fmt.Printf("%x\n", NonceExt)
	fmt.Printf("%x ; %d\n", Height, Height)

	nonce := uint32(NonceExt & 0x0000_0000_FFFF_FFFF)
	fmt.Printf("%x ; %d\n", nonce, nonce)

}

func TestConversion(t *testing.T) {
	height := int32(-1)
	nonce := uint32(100)
	a := uint64(height)<<32 | uint64(nonce)
	b := uint64(height)

	fmt.Printf("height: %d\n", height)
	fmt.Printf("a:%d\n", a)
	fmt.Printf("b:%d\n", b)
	fmt.Printf("b-a: %d\n", b-a)

	rnonce := int32(a)
	fmt.Printf("ar:%d\n", rnonce)
	rnoncep := int32(a & 0x0000_0000_FFFF_FFFF)
	fmt.Printf("rnoncep:%d\n", rnoncep)

	hnonce := int32(a >> 32)
	fmt.Printf("ar:%d\n", hnonce)
}
