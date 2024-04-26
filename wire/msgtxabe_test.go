package wire

import (
	"fmt"
	"testing"

	"github.com/abesuite/abec/chainhash"
)

func TestOutPointAbe_OutPointId(t *testing.T) {
	randomByte := []byte("test")
	txHash := chainhash.DoubleHashH(randomByte)
	Index := uint8(0)

	op := &OutPointAbe{TxHash: txHash, Index: Index}
	fmt.Println(op)

	fmt.Println(op.TxHash[:])
	fmt.Println(op.Index)
	fmt.Println(op.OutPointId())
	fmt.Println(op.OutPointId())
}

func TestRingId(t *testing.T) {
	randomByte := []byte("test")
	hash := chainhash.DoubleHashH(randomByte)

	ringMap := make(map[RingId]int)
	ringMap[RingId(hash)] = 1

	hash2 := chainhash.DoubleHashH(randomByte)
	ringId := RingId(hash2)
	if value, ok := ringMap[ringId]; ok {
		fmt.Println(value)
	}
}
