package wire

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"testing"
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
