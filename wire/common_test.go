package wire

import (
	"bytes"
	"fmt"
	"testing"
)

func TestWriteVarBytes(t *testing.T) {
	//in := []byte{'1', '2', '3'}
	var in []byte
	w := bytes.NewBuffer(make([]byte, 0, len(in)))
	err := WriteVarBytes(w, 0, in)
	if err != nil {
		fmt.Println(err)
	}

	r := bytes.NewReader(w.Bytes())
	n, out := ReadVarBytes(r, 0, 100, "test")
	fmt.Println("n:", n, "read:", out)

}
