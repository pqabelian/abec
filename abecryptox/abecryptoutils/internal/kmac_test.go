package internal

import (
	"github.com/abesuite/abec/abecrypto"
	"golang.org/x/crypto/sha3"
	"reflect"
	"testing"
)

func Test_kmac_Clone(t *testing.T) {
	type fields struct {
		outputLen int
		initBlock []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   sha3.ShakeHash
	}{
		{
			name: "clone",
			fields: fields{
				outputLen: 64,
				initBlock: abecrypto.RandomBytes(256),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &kmac{
				outputLen: tt.fields.outputLen,
				initBlock: tt.fields.initBlock,
			}
			k.ShakeHash = sha3.NewCShake128(abecrypto.RandomBytes(64), abecrypto.RandomBytes(64))

			expected := k.Sum(nil)

			cloned := k.Clone()

			if !reflect.DeepEqual(expected, cloned.Sum(nil)) {
				t.Errorf("Clone() fail")
			}

		})
	}
}
