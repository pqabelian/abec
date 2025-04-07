package abecryptoutils

import (
	"reflect"
	"testing"
)

func TestKDF(t *testing.T) {
	type args struct {
		key   []byte
		input []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []byte
	}{
		{
			name: "kdf_test",
			args: args{
				key:   []byte{124, 20, 218, 1, 119, 86, 153, 51, 89, 192, 106, 104, 109, 113, 156, 18, 234, 151, 150, 14, 49, 76, 226, 189, 19, 93, 63, 6, 174, 125, 206, 47, 126, 118, 51, 222, 103, 47, 40, 205, 63, 5, 58, 223, 134, 208, 240, 70, 79, 181, 118, 216, 12, 89, 138, 235, 89, 253, 8, 14, 52, 130, 188, 202},
				input: []byte{20, 159, 132, 237, 113, 247, 93, 249, 172, 83, 68, 236, 189, 57, 225, 60, 50, 100, 88, 3, 247, 38, 229, 170, 108, 133, 107, 121, 166, 177, 38, 28, 237, 86, 235, 80, 168, 129, 123, 142, 207, 123, 249, 230, 136, 120, 192, 161, 29, 158, 69, 105, 46, 107, 94, 70, 46, 142, 63, 128, 18, 41, 192, 46},
			},
			wantErr: false,
			want:    []byte{149, 170, 149, 181, 217, 68, 8, 130, 88, 20, 221, 64, 79, 240, 139, 45, 196, 242, 51, 137, 130, 183, 171, 8, 223, 168, 105, 170, 24, 121, 39, 92, 168, 176, 238, 146, 109, 117, 255, 44, 55, 86, 236, 65, 197, 157, 179, 242, 10, 118, 80, 70, 84, 149, 74, 202, 60, 7, 92, 184, 114, 89, 154, 124},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("%v", tt.args.key)
			t.Logf("%v", tt.args.input)
			gotOutput, err := KDF(tt.args.key, tt.args.input)
			t.Logf("%v", gotOutput)
			if (err != nil) != tt.wantErr {
				t.Errorf("KDF() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOutput, tt.want) {
				t.Errorf("KDF() gotOutput = %v, want %v", gotOutput, tt.want)
			}
		})
	}
}
