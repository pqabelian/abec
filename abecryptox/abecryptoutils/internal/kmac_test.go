package internal

import (
	"encoding/hex"
	"github.com/pqabelian/abec/abecrypto"
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
func TestKMAC128(t *testing.T) {
	type fields struct {
		key    string
		data   string
		custom string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "KMAC Tests (From NIST) Sample #1",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "",
			},
			want: "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E",
		},
		{
			name: "KMAC Tests (From NIST) Sample #2",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "My Tagged Application",
			},
			want: "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5",
		},
		{
			name: "KMAC Tests (From NIST) Sample #3",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "My Tagged Application",
			},
			want: "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230",
		},
	}
	// Above test cases from NIST
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.fields.data)
			key, _ := hex.DecodeString(tt.fields.key)
			expected, _ := hex.DecodeString(tt.want)

			kmac128 := NewKMAC128(key, 32, []byte(tt.fields.custom))
			kmac128.Write(data)
			result := kmac128.Sum(nil)

			if !reflect.DeepEqual(result, expected) {
				t.Errorf("newKMAC128() expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(result))
			}
		})
	}
}

func TestKMAC256(t *testing.T) {
	type fields struct {
		key    string
		data   string
		custom string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "KMAC Tests (From NIST) Sample #4",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "00010203",
				custom: "My Tagged Application",
			},
			want: "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD",
		},
		{
			name: "KMAC Tests (From NIST) Sample #5",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "",
			},
			want: "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69",
		},
		{
			name: "KMAC Tests (From NIST) Sample #6",
			fields: fields{
				key:    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
				data:   "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7",
				custom: "My Tagged Application",
			},
			want: "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965",
		},
	}
	// Above test cases from NIST
	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := hex.DecodeString(tt.fields.data)
			key, _ := hex.DecodeString(tt.fields.key)
			expected, _ := hex.DecodeString(tt.want)

			kmac256 := NewKMAC256(key, 64, []byte(tt.fields.custom))
			kmac256.Write(data)
			result := kmac256.Sum(nil)

			if !reflect.DeepEqual(result, expected) {
				t.Errorf("newKMAC128() expected %s, got %s", hex.EncodeToString(expected), hex.EncodeToString(result))
			}
		})
	}
}
