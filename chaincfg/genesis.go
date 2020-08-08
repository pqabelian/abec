package chaincfg

import (
	"time"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTxAbe{
	Version: 1,
	TxIns: []*wire.TxInAbe{ //len(TxIns)==1
		{
			SerialNumber: chainhash.ZeroHash, // imply this is a coinbase transaction
			PreviousOutPointRing: wire.OutPointRing{
				BlockHashs: []*chainhash.Hash{
					&chainhash.ZeroHash,
					{
						0x48, 0x68, 0x46,
					}, //this value can be covered by any value as a nonce of coinbase
					{
						/*This is the first block of abe*/
						0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
						0x68, 0x65, 0x20, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
						0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6f, 0x66, 0x20,
						0x61, 0x62, 0x65,
					}, //this value can be any value
				},
				OutPoints: []*wire.OutPointAbe{
					{
						TxHash: chainhash.ZeroHash, // empty hash value
						Index:  0,                  // the index will be limited in a special range
					},
				},
			},
		},
	},
	TxOuts: []*wire.TxOutAbe{ //len(TxOuts) >=1
		{
			ValueScript: 10000000000, // the initial value of coinbase transaction
			AddressScript: []byte{
				0x00, 0x00, 0x00, 0x5c, 0xb8, 0x24, 0x3f, 0xb9,
				0xf9, 0x9f, 0x3f, 0x44, 0xf4, 0x0a, 0xcf, 0xa3,
				0xcc, 0xf9, 0x70, 0x14, 0x86, 0xb3, 0x52, 0x9b,
				0xce, 0x35, 0xd4, 0xcd, 0x8c, 0x2d, 0xe5, 0x26,
				0x0e, 0x9a, 0x3c, 0xd2, 0x5b, 0x8a, 0x4b, 0x21,
				0x29, 0x0a, 0xf8, 0x10, 0x8e, 0x60, 0x29, 0x9f,
				0x79, 0x23, 0x1e, 0x10, 0x76, 0x8c, 0x98, 0xa4,
				0x9a, 0xa3, 0x93, 0xb5, 0xfc, 0x0e, 0xf1, 0xe8,
				0xd2, 0x46, 0x18, 0x47, 0x79, 0x03, 0x68, 0xc7,
				0x51, 0xca, 0xaf, 0x2c, 0x9f, 0x4f, 0xc4, 0x6a,
				0x1a, 0x1f, 0x78, 0x05, 0xc5, 0x00, 0xc5, 0xea,
				0x69, 0xb5, 0x37, 0x24, 0xf2, 0xa2, 0x80, 0x11,
				0x47, 0x97, 0xec, 0x1b, 0xfd, 0x05, 0x39, 0xac,
				0x60, 0xce, 0xf4, 0x1c, 0xfb, 0xb1, 0xaf, 0xbd,
				0xb6, 0x45, 0x6d, 0xfd, 0xc8, 0xf6, 0x62, 0x23,
				0xe8, 0x17, 0x9e, 0x2b, 0xfc, 0x6b, 0x2a, 0x92,
				0xbf, 0xb0, 0xf8, 0xbd, 0x32, 0xa1, 0x55, 0xb4,
				0xed, 0x2b, 0x0a, 0x4d, 0x58, 0x42, 0xf6, 0x6f,
				0xc7, 0x36, 0x2d, 0xa6, 0x47, 0x74, 0x1e, 0xbb,
				0x95, 0x7b, 0xe6, 0xe5, 0x20, 0xf0, 0x8a, 0xcd,
				0xe4, 0xf2, 0x11, 0xb1, 0x82, 0xc8, 0x80, 0xfa,
				0xc3, 0x13, 0x9a, 0xce, 0x70, 0x91, 0x16, 0xfc,
				0x2e, 0xcc, 0x57, 0x31, 0x64, 0x74, 0xf5, 0xc2,
				0x8c, 0xc7, 0x5b, 0xbc, 0xbe, 0x16, 0x47, 0x20,
				0xd1, 0xd1, 0xf9, 0x62, 0xc8, 0xa6, 0x2b, 0xe6,
				0xe7, 0xd7, 0x29, 0x2f, 0x8b, 0x48, 0x30, 0x7a,
				0x1b, 0xc9, 0x8c, 0x4c, 0xee, 0xc0, 0xfd, 0xff,
				0x8b, 0xe8, 0x67, 0xa6, 0x64, 0x11, 0x22, 0x4a,
				0xc6, 0x5d, 0x4f, 0x72, 0xae, 0xa9, 0x45, 0x60,
				0xc9, 0x56, 0x51, 0x15, 0x94, 0x0c, 0x49, 0x6d,
				0xea, 0x4b, 0x3f, 0xe5, 0x2f, 0x5e, 0x9e, 0xf5,
				0x12, 0x0b, 0x74, 0x6d, 0x8e, 0xfd, 0x13, 0x94,
				0xb3, 0xea, 0x23, 0xd0, 0x41, 0x6c, 0x94, 0xf3,
				0xc5, 0x92, 0x82, 0x5c, 0x9e, 0x36, 0xf1, 0x87,
				0x52, 0xc8, 0x8f, 0x1b, 0x04, 0x53, 0x50, 0x1f,
				0x90, 0xc6, 0x82, 0xa9, 0x0a, 0xa4, 0x8f, 0x80,
				0xb3, 0x1e, 0xc0, 0x0e, 0x6c, 0x55, 0xb1, 0xbc,
				0x1e, 0xbd, 0xcb, 0xac, 0x06, 0x77, 0xf8, 0x39,
				0x37, 0xc6, 0x70, 0x1d, 0x54, 0x7f, 0x5f, 0xd0,
				0xac, 0x2f, 0x68, 0x4e, 0xcc, 0x41, 0x2c, 0xec,
				0x5e, 0xa3, 0xca, 0x18, 0x3d, 0xa6, 0xb6, 0x9e,
				0x3a, 0xfe, 0x24, 0x98, 0xd7, 0xc2, 0x4f, 0xea,
				0x14, 0x6c, 0x54, 0xaa, 0xe9, 0xb4, 0xa1, 0x78,
				0xdd, 0x70, 0x91, 0x3a, 0xd3, 0x65, 0xec, 0x29,
				0x0d, 0x13, 0xe2, 0x91, 0xb5, 0x8b, 0xcf, 0x69,
				0xdb, 0x43, 0xa2, 0x95, 0x66, 0xdc, 0xee, 0x22,
				0x1d, 0x75, 0x43, 0xf1, 0x99, 0x85, 0x96, 0x50,
				0x31, 0x53, 0x44, 0xf8, 0x2e, 0x59, 0xc1, 0x02,
				0x5c, 0x7d, 0x0c, 0xee, 0x47, 0x43, 0xde, 0x8a,
				0x72, 0x81, 0xd6, 0xff, 0x20, 0x67, 0x92, 0x0a,
				0x81, 0xde, 0x96, 0x6a, 0x4c, 0x90, 0x04, 0x88,
				0x18, 0x56, 0x4c, 0xbd, 0x6a, 0x28, 0x49, 0xf8,
				0x14, 0xd1, 0xa6, 0x5a, 0x8c, 0x96, 0xc1, 0x1e,
				0xed, 0x6e, 0x88, 0x3c, 0xe8, 0x0c, 0x33, 0x7a,
				0x0b, 0x9e, 0xfd, 0x57, 0x7d, 0xb4, 0x52, 0x07,
				0xcb, 0x0f, 0x6f, 0x4f, 0xe8, 0x6e, 0xbb, 0xec,
				0x89, 0x4e, 0x85, 0x00, 0x81, 0x78, 0xa0, 0xda,
				0xee, 0x21, 0x08, 0x77, 0xea, 0x6c, 0x49, 0x43,
				0xe5, 0x15, 0x2e, 0xa7, 0x08, 0x47, 0x07, 0xdb,
				0xa1, 0x8e, 0x51, 0x18, 0xa4, 0xc3, 0xe9, 0x53,
				0x28, 0xeb, 0xab, 0x57, 0x2d, 0xfe, 0xe0, 0xaf,
				0x2b, 0x51, 0xfa, 0x80, 0x79, 0x73, 0x43, 0x23,
				0x6f, 0xfe, 0x7e, 0x85, 0x8a, 0x5b, 0xa4, 0x46,
				0x7e, 0xb6, 0xad, 0x58, 0xe9, 0x06, 0x7a, 0xcf,
				0x3a, 0x2a, 0xda, 0xe7, 0x7a, 0xc7, 0xbc, 0x50,
				0x69, 0xbb, 0xfe, 0xed, 0x8d, 0xb7, 0x8e, 0x3b,
				0x3c, 0x55, 0x3e, 0x8c, 0xcd, 0xfb, 0x3f, 0x62,
				0xee, 0xc2, 0x20, 0xeb, 0x64, 0x6a, 0xc8, 0xe1,
				0x12, 0xaa, 0x80, 0x67, 0x7b, 0x00, 0x07, 0x51,
				0x58, 0xe3, 0x98, 0xe8, 0xf2, 0xac, 0xf4, 0x1f,
				0xb1, 0x7b, 0x41, 0x19, 0xa4, 0x3b, 0x43, 0x6c,
				0xcc, 0xed, 0xdd, 0x6e, 0x66, 0x14, 0xc5, 0x2e,
				0xec, 0x90, 0xed, 0x43, 0x49, 0xfa, 0x7d, 0x94,
				0xee, 0x72, 0x22, 0xfd, 0x2c, 0xeb, 0x2c, 0x3d,
				0x41, 0x33, 0x87, 0x96, 0x7c, 0xef, 0xe9, 0xd8,
				0xcc, 0x6f, 0xdb, 0x14, 0x08, 0x54, 0xa0, 0x7f,
				0xb8, 0x8b, 0x1a, 0x32, 0xbe, 0x57, 0xa9, 0x66,
				0x84, 0x37, 0x32, 0x70, 0xa6, 0x6e, 0x8a, 0x49,
				0x0b, 0x6b, 0x32, 0x1a, 0xbd, 0xf5, 0xc6, 0x7a,
				0x21, 0x01, 0xa1, 0x89, 0x6d, 0xa8, 0x35, 0x55,
				0x4a, 0xdb, 0xe5, 0x56, 0xec, 0x1a, 0x95, 0x32,
				0x35, 0x3c, 0xbb, 0x9e, 0xdf, 0x50, 0xf2, 0xf9,
				0xc4, 0xec, 0x1f, 0x76, 0x9e, 0x01, 0x30, 0x72,
				0x83, 0x03, 0xf2, 0xe3, 0x1b, 0x06, 0xfc, 0x11,
				0xe9, 0x05, 0x9e, 0x74, 0x13, 0x29, 0x2f, 0x40,
				0x37, 0x90, 0xcd, 0x20, 0xec, 0xae, 0xca, 0xc2,
				0x63, 0x81, 0x55, 0x8e, 0x1a, 0x5d, 0xa1, 0xd6,
				0x81, 0x44, 0xdd, 0xaa, 0x51, 0xf5, 0x5e, 0xa1,
				0x77, 0x2d, 0xb5, 0x39, 0x23, 0x67, 0x0d, 0x71,
				0xbe, 0x8a, 0xfa, 0xab, 0x97, 0xfa, 0x80, 0x09,
				0xb2, 0xff, 0x43, 0x5a, 0x31, 0x95, 0xad, 0x76,
				0x77, 0x3c, 0x8c, 0x72, 0x8a, 0x9d, 0xea, 0x59,
				0x29, 0x0f, 0x76, 0xa9, 0x11, 0x0c, 0x93, 0xba,
				0x1f, 0xaf, 0x95, 0xc1, 0xcd, 0x6c, 0x92, 0xb3,
				0xfb, 0xd9, 0xd4, 0x17, 0x03, 0x4d, 0x16, 0x0f,
				0x9b, 0x2b, 0xab, 0xd7, 0xb3, 0x54, 0x39, 0x1c,
				0x7d, 0x3d, 0x07, 0x67, 0x65, 0xfb, 0xf0, 0x11,
				0x7c, 0x75, 0x0a, 0x67, 0xa1, 0xed, 0x77, 0xed,
				0xef, 0xbf, 0x7a, 0xd3, 0xc2, 0xde, 0xfa, 0x8b,
				0x73, 0xdf, 0x9c, 0x2b, 0x38, 0xd7, 0x92, 0x84,
				0x03, 0x00, 0xfe, 0xa3, 0x81, 0xc5, 0x59, 0x4b,
				0xe1, 0x2e, 0xea, 0x50, 0x66, 0xc1, 0xe8, 0x98,
				0xae, 0x60, 0x42, 0x4c, 0xf6, 0x1c, 0xbf, 0xef,
				0x4c, 0xbf, 0xd5, 0xe3, 0x51, 0x18, 0x1c, 0xb6,
				0x5d, 0xff, 0xca, 0xeb, 0x7b, 0x81, 0x5a, 0x83,
				0x6b, 0x54, 0x65, 0x6a, 0x5f, 0x0c, 0x2d, 0x53,
				0x84, 0xfa, 0x99, 0xbe, 0x84, 0x2c, 0x30, 0x87,
				0xbb, 0x5e, 0x7b, 0x01, 0x73, 0x2f, 0x38, 0x1a,
				0x57, 0xcd, 0xc0, 0x55, 0x59, 0xff, 0xed, 0x92,
				0x6f, 0xad, 0x1b, 0x30, 0x15, 0xd3, 0x76, 0x6f,
				0xa6, 0x0e, 0x8e, 0x53, 0x06, 0x7b, 0x35, 0x3b,
				0x2d, 0xd0, 0xc2, 0x6f, 0xce, 0x3e, 0xdf, 0xa3,
				0xb0, 0xab, 0x35, 0x22, 0x70, 0xc4, 0x14, 0x4a,
				0xd5, 0x9c, 0x3c, 0xd4, 0xab, 0x50, 0xe2, 0x89,
				0x10, 0x04, 0x6b, 0x4e, 0xae, 0x1f, 0xb9, 0x1a,
				0xb1, 0x4f, 0xa1, 0x44, 0xaf, 0xc1, 0xe5, 0x09,
				0x17, 0x1b, 0x06, 0xca, 0x46, 0xc6, 0x1e, 0x3f,
				0x43, 0x15, 0x6b, 0xda, 0xe9, 0x11, 0xdd, 0xf0,
				0x62, 0xa2, 0xcd, 0xad, 0x52, 0x14, 0xb5, 0x51,
				0x7b, 0xe9, 0x0e, 0x54, 0xc1, 0x73, 0xf5, 0x94,
				0x6f, 0x07, 0x18, 0x0a, 0x9e, 0x5e, 0xbb, 0x23,
				0x06, 0x19, 0xc6, 0xfc, 0x27, 0xb5, 0xdb, 0x5c,
				0x9c, 0x7b, 0xb6, 0xa2, 0x17, 0x33, 0xb7, 0x54,
				0x7b, 0x1d, 0x2c, 0x6e, 0xe3, 0xbe, 0x9b, 0x13,
				0x99, 0xb0, 0x7a, 0xa5, 0x12, 0xb2, 0xa5, 0x65,
				0x40, 0x07, 0xda, 0x27, 0xee, 0xd9, 0xc4, 0x17,
				0x13, 0x89, 0x24, 0x87, 0x56, 0x37, 0xfa, 0xa4,
				0x3c, 0x6b, 0xf0, 0xa8, 0xd9, 0xce, 0x18, 0x6a,
				0x0c, 0x48, 0x91, 0x6a, 0xe9, 0x82, 0xbd, 0x2a,
				0x93, 0x91, 0x1e, 0xe0, 0x6e, 0xae, 0x3e, 0x81,
				0x8d, 0x6f, 0xa3, 0x6e, 0x42, 0x2f, 0x68, 0xde,
				0x60, 0x0d, 0x31, 0x03, 0x61, 0x53, 0x8d, 0x81,
				0x91, 0x39, 0xaf, 0xd7, 0x34, 0xbf, 0x6f, 0x0f,
				0x19, 0x11, 0x65, 0x31, 0x54, 0x39, 0x71, 0x69,
				0xba, 0x55, 0xdd, 0x68, 0x0a, 0xca, 0xd9, 0xbe,
				0x93, 0x2e, 0x01, 0x88, 0x85, 0x9f, 0x65, 0x88,
				0xe0, 0x16, 0xaa, 0x42, 0x37, 0xa4, 0xa1, 0x4d,
				0x96, 0x8d, 0xb2, 0x75, 0x66, 0xe7, 0xca, 0xba,
				0xd0, 0x3c, 0xc9, 0xff, 0xc4, 0x96, 0x76, 0x8a,
				0x74, 0x00, 0x9c, 0x64, 0x03, 0xdb, 0xf2, 0x64,
				0xbd, 0x29, 0x4e, 0x3c, 0xf4, 0x86, 0x7e, 0x5c,
				0xa3, 0xad, 0xac, 0x23, 0x5c, 0xf0, 0x07, 0x5b,
				0xcf, 0x6e, 0xeb, 0x8b, 0x59, 0x29, 0x36, 0xf2,
				0xf3, 0x6f, 0x03, 0xc8, 0x06, 0xd4, 0x1d, 0xa0,
				0x8f, 0xd3, 0x4e, 0x47, 0x73, 0x9f, 0xbc, 0xa0,
				0x46, 0x6f, 0xf3, 0x5e, 0xd8, 0x4f, 0x60, 0x59,
				0xd6, 0xe5, 0xaa, 0x9d, 0x5b, 0x54, 0x14, 0x5d,
				0xfc, 0xf5, 0x2b, 0x04, 0xfb, 0x3a, 0x24, 0xfe,
				0xf8, 0xa3, 0x83, 0xe4, 0xba, 0xcc, 0x5f, 0xf5,
				0x40, 0xaf, 0xc5, 0xa0, 0x79, 0xa9, 0x3c, 0x1e,
				0xf7, 0xa4, 0x45, 0xab, 0xe0, 0x33, 0x7d, 0xf8,
				0x70, 0xd0, 0x74, 0xa6, 0x4c, 0x70, 0xaa, 0x0e,
				0x8b, 0x12, 0xa3, 0xcc, 0x5b, 0x32, 0x64, 0xba,
				0x5b, 0xc1, 0x31, 0x68, 0x61, 0xb5, 0x8e, 0xb3,
				0x5c, 0xda, 0x62, 0x5e, 0x0d, 0xac, 0x37, 0x62,
				0x23, 0xae, 0x0b, 0xd1, 0x3f, 0xa8, 0x76, 0xf4,
				0xcc, 0x25, 0xc9, 0x6f, 0x11, 0x6f, 0xc1, 0x7c,
				0xeb, 0x1c, 0x26, 0x6e, 0xbf, 0x3f, 0x3f, 0xf4,
				0xd0, 0x1f, 0x50, 0x17, 0x9c, 0xb4, 0x23, 0x35,
				0xd6, 0xb2, 0x4f, 0x73, 0xe7, 0x5a, 0x13, 0xb7,
				0x3f, 0x4b, 0x32, 0xc7, 0xec, 0xa7, 0xba, 0x0b,
				0xc4, 0x4b, 0xf7, 0xdf, 0x8d, 0x59, 0x35, 0xca,
				0x7d, 0x08, 0x38, 0x15, 0x79, 0xc8, 0x9f, 0x94,
				0x6b, 0x86, 0xb3, 0x41, 0xac, 0x8d, 0x91, 0x55,
				0x04, 0x59, 0xf0, 0x25, 0x7d, 0x57, 0x02, 0xa7,
				0xbf, 0xb2, 0x57, 0x19, 0xbb, 0x28, 0x74, 0x1c,
				0x5a, 0x6f, 0xb3, 0xd4, 0xb3, 0x78, 0x79, 0x3c,
				0x02, 0xa5, 0xb7, 0x85, 0xb7, 0x00, 0x10, 0x00,
				0x0d, 0xff, 0x02, 0xa4, 0x31, 0x0b, 0xa5, 0x6b,
				0x7a, 0x72, 0x7d, 0x6a, 0x67, 0x77, 0xdb, 0x55,
				0xac, 0x58, 0x4d, 0xa4, 0x3f, 0x4f, 0x83, 0x28,
				0xf4, 0x9e, 0x34, 0xf2, 0x76, 0xff, 0x9e, 0x90,
				0xa7, 0x2c, 0xc7, 0x4a, 0x8b, 0x0d, 0x6c, 0x2d,
				0x17, 0x95, 0x99, 0x3a, 0x38, 0xcc, 0xa0, 0xbe,
				0xf8, 0x11, 0xc1, 0x27, 0xf7, 0x62, 0xeb, 0x42,
				0xa0, 0x86, 0x36, 0xdd, 0x30, 0xff, 0x45, 0x11,
				0x11, 0x01, 0x4a, 0x31, 0x4a, 0x78, 0x0c, 0x62,
				0xf7, 0xfc, 0xc7, 0x7d, 0xe3, 0x5e, 0x69, 0xc2,
				0x4a, 0xa2, 0x74, 0x0a, 0x73, 0xa7, 0xc8, 0x24,
				0x96, 0x59, 0x17, 0xc6, 0x95, 0x26, 0x97, 0x09,
				0x6a, 0x49, 0x20, 0xc0, 0x96, 0x80, 0xf3, 0xe2,
				0xda, 0x2a, 0x25, 0x08, 0x93, 0xda, 0x90, 0xb5,
				0xb6, 0x58, 0xf2, 0x21, 0x0d, 0x10, 0xef, 0xc5,
				0xc8, 0xd3, 0xce, 0x99, 0x4d, 0x33, 0xe0, 0xd9,
				0x24, 0xff, 0x90, 0x1a, 0xc1, 0xb0, 0x01, 0x4a,
				0x00, 0x50, 0xa1, 0xc3, 0xdc, 0x20, 0x89, 0x73,
				0xff, 0x78, 0x89, 0x53, 0x97, 0xbc, 0xf7, 0x2c,
				0x53, 0x1f, 0x2d, 0x4a, 0x70, 0xf6, 0xbf, 0xdb,
				0xce, 0x1b, 0x05, 0xa2, 0xa7, 0xdb, 0x56, 0x9e,
				0x0f, 0x46, 0x7a, 0x80, 0xcf, 0x8a, 0xda, 0x95,
				0xf8, 0x3d, 0x64, 0x45, 0xd0, 0xd7, 0xf8, 0xc2,
				0x25, 0x47, 0x1d, 0x35, 0x05, 0x06, 0x99, 0x5d,
				0x09, 0xc3, 0x51, 0xa7, 0x2b, 0x7e, 0x94, 0x31,
				0x94, 0x46, 0x51, 0x59, 0xfd, 0xab, 0x25, 0xf6,
				0xd8, 0x7b, 0xad, 0xf7, 0x6d, 0x15, 0xd3, 0x55,
				0x38, 0x8f, 0xab, 0xa4, 0x40, 0xf0, 0x51, 0xf9,
				0x4d, 0x16, 0xab, 0x23, 0xf8, 0x61, 0xcf, 0x6e,
				0xda, 0x77, 0xb9, 0x54, 0xaf, 0x52, 0x03, 0xb6,
				0xf4, 0x1d, 0x15, 0xb5, 0x60, 0xab, 0x92, 0x06,
				0xe3, 0x36, 0xb2, 0x26, 0xd7, 0xc1, 0xef, 0xa8,
				0x36, 0xbc, 0x92, 0x22, 0x4e, 0x0b, 0xa5, 0x0b,
				0x20, 0x47, 0xb2, 0x82, 0x51, 0x36, 0xb2, 0xb6,
				0x06, 0x67, 0x82, 0xdc, 0xb7, 0xdf, 0x23, 0x07,
				0xe5, 0x29, 0x3a, 0x25, 0x90, 0x43, 0xc9, 0x53,
				0xae, 0x11, 0xd1, 0x9e, 0xa1, 0x8d, 0x96, 0x89,
				0x7d, 0x71, 0x2e, 0x1c, 0xdc, 0xa5, 0x9f, 0x5a,
				0xe3, 0x2b, 0x38, 0xaa, 0x9f, 0x87, 0x30, 0x90,
				0x68, 0xd6, 0x22, 0xc7, 0xe1, 0x95, 0x46, 0xe7,
				0x4a, 0x02, 0x66, 0x7a, 0xd2, 0x70, 0x83, 0xfd,
				0x15, 0x42, 0xcb, 0x9a, 0x4e, 0x68, 0x06, 0x54,
				0x4c, 0x82, 0x2d, 0xbf, 0xf3, 0x7a, 0x67, 0xdf,
				0xa0, 0x87, 0xd1, 0xae, 0xec, 0x7b, 0x2a, 0x59,
				0x40, 0xed, 0x55, 0xf6, 0x40, 0xa7, 0x65, 0x58,
				0x3b, 0x04, 0x59, 0x1b, 0x91, 0x69, 0x4d, 0x6a,
				0x27, 0xa3, 0x49, 0x0f, 0xbf, 0xc4, 0xd5, 0x79,
				0x1c, 0x2e, 0xda, 0x0b, 0x02, 0x0b, 0x76, 0xf3,
				0x46, 0x50, 0x71, 0x40, 0x0a, 0xb3, 0xf2, 0x12,
				0x55, 0x53, 0x8d, 0x46, 0xc4, 0xb2, 0x38, 0xa0,
				0x31, 0x86, 0x5e, 0x52, 0x7f, 0x6b, 0xeb, 0xc7,
				0x80, 0xb0, 0x07, 0x22, 0x35, 0x75, 0xaf, 0x5e,
				0x9e, 0x6a, 0x16, 0x89, 0x1a, 0x81, 0x0c, 0x19,
				0xf2, 0x33, 0xe8, 0xa2, 0x9d, 0xc0, 0x2d, 0x39,
				0x3f, 0xaa, 0xcd, 0xdb, 0xc0, 0xfd, 0x6f, 0x5b,
				0x13, 0x4d, 0x24, 0x3c, 0xc1, 0xf3, 0xae, 0xb2,
				0x84, 0x61, 0x99, 0x77, 0x94, 0xeb, 0xc7, 0x7a,
				0x7d, 0x42, 0x42, 0xef, 0x38, 0xa7, 0x74, 0xd6,
				0x62, 0x37, 0xc6, 0x71, 0x6c, 0xe8, 0xf7, 0x4a,
				0x54, 0x4b, 0x8a, 0x78, 0x48, 0xce, 0x28, 0xe2,
				0xb2, 0xe6, 0x27, 0x10, 0x87, 0x11, 0x8f, 0x7e,
				0xe1, 0x05, 0x37, 0x53, 0x2e, 0xca, 0x54, 0xa4,
				0x1e, 0x81, 0xcb, 0x37, 0x6e, 0x1d, 0x05, 0x6b,
				0x06, 0xd3, 0x90, 0x66, 0x97, 0x1f, 0x71, 0x77,
				0x41, 0xdd, 0xe2, 0xfe, 0x2a, 0x55, 0x2d, 0xb0,
				0xe4, 0x4d, 0xee, 0xe1, 0xdb, 0x43, 0x80, 0x6f,
				0x23, 0x49, 0x6d, 0x4d, 0x99, 0x09, 0xe4, 0x67,
				0xa6, 0x2c, 0x32, 0x53, 0xf1, 0x70, 0xfa, 0xc7,
				0x47, 0x00, 0x58, 0x14, 0x7b, 0x24, 0xb9, 0x41,
				0x5d, 0x31, 0x75, 0xf0, 0x44, 0x62, 0xc5, 0x91,
				0xb7, 0x1f, 0x51, 0xb9, 0x6f, 0xe5, 0x16, 0x43,
				0xde, 0xa4, 0x8d, 0x81, 0x35, 0xe0, 0xe7, 0x09,
				0xfa, 0x20, 0x90, 0x37, 0x54, 0x87, 0xf9, 0xfe,
				0x66, 0x4f, 0xb3, 0xc4, 0xe8, 0x65, 0x76, 0x68,
				0x35, 0x29, 0xa7, 0xc3, 0x8a, 0x17, 0x26, 0xc1,
				0xcb, 0x39, 0x55, 0xf9, 0x95, 0xd1, 0x69, 0x81,
				0xc0, 0x8b, 0xbe, 0x5d, 0x7e, 0x4f, 0x9a, 0xe7,
				0xf4, 0xae, 0xd3, 0x10, 0x45, 0x5a, 0xd5, 0x61,
				0x48, 0xf5, 0x0b, 0x7d, 0x90, 0x27, 0x47, 0x1a,
				0xdd, 0xf4, 0x00, 0x73, 0x95, 0xe8, 0x6b, 0x4b,
				0xd0, 0x33, 0x41, 0x65, 0xfe, 0x73, 0x4a, 0x1f,
				0xb7, 0x1e, 0x59, 0x74, 0x95, 0x94, 0xb4, 0xe2,
				0x2c, 0x60, 0xce, 0x86, 0xf8, 0xd4, 0x75, 0x24,
				0xb3, 0x22, 0x7c, 0xec, 0x96, 0xd5, 0x96, 0x21,
				0x1f, 0x6b, 0x50, 0x60, 0x78, 0x91, 0x61, 0x45,
				0xa4, 0x52, 0xc7, 0x5c, 0xfc, 0x02, 0x2f, 0x8f,
				0xf2, 0xc6, 0x57, 0x59, 0x7d, 0xfa, 0xd6, 0xb6,
				0xa2, 0xa7, 0x2f, 0x6b, 0x1f, 0x63, 0x52, 0x03,
				0x85, 0x28, 0xa0, 0xce, 0xb4, 0xf1, 0x18, 0xe2,
				0x43, 0x36, 0xf2, 0x80, 0xc3, 0x36, 0x5b, 0x1a,
				0xdc, 0x37, 0xcb, 0x36, 0x83, 0x71, 0xef, 0x93,
				0x0b, 0xa3, 0x8c, 0xd1, 0x49, 0x30, 0x99, 0xd5,
				0x8f, 0x5e, 0x0c, 0x69, 0xa7, 0xff, 0x74, 0xd3,
				0xfa, 0x82, 0x67, 0xa3, 0x8a, 0xa0, 0x76, 0x45,
				0x65, 0xdc, 0xc6, 0x0c, 0xf4, 0x47, 0x1a, 0x40,
				0xd2, 0x28, 0x51, 0x67, 0x43, 0x53, 0xd0, 0x7a,
				0x99, 0x75, 0xb0, 0xdf, 0x08, 0x42, 0x7b, 0x97,
				0x71, 0xf1, 0xb2, 0xc1, 0xf7, 0xd9, 0x79, 0x02,
				0xf7, 0xd1, 0x41, 0xc3, 0x0a, 0x8c, 0xb3, 0x0d,
				0x96, 0xf7, 0xb1, 0x6a, 0xa0, 0x7b, 0x53, 0xb6,
				0x59, 0x63, 0x95, 0xbd, 0x05, 0x87, 0xda, 0x5f,
				0xc0, 0x71, 0x44, 0xb7, 0x87, 0xd7, 0xb2, 0xae,
				0xec, 0xe6, 0x0c, 0xd8, 0x41, 0x67, 0xee, 0x81,
				0x5b, 0x15, 0x6f, 0x5d, 0xa4, 0x40, 0x7e, 0x24,
				0x71, 0x92, 0x98, 0xa2, 0x7e, 0xd3, 0xbb, 0x99,
				0x91, 0x20, 0x23, 0x89, 0x54, 0x07, 0xfb, 0x6f,
				0xca, 0xc4, 0xe5, 0x36, 0x5e, 0x3f, 0x14, 0x21,
				0x0b, 0x90, 0xfb, 0x87, 0x01, 0xc1, 0x9b, 0x07,
				0x9a, 0xca, 0x2e, 0xb8, 0x91, 0x18, 0xe5, 0x2a,
				0x0b, 0x4c, 0xc0, 0xb6, 0x1f, 0x64, 0x56, 0xb0,
				0x6b, 0x0b, 0xb2, 0x39, 0x27, 0x3c, 0xf1, 0x6f,
				0xa2, 0x89, 0x33, 0xb5, 0x48, 0x20, 0x33, 0x51,
				0x1c, 0xc6, 0x58, 0x26, 0x7a, 0x52, 0x92, 0xb9,
				0x73, 0xe9, 0x0f, 0xf9, 0x60, 0xbd, 0xca, 0x65,
				0xbc, 0xf0, 0x10, 0xdf, 0xb2, 0x0f, 0x26, 0x7a,
				0xfe, 0x0b, 0x62, 0xf1, 0xb3, 0x54, 0x61, 0x60,
				0xe0, 0xb7, 0x2a, 0x47, 0x59, 0x11, 0x41, 0x19,
				0x59, 0x76, 0x0b, 0xd3, 0xd7, 0x40, 0x80, 0x8a,
				0x08, 0xff, 0x56, 0x03, 0x11, 0x85, 0x28, 0x2e,
				0x67, 0x30, 0x7b, 0xf2, 0xd7, 0xb8, 0x53, 0x64,
				0x5b, 0xcf, 0x49, 0x69, 0xdd, 0xcf, 0x4a, 0xd7,
				0x29, 0x61, 0x4a, 0x68, 0xde, 0xfb, 0xa3, 0x18,
				0xd1, 0x15, 0xbb, 0xbc, 0x78, 0x25, 0x5c, 0x0d,
				0xe6, 0x93, 0xb1, 0x83, 0x85, 0x55, 0xf5, 0x65,
				0xeb, 0xef, 0x95, 0x17, 0x98, 0xd9, 0x09, 0x4a,
				0x0a, 0x7c, 0xee, 0x96, 0x12, 0xcc, 0xbb, 0x0a,
				0x8c, 0x96, 0xd3, 0x1d, 0x36, 0x3b, 0x3a, 0xdb,
				0x74, 0xbc, 0xa5, 0xc5, 0x64, 0x03, 0xce, 0x0d,
				0x44, 0x69, 0x24, 0x26, 0x99, 0xb6, 0xb0, 0x48,
				0x94, 0xfc, 0x36, 0x78, 0x02, 0xeb, 0xf5, 0xc0,
				0xb8, 0xe0, 0xfe, 0x2a, 0x4b, 0x38, 0x15, 0x25,
				0x32, 0x5e, 0xa6, 0xd9, 0x4a, 0x5e, 0xb6, 0x89,
				0x6e, 0x61, 0x50, 0x98, 0xfc, 0x5f, 0xfd, 0xfb,
				0x3e, 0x6d, 0x81, 0xb7, 0x4a, 0x5c, 0x0e, 0x44,
				0x2e, 0x8c, 0x8a, 0x40, 0x3a, 0x1f, 0x73, 0x3f,
				0x24, 0x68, 0x73, 0x05, 0x76, 0xaf, 0x0e, 0xc8,
				0x35, 0x3e, 0xed, 0x21, 0x58, 0xd2, 0x6f, 0xcd,
				0x9e, 0x2d, 0x8f, 0xca, 0xd8, 0x87, 0xc3, 0x55,
				0xd4, 0x32, 0x2f, 0xd4, 0x8f, 0x63, 0x12, 0x56,
				0xf5, 0x0e, 0x89, 0x29, 0xca, 0x2e, 0x6e, 0x44,
				0x15, 0xa1, 0xdf, 0x62, 0x79, 0x92, 0x75, 0xd6,
				0x0e, 0x92, 0xf0, 0xf1, 0x27, 0x48, 0x38, 0xed,
				0xa3, 0xee, 0x87, 0xdc, 0xb8, 0x45, 0x74, 0xc5,
				0x11, 0xb3, 0xeb, 0x71, 0x1f, 0xea, 0x1b, 0x3c,
				0x00, 0x59, 0xa8, 0x06, 0x60, 0x0c, 0x2d, 0x37,
				0x7d, 0x47, 0x91, 0x8e, 0xcd, 0x83, 0xa3, 0x38,
				0xc8, 0x7a, 0x33, 0x29, 0xc1, 0xa3, 0xb2, 0x12,
				0x58, 0xe1, 0x10, 0x05, 0xf1, 0x00, 0x34, 0xb5,
				0x8f, 0x92, 0x07, 0x4b, 0x21, 0x61, 0x0d, 0x20,
				0x77, 0x66, 0xa2, 0x3b, 0x68, 0xb0, 0xc2, 0x7d,
				0x0f, 0xa5, 0x1e, 0x08, 0x3f, 0x4c, 0x3b, 0x99,
				0xe4, 0xb8, 0xf2, 0xab, 0x21, 0xc9, 0x58, 0xc9,
				0x6a, 0x98, 0x0d, 0x93, 0xf3, 0x4c, 0x67, 0x14,
				0xed, 0x42, 0xe4, 0x84, 0x67, 0x44, 0xcf, 0x5e,
				0x4a, 0x75, 0x30, 0x92, 0x0c, 0x10, 0xe3, 0x53,
				0x59, 0x2c, 0xad, 0xa8, 0xd7, 0x40, 0x53, 0x70,
				0x7c, 0x58, 0x20, 0x95, 0x14, 0x46, 0xfc, 0x96,
				0xd8, 0x91, 0x36, 0x00, 0x84, 0x32, 0xb0, 0xff,
				0x55, 0xd8, 0x09, 0xc3, 0x2f, 0x2c, 0xfa, 0x0c,
				0x9b, 0x60, 0x59, 0x7f, 0x2d, 0x5f, 0x3c, 0x4d,
				0x74, 0x3a, 0x42, 0x7a, 0xe9, 0xf9, 0x5e, 0x20,
				0xa0, 0x39, 0x32, 0x32, 0xe6, 0xfb, 0x1d, 0x0e,
				0x0f, 0xa2, 0xf4, 0x35, 0xd4, 0xf4, 0x99, 0x5e,
				0x02, 0xa6, 0xb9, 0xd6, 0x56, 0x77, 0x82, 0x7d,
				0xef, 0x06, 0x5c, 0x79, 0x1d, 0xba, 0xb0, 0xfe,
				0x6f, 0xc1, 0x6a, 0x61, 0x8f, 0x02, 0x1e, 0xd0,
				0x35, 0xd4, 0xa4, 0x45, 0x93, 0xbe, 0xf2, 0x25,
				0x31, 0xae, 0x44, 0xf6, 0x1f, 0x45, 0xce, 0xb3,
				0xbb, 0x82, 0x91, 0x26, 0x97, 0x44, 0x7c, 0x3d,
				0x3a, 0x74, 0x21, 0x0e, 0xb3, 0x6e, 0x1b, 0x59,
				0xbb, 0xc4, 0xba, 0xb0, 0x89, 0xc0, 0xd6, 0x40,
				0x0f, 0x8d, 0x04, 0x65, 0x42, 0x4b, 0x7a, 0xb2,
				0x04, 0x2b, 0x84, 0x38, 0xdb, 0x40, 0x9f, 0x6f,
				0x0f, 0x3a, 0x50, 0xe8, 0x30, 0x4c, 0x94, 0x6c,
				0xba, 0xd2, 0x2d, 0x18, 0xe6, 0x2a, 0x9d, 0x46,
				0x79, 0xb8, 0x62, 0x34, 0xb2, 0x37, 0x92, 0xe0,
				0x66, 0xd7, 0x52, 0xee, 0x58, 0xcb, 0x75, 0xfb,
				0x57, 0xf1, 0xd0, 0x08, 0x73, 0x7d, 0x1d, 0x97,
				0xdf, 0xc6, 0x93, 0x51, 0x92, 0x88, 0x11, 0x70,
				0x49, 0x4a, 0x04, 0xa2, 0x4b, 0x5f, 0xa1, 0x11,
				0x9a, 0xf3, 0x99, 0x58, 0x80, 0xf7, 0x0d, 0xe5,
				0x7a, 0x6f, 0xd6, 0x71, 0x9f, 0xa2, 0x8b, 0xd0,
				0x2f, 0x38, 0x67, 0xc8, 0x33, 0xfd, 0x85, 0xdf,
				0x9f, 0x55, 0x38, 0xd9, 0x39, 0xf1, 0xa2, 0x24,
				0x43, 0x0d, 0x27, 0x48, 0xd0, 0xef, 0x69, 0xc4,
				0x14, 0xa6, 0xab, 0x17, 0x2f, 0x7a, 0xee, 0x50,
				0x92, 0xc1, 0x24, 0xb8, 0x38, 0x61, 0x0d, 0xe5,
				0x33, 0xae, 0xb4, 0x91, 0xc8, 0x14, 0x2c, 0x6b,
				0x8f, 0x37, 0x09, 0xa6, 0x47, 0xe9, 0xcc, 0x1a,
				0x18, 0x01, 0x1d, 0x85, 0xe6, 0xc2, 0x7a, 0x92,
				0x3d, 0x16, 0xa5, 0x2d, 0xe4, 0x91, 0x4d, 0xbe,
				0xa2, 0x3e, 0xd1, 0x42, 0x64, 0x73, 0xc4, 0x98,
				0x67, 0x21, 0x54, 0x08, 0x44, 0x69, 0xa8, 0x17,
				0xe9, 0xe2, 0x21, 0x45, 0xda, 0x7e, 0xd7, 0x24,
				0xe7, 0xe0, 0xc1, 0x7c, 0x49, 0xc3, 0x9c, 0xae,
				0x14, 0xd3, 0x0e, 0x5b, 0x5d, 0x74, 0x44, 0xd9,
				0x4c, 0x98, 0xc5, 0x69, 0x59, 0x7f, 0x3b, 0x1b,
				0x1a, 0x3d, 0xeb, 0xd0, 0xfe, 0x64, 0xee, 0x77,
				0xfc, 0x2b, 0xdb, 0x01, 0x03, 0xc9, 0x8e, 0x05,
				0x7d, 0x45, 0x3e, 0x57, 0x7f, 0x50, 0xde, 0xa1,
				0x33, 0x7c, 0x32, 0x02, 0x2f, 0x8a, 0x07, 0x64,
				0x76, 0x71, 0x29, 0x6b, 0x9f, 0xdf, 0x69, 0xe1,
				0xbe, 0xf6, 0xa7, 0x5d, 0xf7, 0x97, 0x8d, 0x6f,
				0x10, 0x76, 0xa7, 0x6a, 0x62, 0xb4, 0x33, 0x75,
				0xf5, 0x94, 0xd1, 0xb2, 0x79, 0x3f, 0x86, 0x20,
				0x2d, 0xa1, 0x61, 0xe2, 0x50, 0x70, 0x25, 0x41,
				0x69, 0x8f, 0x10, 0x41, 0x5e, 0x9e, 0x27, 0x2b,
				0xed, 0x98, 0x54, 0xb4, 0xf5, 0x8f, 0x60, 0x37,
				0x73, 0x8d, 0xf3, 0x4e, 0x32, 0x62, 0xae, 0x69,
				0xb4, 0x5c, 0x5a, 0xea, 0x12, 0xff, 0xe7, 0x21,
				0x9e, 0x1f, 0x1e, 0x0e, 0x96, 0x3d, 0x15, 0xb5,
				0x71, 0xb7, 0xeb, 0x17, 0x4c, 0xfe, 0x56, 0xd7,
				0x86, 0x3c, 0xbb, 0xa3, 0x6c, 0x7e, 0xf5, 0x07,
				0x44, 0xa6, 0x1e, 0xf1, 0xd7, 0x5e, 0x1c, 0x28,
				0xf8, 0x73, 0x96, 0xe4, 0xc2, 0x3f, 0x04, 0x35,
				0x71, 0xb6, 0xf9, 0xe6, 0xa5, 0x90, 0x0a, 0x5f,
				0x08, 0xb9, 0x64, 0x2d, 0xc1, 0x81, 0x54, 0x4d,
				0x0a, 0xb2, 0x84, 0xde, 0xf8, 0xf6, 0x15, 0x55,
				0x9a, 0x41, 0xfa, 0xc5, 0x8c, 0xf4, 0x87, 0x17,
				0x17, 0x78, 0x2a, 0x48, 0x5f, 0x06, 0x70, 0x04,
				0x6f, 0x40, 0xb5, 0x54, 0xc7, 0x2a, 0x33, 0x5b,
				0x77, 0xe1, 0x4d, 0x33, 0x4c, 0xe3, 0x27, 0x1c,
				0xdf, 0xf2, 0xa8, 0x3a, 0x8b, 0x36, 0x4b, 0xb9,
				0xd4, 0x89, 0x11, 0xa1, 0x20, 0x0d, 0x61, 0xfb,
				0x65, 0x78, 0x0f, 0x90, 0x68, 0x2b, 0x92, 0x32,
				0xa9, 0xbc, 0x1e, 0x6c, 0x62, 0x59, 0x95, 0x1c,
				0x4f, 0xe7, 0x3f, 0xc3, 0x96, 0x43, 0xba, 0x2b,
				0xf1, 0x1a, 0xf7, 0x2b, 0xc5, 0x6a, 0x86, 0x98,
				0x0b, 0x30, 0x74, 0x71, 0x76, 0x79, 0xd4, 0xa4,
				0x6b, 0x35, 0x92, 0x3d, 0xf9, 0x18, 0xb8, 0xd5,
				0x25, 0x66, 0xae, 0xe3, 0x48, 0x5d, 0x89, 0x61,
				0xda, 0x77, 0x0f, 0x16, 0x73, 0x0b, 0x5c, 0xba,
				0x44, 0xa2, 0x05, 0x26, 0x64, 0x1d, 0x6b, 0x85,
				0xd9, 0xad, 0x76, 0x75, 0x66, 0xed, 0xfc, 0x6e,
				0xa4, 0x35, 0x7a, 0x36, 0x21, 0xda, 0x47, 0x14,
				0x1a, 0x85, 0x7e, 0xbb, 0xfe, 0x90, 0x13, 0xcf,
				0xf4, 0x41, 0x2b, 0xa8, 0xf4, 0xc4, 0x32, 0xec,
				0xc9, 0x72, 0x74, 0xec, 0xb1, 0xb2, 0xfe, 0xc6,
				0x19, 0x3b, 0x66, 0x5f, 0x5f, 0x8f, 0x91, 0x98,
				0x96, 0x8d, 0x2d, 0x69, 0x69, 0x6e, 0xa2, 0xc6,
				0x0d, 0xd4, 0x01, 0xfa, 0x9c, 0x67, 0xeb, 0xcd,
				0x43, 0xe6, 0x31, 0x0c, 0x23, 0x7f, 0x55, 0xfc,
				0xeb, 0x7d, 0xad, 0xa5, 0x03, 0xbf, 0xf7, 0x50,
				0xde, 0x05, 0x93, 0x06, 0x30, 0x2a, 0x41, 0xa6,
				0x59, 0xf6, 0x81, 0x34, 0x98, 0xf4, 0x15, 0x3e,
				0x5b, 0x4f, 0x76, 0x8a, 0xae, 0xc7, 0xf0, 0xd0,
				0xc6, 0x59, 0x62, 0x43, 0x87, 0x0d, 0x3a, 0xb2,
				0x8c, 0xd5, 0xfd, 0x48, 0x4e, 0xea, 0x80, 0xf2,
				0x46, 0x49, 0x6f, 0xae, 0x68, 0x25, 0x62, 0x43,
				0x98, 0x01, 0x60, 0xf9, 0x4f, 0x3b, 0x86, 0x65,
				0xd7, 0x15, 0x02, 0xb2, 0x8c, 0xac, 0x36, 0x50,
				0xfa, 0xa0, 0xb5, 0x42, 0x3c, 0xdb, 0x0f, 0x5f,
				0x07, 0xbe, 0xf3, 0x17, 0x65, 0x65, 0xc4, 0xc3,
				0x46, 0x86, 0x6e, 0x19, 0xec, 0x41, 0xf9, 0x88,
				0x8a, 0x7a, 0xa6, 0xad, 0x42, 0x39, 0xf6, 0x80,
				0xaf, 0x59, 0x13, 0x82, 0xda, 0xe6, 0x50, 0xd0,
				0x18, 0xd4, 0x33, 0x62, 0xf3, 0x3f, 0xd0, 0x9d,
				0x63, 0x22, 0xed, 0xd9, 0x71, 0x27, 0x69, 0xeb,
				0x89, 0x57, 0xf7, 0x32, 0x55, 0x00, 0x0c, 0x0e,
				0x1e, 0x48, 0xe5, 0x76, 0xe9, 0x34, 0x41, 0x61,
				0x91, 0x3b, 0x78, 0xd7, 0xf2, 0xd7, 0x82, 0x7d,
				0x6a, 0xc6, 0x08, 0x13, 0x41, 0xd2, 0xd2, 0x40,
				0x41, 0x5e, 0x0b, 0x92, 0x3d, 0x04, 0xd2, 0xe5,
				0xe7, 0x6a, 0x6c, 0x66, 0xa3, 0x2b, 0x84, 0xdb,
				0xa7, 0x99, 0x12, 0x60, 0x3d, 0x44, 0x93, 0x95,
				0xd8, 0x8a, 0xc4, 0x37, 0x78, 0x2e, 0x7c, 0x83,
				0x84, 0x5e, 0x56, 0xd3, 0x09, 0xfe, 0x0a, 0x10,
				0xdc, 0xa5, 0x30, 0x19, 0x21, 0x36, 0x3f, 0xed,
				0x51, 0xb8, 0x10, 0x98, 0xaa, 0xa3, 0x34, 0x24,
				0x50, 0xb9, 0xea, 0xd5, 0xd3, 0x8e, 0x49, 0x76,
				0x62, 0x90, 0x6a, 0xbf, 0xb7, 0x32, 0x70, 0xcf,
				0x2a, 0x29, 0xb6, 0x5c, 0x66, 0x27, 0x73, 0x21,
				0xfa, 0x5a, 0xe0, 0x02, 0xa4, 0xac, 0xf2, 0xa7,
				0x2b, 0xd0, 0x6d, 0x46, 0x05, 0x5a, 0x96, 0x70,
				0x7f, 0xa2, 0xb6, 0x1a, 0x1d, 0x78, 0x5f, 0x40,
				0x47, 0xd5, 0xc3, 0xb3, 0x17, 0xeb, 0xb3, 0x64,
				0x57, 0xa4, 0x63, 0x6c, 0xbc, 0x36, 0x0e, 0xdf,
				0xc5, 0x19, 0x35, 0x29, 0xd9, 0x51, 0x0f, 0x62,
				0x11, 0x44, 0xb9, 0x57, 0x8f, 0x57, 0x70, 0x42,
				0x76, 0xa8, 0xe2, 0x70, 0xc5, 0xa8, 0x61, 0x68,
				0x08, 0x01, 0x1a, 0xb7, 0x27, 0x54, 0xd4, 0x08,
				0x6e, 0x0a, 0x22, 0x88, 0xf3, 0xb3, 0xe4, 0x0f,
				0xec, 0x0c, 0x77, 0xce, 0x65, 0x88, 0xe1, 0xf2,
				0x59, 0x16, 0xf3, 0x73, 0x08, 0x7e, 0xea, 0xfb,
				0x50, 0xd9, 0x44, 0xf0, 0x17, 0x45, 0x60, 0x07,
				0x73, 0x71, 0x9f, 0xe1, 0xe1, 0x29, 0x60, 0x3d,
				0xd2, 0xdf, 0x40, 0x53, 0xfa, 0x62, 0x4c, 0x15,
				0x31, 0x17, 0xda, 0xa7, 0xdb, 0x2d, 0x0c, 0x32,
				0x11, 0xa4, 0xb6, 0x5a, 0x50, 0x83, 0xa1, 0x1e,
				0x34, 0xb1, 0x2c, 0x23, 0xb6, 0xf1, 0xf3, 0xb7,
				0xca, 0x36, 0xf9, 0xd6, 0x66, 0xc8, 0x82, 0x64,
				0x6f, 0x5d, 0x75, 0xa1, 0x68, 0xd1, 0xf3, 0xe3,
				0x0a, 0xa4, 0x22, 0x70, 0x67, 0xdd, 0x11, 0x1f,
				0x77, 0x61, 0x54, 0xe4, 0x74, 0x29, 0xdf, 0x01,
				0x0b, 0x26, 0x84, 0x75, 0x9b, 0x3f, 0xd3, 0x9c,
				0x51, 0x6c, 0x42, 0xa6, 0x00, 0x80, 0x02, 0xe5,
				0x4a, 0xee, 0x5d, 0xe2, 0xf2, 0x63, 0xa7, 0x64,
				0xde, 0x9b, 0x89, 0x1b, 0x21, 0x54, 0x2d, 0x21,
				0x3b, 0xa1, 0x55, 0xa8, 0x56, 0xb2, 0x05, 0xb7,
				0xed, 0x2b, 0x66, 0x9e, 0x2d, 0xb8, 0x03, 0x65,
				0x11, 0x72, 0x5c, 0xe0, 0x1b, 0xcb, 0xee, 0x03,
				0x55, 0x92, 0x52, 0x3e, 0x80, 0x3e, 0xbd, 0x67,
				0x35, 0xb7, 0xce, 0x9f, 0x3b, 0xf5, 0x09, 0xba,
				0x18, 0x61, 0xcd, 0x4a, 0xf9, 0x63, 0xc9, 0x31,
				0xd0, 0x3e, 0xa3, 0x1f, 0x84, 0x3b, 0x26, 0x99,
				0x84, 0xd8, 0xd0, 0x44, 0xb8, 0x00, 0x78, 0x7e,
				0xf2, 0x46, 0x39, 0x5e, 0xa5, 0xf0, 0x7e, 0xfc,
				0x58, 0x3d, 0x55, 0xca, 0xf3, 0xd3, 0xd2, 0xf1,
				0x40, 0x5c, 0x2d, 0x70, 0xb8, 0x2b, 0x06, 0xf3,
				0x54, 0x72, 0x02, 0x67, 0x6c, 0x1b, 0x14, 0x37,
				0x94, 0x22, 0x36, 0x30, 0xe8, 0x3c, 0x9e, 0xaf,
				0xc0, 0x6f, 0x8a, 0x34, 0x50, 0xdf, 0x10, 0xb0,
				0x3a, 0xe7, 0x78, 0x7a, 0x96, 0x3e, 0x33, 0x22,
				0x12, 0xec, 0x96, 0xae, 0xb3, 0x31, 0x70, 0x5e,
				0x9f, 0x57, 0xd9, 0xb3, 0x03, 0xec, 0x58, 0x37,
				0x10, 0xb1, 0x03, 0x6c, 0x32, 0xb8, 0x96, 0x63,
				0x64, 0x6b, 0xef, 0x4a, 0x6c, 0xb2, 0xde, 0xb3,
				0x13, 0x6e, 0x83, 0x14, 0xd2, 0x12, 0x75, 0x32,
				0x96, 0xea, 0x06, 0x0b, 0x8f, 0x14, 0x9d, 0x92,
				0xde, 0xf6, 0x74, 0x52, 0x34, 0x6c, 0xe4, 0x2d,
				0xb5, 0x88, 0x61, 0xee, 0x74, 0x68, 0xad, 0xed,
				0xe4, 0x52, 0xbe, 0x05, 0xdf, 0x32, 0xa1, 0x2d,
				0x60, 0x5a, 0x57, 0x63, 0x1a, 0x5c, 0x45, 0xa2,
				0x5f, 0xe4, 0x15, 0x65, 0x84, 0x06, 0xc2, 0x27,
				0x05, 0x96, 0x05, 0xde, 0x87, 0xf9, 0x29, 0x28,
				0x22, 0x3e, 0x66, 0x74, 0xcf, 0xd6, 0x0f, 0x2c,
				0xd8, 0x6d, 0x32, 0xd5, 0x31, 0x95, 0xd5, 0x29,
				0xb1, 0xc1, 0x0e, 0xbf, 0x2b, 0x9b, 0xa0, 0x75,
				0x35, 0x82, 0x1a, 0x11, 0x15, 0x6a, 0xeb, 0xda,
				0x80, 0x50, 0x57, 0xc0, 0x41, 0x12, 0x62, 0xa9,
				0x79, 0xc3, 0xbe, 0x04, 0x72, 0x48, 0x9a, 0x4c,
				0x4c, 0x68, 0x61, 0x14, 0x17, 0xb3, 0x3d, 0xc3,
				0xaf, 0xf2, 0x22, 0x50, 0x33, 0x61, 0x78, 0x6d,
				0x82, 0x2e, 0x81, 0xb0, 0xe2, 0x3c, 0x33, 0x82,
				0x7e, 0x93, 0xd1, 0xc8, 0x76, 0x62, 0xcf, 0x8b,
				0xcb, 0x7e, 0xee, 0xf1, 0xb4, 0x10, 0x73, 0x80,
				0x7a, 0xae, 0x77, 0x71, 0x48, 0x81, 0x30, 0x96,
				0x1a, 0x1d, 0xde, 0x77, 0x49, 0x2a, 0x04, 0xd1,
				0x06, 0xb7, 0xa9, 0xbe, 0x31, 0x20, 0xe4, 0x22,
				0xca, 0x60, 0x17, 0xec, 0x08, 0x3a, 0x85, 0x75,
				0x04, 0x59, 0x27, 0x44, 0xfa, 0x1d, 0x50, 0x0f,
				0x50, 0x13, 0x95, 0xc5, 0x5c, 0xe0, 0xcf, 0x3a,
				0xee, 0x40, 0xa8, 0xc5, 0xb3, 0x30, 0x33, 0x43,
				0x53, 0xe5, 0x80, 0x45, 0x1f, 0x94, 0xac, 0xde,
				0x8d, 0x46, 0xb5, 0xfa, 0x39, 0xed, 0xa6, 0x51,
				0xd4, 0x68, 0x16, 0x57, 0xd1, 0x05, 0xf0, 0x37,
				0x3d, 0x5f, 0xcb, 0x15, 0xc0, 0xb1, 0xe8, 0x7d,
				0xd6, 0xca, 0x65, 0xe0, 0x13, 0x08, 0x81, 0x3f,
				0xea, 0xe0, 0xfb, 0x85, 0x99, 0x1e, 0x9c, 0xdf,
				0x43, 0xe2, 0x04, 0xec, 0x8d, 0x79, 0x06, 0x4b,
				0x1e, 0x98, 0x78, 0x91, 0x2e, 0x94, 0x10, 0x4e,
				0x60, 0x66, 0x55, 0xb2, 0x50, 0x44, 0x19, 0x59,
				0x7f, 0x5b, 0xc2, 0x11, 0x03, 0xa7, 0x13, 0xa8,
				0x44, 0x70, 0x74, 0x9b, 0x48, 0x81, 0x15, 0x2e,
				0x30, 0x50, 0x15, 0x2b, 0xef, 0xde, 0x8b, 0x45,
				0x0d, 0xdd, 0x2a, 0x28, 0x05, 0xaa, 0x6d, 0x06,
				0x47, 0x84, 0x09, 0xd6, 0x0a, 0xb2, 0x5b, 0xa0,
				0xda, 0xb6, 0xe5, 0x87, 0x42, 0x28, 0xfe, 0x1a,
				0x4a, 0x27, 0xd5, 0x50, 0x7c, 0x9e, 0x2d, 0x8c,
				0x8b, 0x78, 0x73, 0x30, 0x5f, 0x8a, 0x06, 0x4d,
				0xab, 0x24, 0x14, 0x3b, 0xd3, 0xb1, 0x11, 0xba,
				0x0a, 0x15, 0xdb, 0x9b, 0x96, 0x05, 0x22, 0x16,
				0x58, 0x73, 0xca, 0x77, 0x0d, 0xf4, 0x97, 0xa0,
				0x68, 0x7d, 0x67, 0x3d, 0xfc, 0x8a, 0x88, 0xb4,
				0x8b, 0x8f, 0xce, 0x0f, 0x56, 0xce, 0xdc, 0xcd,
				0x20, 0x7c, 0x65, 0x8e, 0x7c, 0xf6, 0x18, 0x3d,
				0x6f, 0x23, 0x1d, 0xb2, 0x91, 0x2a, 0xd3, 0x06,
				0xb9, 0xf5, 0x02, 0x0c, 0x5a, 0xa5, 0x1a, 0x75,
				0x43, 0xd5, 0xe7, 0xf6, 0xdf, 0xfb, 0xd3, 0x3b,
				0x54, 0x08, 0x5c, 0xce, 0xf1, 0x72, 0x22, 0xc3,
				0x52, 0x72, 0xfa, 0xd3, 0x94, 0xf3, 0x19, 0xc9,
				0x68, 0x33, 0xc9, 0x99, 0x88, 0x63, 0xf0, 0x84,
				0xbf, 0x2f, 0x7d, 0xf4, 0x5d, 0x75, 0x83, 0x23,
				0x24, 0x63, 0x82, 0x24, 0x64, 0x27, 0xf7, 0x92,
				0xa6, 0x5c, 0x97, 0x1d, 0x24, 0x78, 0x3b, 0x8b,
				0x06, 0xf1, 0x25, 0x33, 0x59, 0x4f, 0x8d, 0xf9,
				0x8a, 0x25, 0xd3, 0x62, 0x68, 0x42, 0x2b, 0x84,
				0x7a, 0x45, 0x3c, 0x14, 0x57, 0x0e, 0x25, 0x71,
				0x4e, 0xef, 0xc6, 0x38, 0x50, 0x3d, 0xc3, 0xf7,
				0x2d, 0x55, 0xd4, 0x09, 0x2e, 0x83, 0x65, 0xba,
				0x9b, 0x3c, 0x62, 0x66, 0xbd, 0x9f, 0xe6, 0x16,
				0xd7, 0x99, 0x34, 0x48, 0x29, 0x55, 0x69, 0x91,
				0xb2, 0x91, 0xf5, 0x68, 0xc5, 0xa0, 0xee, 0xd5,
				0x20, 0x12, 0xdb, 0x00, 0x27, 0x2a, 0xaa, 0xed,
				0x66, 0x75, 0xda, 0x84, 0x55, 0x4c, 0x48, 0xf6,
				0x4e, 0xb4, 0x94, 0xab, 0x47, 0x71, 0x6e, 0x11,
				0xc4, 0x45, 0x23, 0x25, 0xf4, 0x9e, 0xd5, 0x6f,
				0xa3, 0x91, 0xe5, 0x9a, 0xe0, 0x0a, 0x97, 0xea,
				0x60, 0x58, 0x00, 0x27, 0x6a, 0x25, 0x86, 0x46,
				0x1e, 0x3f, 0xa0, 0x94, 0xd5, 0xd1, 0x81, 0xa3,
				0xec, 0xa4, 0x5e, 0xcf, 0x51, 0xb8, 0xc5, 0x82,
				0x14, 0x73, 0x01, 0x77, 0xfe, 0xf3, 0x39, 0xd6,
				0x60, 0x86, 0x84, 0xc7, 0x7e, 0x4f, 0x2f, 0x08,
				0x1b, 0xc6, 0x11, 0x67, 0xa4, 0x01, 0x48, 0xb4,
				0xa1, 0xa9, 0x66, 0x39, 0xd5, 0xc9, 0x77, 0xc8,
				0x33, 0xdb, 0x4a, 0xf6, 0x26, 0x0d, 0xda, 0x1f,
				0x89, 0x48, 0x82, 0xa9, 0x61, 0x88, 0x5d, 0x26,
				0x4f, 0x33, 0x21, 0x05, 0x72, 0xa0, 0x99, 0xec,
				0x2f, 0x70, 0xe7, 0xa0, 0xf2, 0x5a, 0x07, 0xd3,
				0x6e, 0xf0, 0x56, 0xd2, 0x52, 0xc6, 0x2b, 0xe5,
				0x5a, 0x62, 0x66, 0x12, 0x2f, 0x39, 0x6d, 0xf0,
				0xc0, 0xbf, 0x64, 0xef, 0x54, 0xac, 0x24, 0x50,
				0x76, 0xf6, 0x8d, 0x52, 0xa8, 0x5f, 0x97, 0xe1,
				0xc6, 0xb6, 0xd3, 0x08, 0x54, 0xd7, 0x0d, 0x54,
				0xa7, 0x74, 0xe0, 0x92, 0xf9, 0x8a, 0x9b, 0x42,
				0xe8, 0xdd, 0xb3, 0xb0, 0x71, 0x11, 0xd2, 0xd0,
				0x72, 0x77, 0xac, 0xc5, 0xa8, 0xc7, 0xb1, 0xde,
				0x58, 0x1f, 0x47, 0x66, 0x61, 0xc3, 0x03, 0x5e,
				0x41, 0xdc, 0x0c},
		},
	},
	TxFee: 0,
	TxWitness: &wire.TxWitnessAbe{ //len(TxWitness.Witnesses)==0
		Witnesses: []wire.Witness{},
	},
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x40, 0x45, 0xe3, 0x50, 0xa8, 0x9d, 0x60, 0xda,
	0x2b, 0xaa, 0xb4, 0xcb, 0x4c, 0xf8, 0x59, 0x16,
	0xa5, 0x08, 0x1c, 0x45, 0xad, 0xb2, 0xf5, 0xbd,
	0xfa, 0xc8, 0x0b, 0x46, 0x01, 0x00, 0x00, 0x00,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{
	0xf2, 0x53, 0x2a, 0x3d, 0x9f, 0x84, 0x08, 0x4a,
	0x60, 0xf7, 0x1c, 0xcf, 0x69, 0x1c, 0xe3, 0x0d,
	0x40, 0xf5, 0xde, 0x95, 0x19, 0x16, 0x31, 0x31,
	0xb0, 0xba, 0xf8, 0x9e, 0x24, 0x65, 0x1d, 0xf8,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlockAbe{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x5f2ea276, 0), // 2020-07-09 16:55:41 +0800 CST
		Bits:       0x1d07ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x4105ab22,               // 3890968129
	},
	Transactions: []*wire.MsgTxAbe{&genesisCoinbaseTx},
}

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
var regTestGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x75, 0x99, 0x54, 0x33, 0x94, 0x63, 0x01, 0x97,
	0x90, 0xf2, 0xc5, 0xda, 0xea, 0xad, 0x6f, 0xa0,
	0xc0, 0xfa, 0x30, 0x0d, 0x5f, 0x51, 0x77, 0xd2,
	0xd7, 0xd4, 0xe8, 0xaf, 0x8b, 0x67, 0x1d, 0x4c,
})

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = genesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlockAbe{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x5f125ae8, 0), // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      0xf20d5365,
	},
	Transactions: []*wire.MsgTxAbe{&genesisCoinbaseTx},
}

// testNet3GenesisHash is the hash of the first block in the block chain for the
// test network (version 3).
var testNet3GenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
	0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
	0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
	0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
})

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet3GenesisMerkleRoot = genesisMerkleRoot

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet3GenesisBlock = wire.MsgBlockAbe{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet3GenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(1296688602, 0),  // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x1d00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x18aea41a,                // 414098458
	},
	Transactions: []*wire.MsgTxAbe{&genesisCoinbaseTx},
}

// simNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var simNetGenesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0xb9, 0x0a, 0xe1, 0xe6, 0x0a, 0x56, 0xb8, 0x17,
	0xf6, 0x95, 0xf5, 0xca, 0x77, 0x1e, 0xa0, 0x2d,
	0x20, 0x11, 0xc0, 0x55, 0x04, 0x23, 0xed, 0x12,
	0x1a, 0xd4, 0x4b, 0x70, 0xa3, 0x57, 0x97, 0x41,
})

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var simNetGenesisMerkleRoot = genesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = wire.MsgBlockAbe{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: simNetGenesisMerkleRoot,  // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x5f1a4321, 0), // 2014-05-28 15:52:37 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      0xbffffffe,
	},
	Transactions: []*wire.MsgTxAbe{&genesisCoinbaseTx},
}
