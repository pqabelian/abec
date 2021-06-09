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
			SerialNumber: chainhash.ZeroHash[:], // imply this is a coinbase transaction
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
			Version:wire.TxVersion ,
			TxoScript: []byte{},
		},
	},
	TxFee: 0,
	TxWitness: []byte{
	},
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
//var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
//	0x85, 0x15, 0xde, 0xf3, 0xd6, 0x44, 0xb2, 0x86,
//	0xd4, 0x17, 0xec, 0x7d, 0x60, 0xa5, 0x2d, 0x2e,
//	0x64, 0xea, 0x1d, 0x51, 0xba, 0xf5, 0x25, 0x77,
//	0x4f, 0xad, 0x0e, 0x8b, 0x05, 0x00, 0x00, 0x00,
//})
var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x1e, 0x91, 0x7e, 0x04, 0xfc, 0x2b, 0x3f, 0x81,
	0xff, 0x61, 0x5b, 0x2a, 0xef, 0x7d, 0x68, 0x18,
	0x44, 0xa5, 0x69, 0x90, 0x3b, 0x1b, 0x24, 0x37,
	0x98, 0x8f, 0x38, 0xe1, 0x6e, 0x01, 0x00, 0x00,
})

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
//var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{
//	0x66, 0xba, 0x15, 0xe1, 0x00, 0xce, 0x25, 0x18,
//	0x1f, 0x7c, 0x6d, 0x41, 0xad, 0xec, 0xe7, 0xab,
//	0x5d, 0xfc, 0xbb, 0x5b, 0xad, 0x9e, 0xb9, 0x75,
//	0x6c, 0x5c, 0x0c, 0xab, 0x71, 0xc9, 0x1c, 0xf4,
//})
var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{
	0xdc, 0xc4, 0xfb, 0x07, 0xa0, 0x7b, 0x9d, 0x6b,
	0x6a, 0x67, 0xed, 0x28, 0x8f, 0x55, 0xdb, 0x6b,
	0x8e, 0x8f, 0x84, 0xbc, 0x67, 0xdc, 0x85, 0x6b,
	0x89, 0x6d, 0xc7, 0x63, 0xdf, 0xaf, 0xbe, 0x05,
})

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
//var genesisBlock = wire.MsgBlockAbe{
//	Header: wire.BlockHeader{
//		Version:    1,
//		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
//		MerkleRoot: genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
//		Timestamp:  time.Unix(0x5f659cd6, 0), // 2020-07-09 16:55:41 +0800 CST
//		Bits:       0x1d07ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
//		Nonce:      0x496611ff,               // 3890968129
//	},
//	Transactions: []*wire.MsgTxAbe{&genesisCoinbaseTx},
//}
var genesisBlock = wire.MsgBlockAbe{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},
		MerkleRoot: genesisMerkleRoot,
		Timestamp:  time.Unix(0x6038f247, 0),
		Bits:       0x1e01ffff,
		Nonce:      0x10ab387,
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
