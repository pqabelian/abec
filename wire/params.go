package wire

import (
	"errors"
)

// These vesion-consts are used to maintain the history TxVersion.
const (
	TxVersion_Height_0 uint32 = iota + 1 // the TxVersion since height 0, corresponding to CryptoSchemePQRingCT
	//CryptoSchemePQRingCTV2
	// ToDo(MLP): how about not use iota?
	TxVersion_Height_MLPAUT_236000 uint32 = 2
)

const (
	// TxVersion is the current latest supported transaction version.
	// TxVersion is used by Tx and Txo, where Txo uses the same version as the Tx creates it.
	// TxVersion is closely related to crypto-scheme in abecryptoparam package, namely, when the underlying crypto scheme updates, the TxVersion needs to update.
	// The reason is that Tx is generated and verified by the underlying cryptoscheme.
	// The mapping/relation between txVersion and crypto-Scheme will be hardcoded in abecryptoparam package, depending on the design.
	// A block shall collect the Txs with the same TxVersion, so that the Txos in a block share the same version.
	// A ring shall collect the Txos with the same version, to guarantee the ring can be processed by a corresponding crypto-scheme.
	// The ring version is same as that of the Txos in the ring.
	// In summary,
	// (1) When a Tx is created, it uses the latest TxVersion value; and the TxOuts use the same Version as the Tx;
	// (2) A block will collect the Txs with the same Version, which implies the corresponding TxOuts also share the same Version;
	// (3) When the TxOuts in blocks are grouped to rings, ring uses the same version as its member TxoOuts;
	// (4) The input rings of a transferTx shall have the same ringVersion (since this can guarantee all the member Txos have the same version);
	// (5) The input ringVersion of a transferTx may be different (older) from the TxVersion of the transferTx,
	//     the TransferTxGen shall handle the cases by making use of the (InputRingVersion, TxVersion) to different "branch".
	//		in particular, suppose there are history versions TxVersion1 and TxVersion2, and we are updating the version to TxVersion,
	//		we need to provide TransferTxGen implementation logics for (TxVersion1, TxVersion) and (TxVersion2, TxVersion).
	//	Note that when underlying crypto-scheme updates, TxVersion must update.
	//	But on the other side, TxVersion updates do not only work for crypto-scheme update, and it works for all possible updates.
	//	That's why we need to maintain the mapping of (CryptoScheme, TxVersion).

	//	TxVersion = 1
	TxVersion = TxVersion_Height_0

	//	todo: (EthashPow) BlockVersionEthashPow
	// BlockVersionEthashPow is the block version which changed block to use EthashPoW
	//	This causes hard-fork.
	//	Thus, we set it to 0x20000000, while the previous (original) version is 0x10000000.
	BlockVersionEthashPow = 0x20000000

	// BlockVersionMLPAUT is the block version which changed block to support MLP and AUT.
	// The version is coded by the rule in versionbits.go
	// ToDo(MLP):
	BlockVersionMLPAUT = 0x30000000

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW denotes the block height from which Ethash-PoW mining is applied.
	//	BlockHeightEthashPoW = 56000
)

/*
*
BlockNumPerRingGroup and TxRingSize define the rules for ring，
being a part of the protocol rules, depending on the design.
If the value of the two parameters change, it needs vote and may cause fork.
BlockNumPerRingGroup and TxoRingSize are the current setting.
For history settings, the value of the two parameters are bounded to TxVersion, since
TxVersion --> TxoVersion --> RingVersion --> Ring.
When the two parameters update, the history version should be kept, e.g. with a postfix implying the version.
*/
const (
	//	BlockNumPerRingGroup should not be too large, we suppose it to be at most 2^8-1, i.e., uint8
	BlockNumPerRingGroup = 3
	//	TxoRingSize should not be too large, we suppose it to be at most 2^8-1, i.e., uint8
	TxoRingSize = 7
)

// GetBlockNumPerRingGroupByRingVersion() returns the BlockNumPerRingGroup value corresponding to a version, which should be a TxVersion/TxoVersion/RingVersion.
// The mapping between TxVersion and BlockNumPerRingGroup is hardcode here.
func GetBlockNumPerRingGroupByRingVersion(version uint32) (uint8, error) {
	switch version {
	case 1:
		return BlockNumPerRingGroup, nil

	default:
		return 0, errors.New("GetBlockNumPerRingGroupByRingVersion: Unsupported ringVersion")
	}
}

// GetBlockNumPerRingGroupByBlockHeight() returns the BlockNumPerRingGroup value corresponding to a block height.
// When BlockNumPerRingGroup changes, it may cause fork.
// As the forks depend on the chain height, we need to hardcode the mapping between block height and BlockNumPerRingGroup.
// The mapping between block height and BlockNumPerRingGroup is hardcoded here.
func GetBlockNumPerRingGroupByBlockHeight(height int32) uint8 {
	return BlockNumPerRingGroup
}

// GetTxoRingSizeByRingVersion() returns the TxoRingSize value corresponding to a version, which should be a TxVersion/TxoVersion/RingVersion.
// The mapping between TxVersion and TxoRingSize is hardcode here.
func GetTxoRingSizeByRingVersion(version uint32) (uint8, error) {
	switch version {
	case 1:
		return TxoRingSize, nil

	default:
		return 0, errors.New("GetTxoRingSizeByRingVersion: Unsupported ringVersion")
	}
}

// GetTxoRingSizeByBlockHeight() returns the TxoRingSize value corresponding to a block height.
// When TxoRingSize changes, it may cause fork.
// As the forks depend on the chain height, we need to hardcode the mapping between block height and TxoRingSize.
// The mapping between block height and TxoRingSize is hardcoded here.
func GetTxoRingSizeByBlockHeight(height int32) uint8 {
	return TxoRingSize
}

// WireParam define the blockchain protocol.
// Blockchain is essentially a P2P network, so the protocol
// and the parameter of blockchain is the fundamental.
type WireParam struct {
	//	The wireVersion is the unique identifier for WireParam.
	//	Any change of other fields will cause a new version of WireParam to be added.
	//	The wireVersion shall be used by peer-connect protocols.
	wireVersion uint32
}
