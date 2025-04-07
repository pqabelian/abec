package blockchain

import (
	"fmt"
	"github.com/pqabelian/abec/abecryptox"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/database"
	"github.com/pqabelian/abec/wire"
)

// These constants are used to initialize the capacity for the corresponding slice.
// These constants should be set according to a computation and evaluation on number of transactions in a block,
// and they could be adjusted later,
// for example, after MLPAUT_FORK_COMMIT, the first two could be adjusted to small, since they are expected to be 0.
const (
	defaultCoinbaseRmTxoNumWithTxVersionInit      = 3
	defaultTransferRmTxoNumWithTxVersionInit      = 30
	defaultCoinbaseRmTxoNumWithTxVersionMLPAUTRCT = 3
	defaultCoinbaseRmTxoNumWithTxVersionMLPAUTSDN = 3
	defaultTransferRmTxoNumWithTxVersionMLPAUTRCT = 30
	defaultTransferRmTxoNumWithTxVersionMLPAUTSDN = 300
)

// newUtxoRingEntriesMLP creates new UtxoRingEntries for the input block, which serves as the last block for the block-group.
// reviewed on 2024.01.04
func (view *UtxoRingViewpoint) newUtxoRingEntriesMLP(db database.DB, node *blockNode, block *abeutil.BlockAbe) error {
	if node == nil || block == nil {
		return AssertError("newUtxoRingEntriesMLP: newUtxoRingEntriesMLP is called with nil node or nil block.")
	}

	//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
	//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
	blockNumPerRingGroup := int(wire.GetBlockNumPerRingGroupByBlockHeight(node.height))
	txoRingSize := int(wire.GetTxoRingSizeByBlockHeight(node.height))
	if !(node.height%int32(blockNumPerRingGroup) == int32(blockNumPerRingGroup)-1) {
		return AssertError("newUtxoRingEntriesMLP: newUtxoRingEntriesMLP is called with node where node.height % BlockNumPerRingGroup != BlockNumPerRingGroup-1.")
	}

	if !view.bestHash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntriesMLP: newUtxoRingEntriesMLP is called with block's hash not equal to the view.bestHash")
	}

	if !node.hash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntriesMLP: newUtxoRingEntriesMLP is called with block that has different hash with the node.")
	}

	ringBlockHeight := block.Height()
	blockNum := blockNumPerRingGroup
	//	read blocks from database
	prevNode := node.parent
	blocks := make([]*abeutil.BlockAbe, blockNum)
	blocks[blockNum-1] = block
	for i := blockNum - 2; i >= 0; i-- {
		if prevNode == nil {
			return AssertError("newUtxoRingEntriesMLP: newUtxoRingEntriesMLP is called with node that does not have (BlockNumPerRingGroup-1) previous successive blocks in database")
		}
		err := db.View(func(dbTx database.Tx) error {
			var err error
			blocks[i], err = dbFetchBlockByNodeAbe(dbTx, prevNode)
			return err
		})
		if err != nil {
			return err
		}
		prevNode = prevNode.parent
	}

	newTxoRings, err := BuildTxoRingsMLP(blockNum, txoRingSize, blocks)
	if err != nil {
		return err
	}

	for ringId, txoRing := range newTxoRings {
		if _, ok := view.entries[ringId]; ok {
			return AssertError(fmt.Sprintf("newUtxoRingEntriesMLP: Found a hash collision (by RingId) when calling newUtxoRingEntriesMLP with blocks (hash %v, ringHeight %d, ringId %v)",
				node.hash, ringBlockHeight, ringId))
		} else {
			newUtxoRingEntry := InitNewUtxoRingEntryMLP(txoRing)
			view.entries[ringId] = newUtxoRingEntry
		}
	}

	return nil

}

// BuildTxoRingsMLP builds txoRings for the input blocks.
// reviewed on 2024.01.04
func BuildTxoRingsMLP(blockNumPerRingGroup int, txoRingSize int, blocks []*abeutil.BlockAbe) (txoRings map[wire.RingId]*wire.TxoRing, err error) {
	//blockNum := blockNumPerRingGroup

	if blockNumPerRingGroup < 1 {
		return nil, AssertError("BuildTxoRingsMLP: number of blocks is smaller than 1")
	}

	if len(blocks) != blockNumPerRingGroup {
		return nil, AssertError("BuildTxoRingsMLP: number of blocks does not match the parameter blockNumPerRingGroup")
	}

	for i := 0; i < blockNumPerRingGroup; i++ {
		if blocks[i] == nil {
			return nil, AssertError("BuildTxoRingsMLP: there are nil in the input blocks")
		}
	}

	ringBlockHeight := blocks[blockNumPerRingGroup-1].Height()
	for i := blockNumPerRingGroup - 1; i >= 0; i-- {
		if blocks[i].Height() != ringBlockHeight-(int32(blockNumPerRingGroup)-1-int32(i)) {
			return nil, AssertError("BuildTxoRingsMLP: the input blocks should have successive height")
		}
	}

	blockHashStr := make([]byte, blockNumPerRingGroup*chainhash.HashSize)
	//	blockHashStr is used only for the hint of hash-collision happening
	for i := 0; i < blockNumPerRingGroup; i++ {
		copy(blockHashStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	//	2023.12.24 MLP Fork
	//	With the MLP_Fork, there are two TxVersions, say, TxVersion_Height_0 and TxVersion_Height_MLPAUT_300000,
	//	For TxVersion_Height_0, all Txos have the same privacy-level: RingCTPre, and all these Txos will be collected together and divided into rings.
	//	For TxVersion_Height_MLPAUT_300000, the Txos may have three privacy-level, say, RingCTPre, RingCT, and Pseudonym,
	//		the Txos of RingCTPre and RingCT will be collected together and divided into rings,
	//		the Txos of Pseudonym will be collected and divided into rings with size 1.
	//	NOTE: when there are more cases ,we need to hard code the ring-building process here.

	allCoinbaseRmTxoWithTxVersionInit := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionInit)
	allTransferRmTxoWithTxVersionInit := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionInit)
	allCoinbaseRmTxoWithTxVersionMLPAUTRCT := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTRCT)
	allCoinbaseRmTxoWithTxVersionMLPAUTSDN := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTSDN)
	allTransferRmTxoWithTxVersionMLPAUTRCT := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTRCT)
	allTransferRmTxoWithTxVersionMLPAUTSDN := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTSDN)

	// str = block1.hash, block2.hash, block3.hash, blockhash, txHash, outIndex
	// all Txos are ordered by Hash(str), then grouped into rings
	txoSortStr := make([]byte, blockNumPerRingGroup*chainhash.HashSize+chainhash.HashSize+chainhash.HashSize+1)
	//	(1) block1.hash, block2.hash, block3.hash
	for i := 0; i < blockNumPerRingGroup; i++ {
		copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	blockHashes := make([]*chainhash.Hash, blockNumPerRingGroup) // blockHashes is collected for later use in buildTxoRingsFromTxos
	for i := 0; i < blockNumPerRingGroup; i++ {
		blockHashes[i] = blocks[i].Hash()

		blockHash := blocks[i].Hash()
		blockHeight := blocks[i].Height()

		//	(2) block hash
		copy(txoSortStr[blockNumPerRingGroup*chainhash.HashSize:], blockHash[:])

		//	coinbase transaction
		cbTx := blocks[i].Transactions()[0]
		isCbTx, err := cbTx.IsCoinBase()
		if err != nil {
			return nil, err
		}
		if !isCbTx {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's first transaction is not coinbase transaction", i))
		}

		//	(3) tx hash
		txHash := cbTx.Hash()
		copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])

		for outIndex, txOut := range cbTx.MsgTx().TxOuts {
			//	(4) outIndex
			txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

			txoOrderHash := chainhash.DoubleHashH(txoSortStr)

			ringMemberTxo := NewRingMemberTxo(txOut.Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)

			if txOut.Version != cbTx.MsgTx().Version {
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's coinbase transaction's %d -th txo has a version different from that of tx", i, outIndex))
			}

			//	put into corresponding group
			switch txOut.Version {
			case wire.TxVersion_Height_0:
				allCoinbaseRmTxoWithTxVersionInit = append(allCoinbaseRmTxoWithTxVersionInit, ringMemberTxo)

			case wire.TxVersion_Height_MLPAUT_300000:
				privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
				if err != nil {
					return nil, err
				}
				switch privacyLevel {
				case abecryptoxkey.PrivacyLevelRINGCTPre:
					allCoinbaseRmTxoWithTxVersionMLPAUTRCT = append(allCoinbaseRmTxoWithTxVersionMLPAUTRCT, ringMemberTxo)

				case abecryptoxkey.PrivacyLevelRINGCT:
					allCoinbaseRmTxoWithTxVersionMLPAUTRCT = append(allCoinbaseRmTxoWithTxVersionMLPAUTRCT, ringMemberTxo)

				case abecryptoxkey.PrivacyLevelPSEUDONYM:
					allCoinbaseRmTxoWithTxVersionMLPAUTSDN = append(allCoinbaseRmTxoWithTxVersionMLPAUTSDN, ringMemberTxo)

				default:
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's coinbase transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, outIndex, privacyLevel))
				}

			default:
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's coinbase transaction's version is not supported", i))
			}
		}

		//	transfer transactions
		for t, trTx := range blocks[i].Transactions()[1:] {
			isCbTx, err = trTx.IsCoinBase()
			if err != nil {
				return nil, err
			}
			if isCbTx {
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's %d -th transaction is a coinbase transaction", i, t))
			}

			//	(3) tx hash
			txHash = trTx.Hash()
			copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range trTx.MsgTx().TxOuts {
				//	(4) outIndex
				txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := NewRingMemberTxo(txOut.Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)

				if txOut.Version != trTx.MsgTx().Version {
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's %d -th transaction's %d -th txo has a version different from that of tx", i, t, outIndex))
				}

				//	put into corresponding group
				switch txOut.Version {
				case wire.TxVersion_Height_0:
					allTransferRmTxoWithTxVersionInit = append(allTransferRmTxoWithTxVersionInit, ringMemberTxo)

				case wire.TxVersion_Height_MLPAUT_300000:
					privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
					if err != nil {
						return nil, err
					}
					switch privacyLevel {
					case abecryptoxkey.PrivacyLevelRINGCTPre:
						allTransferRmTxoWithTxVersionMLPAUTRCT = append(allTransferRmTxoWithTxVersionMLPAUTRCT, ringMemberTxo)

					case abecryptoxkey.PrivacyLevelRINGCT:
						allTransferRmTxoWithTxVersionMLPAUTRCT = append(allTransferRmTxoWithTxVersionMLPAUTRCT, ringMemberTxo)

					case abecryptoxkey.PrivacyLevelPSEUDONYM:
						allTransferRmTxoWithTxVersionMLPAUTSDN = append(allTransferRmTxoWithTxVersionMLPAUTSDN, ringMemberTxo)

					default:
						return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's %d -th transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, t, outIndex, privacyLevel))
					}

				default:
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: the %d -th input block's %d -th transaction's version is not supported", i, t))
				}
			}
		}
	}

	log.Debugf("BuildTxoRingsMLP: %d blocks are building rings for ringBlockHeight %d: "+
		"coinBaseRmTxoNumTxVersionInit = %d, transferRmTxoNumTxVersionInit = %d, "+
		"coinBaseRmTxoNumTxVersionMLPAUTRCT = %d, coinBaseRmTxoNumTxVersionMLPAUTSDN = %d, "+
		"transferRmTxoNumTxVersionMLPAUTRCT = %d, transferRmTxoNumTxVersionMLPAUTSDN = %d",
		blockNumPerRingGroup, ringBlockHeight,
		len(allCoinbaseRmTxoWithTxVersionInit), len(allTransferRmTxoWithTxVersionInit),
		len(allCoinbaseRmTxoWithTxVersionMLPAUTRCT), len(allCoinbaseRmTxoWithTxVersionMLPAUTSDN),
		len(allTransferRmTxoWithTxVersionMLPAUTRCT), len(allTransferRmTxoWithTxVersionMLPAUTSDN))

	//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	cbTxoRingsWithTxVersionInit, err := buildTxoRingsFromTxos(allCoinbaseRmTxoWithTxVersionInit, ringBlockHeight, blockHashes, txoRingSize, true)
	if err != nil {
		return nil, err
	}

	trTxoRingsWithTxVersionInit, err := buildTxoRingsFromTxos(allTransferRmTxoWithTxVersionInit, ringBlockHeight, blockHashes, txoRingSize, false)
	if err != nil {
		return nil, err
	}

	cbTxoRingsWithTxVersionMLPAUTRCT, err := buildTxoRingsFromTxos(allCoinbaseRmTxoWithTxVersionMLPAUTRCT, ringBlockHeight, blockHashes, txoRingSize, true)
	if err != nil {
		return nil, err
	}

	trTxoRingsWithTxVersionMLPAUTRCT, err := buildTxoRingsFromTxos(allTransferRmTxoWithTxVersionMLPAUTRCT, ringBlockHeight, blockHashes, txoRingSize, false)
	if err != nil {
		return nil, err
	}

	cbTxoRingsWithTxVersionMLPAUTSDN, err := buildTxoRingsFromTxosForSingle(allCoinbaseRmTxoWithTxVersionMLPAUTSDN, ringBlockHeight, blockHashes, true)
	if err != nil {
		return nil, err
	}

	trTxoRingsWithTxVersionMLPAUTSDN, err := buildTxoRingsFromTxosForSingle(allTransferRmTxoWithTxVersionMLPAUTSDN, ringBlockHeight, blockHashes, false)
	if err != nil {
		return nil, err
	}

	rstRingNum := len(cbTxoRingsWithTxVersionInit) + len(trTxoRingsWithTxVersionInit) +
		len(cbTxoRingsWithTxVersionMLPAUTRCT) + len(trTxoRingsWithTxVersionMLPAUTRCT) +
		len(cbTxoRingsWithTxVersionMLPAUTSDN) + len(trTxoRingsWithTxVersionMLPAUTSDN)

	rstTxoRings := make(map[wire.RingId]*wire.TxoRing, rstRingNum)

	for i, txoRing := range cbTxoRingsWithTxVersionInit {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: cbTxoRingsWithTxVersionInit[%d], ring size = %d, , ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionInit {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: trTxoRingsWithTxVersionInit[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range cbTxoRingsWithTxVersionMLPAUTRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: cbTxoRingsWithTxVersionMLPAUTRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionMLPAUTRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: trTxoRingsWithTxVersionMLPAUTRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range cbTxoRingsWithTxVersionMLPAUTSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: cbTxoRingsWithTxVersionMLPAUTSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionMLPAUTSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsMLP: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsMLP: trTxoRingsWithTxVersionMLPAUTSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}

	return rstTxoRings, nil

}

// InitNewUtxoRingEntryMLP initializes a new UtxoRingEntry from the input wire.TxoRing.
// reviewed on 2024.01.04
func InitNewUtxoRingEntryMLP(txoRing *wire.TxoRing) *UtxoRingEntry {
	utxoRingEntry := &UtxoRingEntry{
		Version:             txoRing.Version,
		ringBlockHeight:     txoRing.RingBlockHeight,
		outPointRing:        txoRing.OutPointRing,
		txOuts:              txoRing.TxOuts,
		serialNumbers:       nil,
		consumingBlockHashs: nil,
		packedFlags:         tfModified,
	}

	if txoRing.IsCoinbase {
		utxoRingEntry.packedFlags |= tfCoinBase
	}
	return utxoRingEntry
}

// buildTxoRingsFromTxosForSingle builds rings with ringSize = 1 from the input ringMemberTxos,
// i.e., each ringMemberTxo will form a ring.
// reviewed on 2024.01.04
func buildTxoRingsFromTxosForSingle(ringMemberTxos []*RingMemberTxo, ringBlockHeight int32, blockHashes []*chainhash.Hash, isCoinBase bool) (txoRings []*wire.TxoRing, err error) {

	if len(ringMemberTxos) == 0 {
		return nil, nil
	}

	rstTxoRings := make([]*wire.TxoRing, len(ringMemberTxos))

	// txoRingSize := 1
	for i := 0; i < len(ringMemberTxos); i++ {
		rstTxoRings[i], err = NewTxoRing(ringMemberTxos[i].version, ringBlockHeight, blockHashes, ringMemberTxos[i:i+1], isCoinBase)
		if err != nil {
			return nil, err
		}
	}

	return rstTxoRings, nil
}
