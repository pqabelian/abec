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

// newUTxoRingEntriesAconcagua creates new UTxoRingEntries for the input block,
// which serves as the last block for the block-group.
//
// This function backward compatible with the function newUTxoRingEntriesMLP,
// so that the call on newUTxoRingEntriesMLP can be replaced by call on this function.
func (view *UtxoRingViewpoint) newUTxoRingEntriesAconcagua(db database.DB, node *blockNode, block *abeutil.BlockAbe) error {
	if node == nil || block == nil {
		return AssertError("newUTxoRingEntriesAconcagua: newUTxoRingEntriesAconcagua is called with nil node or nil block.")
	}

	//	todo: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
	//	Here we should call wire.GetBlockNumPerRingGroupByBlockHeight()
	blockNumPerRingGroup := int(wire.GetBlockNumPerRingGroupByBlockHeight(node.height))
	txoRingSize := int(wire.GetTxoRingSizeByBlockHeight(node.height))
	if !(node.height%int32(blockNumPerRingGroup) == int32(blockNumPerRingGroup)-1) {
		return AssertError("newUTxoRingEntriesAconcagua: newUTxoRingEntriesAconcagua is called with node where node.height % BlockNumPerRingGroup != BlockNumPerRingGroup-1.")
	}

	if !view.bestHash.IsEqual(block.Hash()) {
		return AssertError("newUTxoRingEntriesAconcagua: newUTxoRingEntriesAconcagua is called with block's hash not equal to the view.bestHash")
	}

	if !node.hash.IsEqual(block.Hash()) {
		return AssertError("newUTxoRingEntriesAconcagua: newUTxoRingEntriesAconcagua is called with block that has different hash with the node.")
	}

	ringBlockHeight := block.Height()
	blockNum := blockNumPerRingGroup
	//	read blocks from database
	prevNode := node.parent
	blocks := make([]*abeutil.BlockAbe, blockNum)
	blocks[blockNum-1] = block
	for i := blockNum - 2; i >= 0; i-- {
		if prevNode == nil {
			return AssertError("newUTxoRingEntriesAconcagua: newUTxoRingEntriesAconcagua is called with node that does not have (BlockNumPerRingGroup-1) previous successive blocks in database")
		}
		err := db.View(func(dbTx database.Tx) error {
			var err error
			blocks[i], err = dbFetchBlockByNodeAbe(dbTx, prevNode) // todo: should make it clear to read witness or not, 2025.06.15
			return err
		})
		if err != nil {
			return err
		}
		prevNode = prevNode.parent
	}

	newTxoRings, err := BuildTxoRingsAconcagua(blockNum, txoRingSize, blocks)
	if err != nil {
		return err
	}

	for ringId, txoRing := range newTxoRings {
		if _, ok := view.entries[ringId]; ok {
			return AssertError(fmt.Sprintf("newUTxoRingEntriesAconcagua: Found a hash collision (by RingId) when calling newUtxoRingEntriesAconcagua with blocks (hash %v, ringHeight %d, ringId %v)",
				node.hash, ringBlockHeight, ringId))
		} else {
			// here still use InitNewUTxoRingEntryMLP
			newUTxoRingEntry := InitNewUtxoRingEntryMLP(txoRing)
			view.entries[ringId] = newUTxoRingEntry
		}
	}

	return nil

}

// BuildTxoRingsAconcagua builds txoRings for the input blocks.
//
// This function is backward compatible with the function BuildTxoRingsMLP,
// so that the call on BuildTxoRingsMLP can be replaced by the call on this function.
// aut review done 2025.12.16
func BuildTxoRingsAconcagua(blockNumPerRingGroup int, txoRingSize int, blocks []*abeutil.BlockAbe) (txoRings map[wire.RingId]*wire.TxoRing, err error) {
	//blockNum := blockNumPerRingGroup

	if blockNumPerRingGroup < 1 {
		return nil, AssertError("BuildTxoRingsAconcagua: number of blocks is smaller than 1")
	}

	if len(blocks) != blockNumPerRingGroup {
		return nil, AssertError("BuildTxoRingsAconcagua: number of blocks does not match the parameter blockNumPerRingGroup")
	}

	for i := 0; i < blockNumPerRingGroup; i++ {
		if blocks[i] == nil {
			return nil, AssertError("BuildTxoRingsAconcagua: there are nil in the input blocks")
		}
	}

	ringBlockVersion := blocks[blockNumPerRingGroup-1].MsgBlock().Header.Version
	ringBlockHeight := blocks[blockNumPerRingGroup-1].Height()
	for i := blockNumPerRingGroup - 1; i >= 0; i-- {
		if blocks[i].Height() != ringBlockHeight-(int32(blockNumPerRingGroup)-1-int32(i)) {
			return nil, AssertError("BuildTxoRingsAconcagua: the input blocks should have successive height")
		}
	}

	blockHashesStrBytes := make([]byte, 0, 2*blockNumPerRingGroup*chainhash.HashSize+blockNumPerRingGroup-1)
	//	blockHashesStr is used only for the hint of hash-collision happening
	for i := 0; i < blockNumPerRingGroup; i++ {
		// copy(blockHashStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
		blockHashesStrBytes = append(blockHashesStrBytes, blocks[i].Hash().String()...)
		if i != blockNumPerRingGroup-1 {
			blockHashesStrBytes = append(blockHashesStrBytes, ","...)
		}
	}
	blockHashesStr := string(blockHashesStrBytes)

	// 2025.09.18 Aconcagua Fork
	// With the Aconcagua-fork, one more TxVersion, say TxVersion_Height_450000_Aconcagua, is added.
	// For TxVersion_Height_450000_Aconcagua, the Txos may also have four privacy-level,
	// say, RingCTPre, RingCT, Pseudonym, PseudonymCT
	// (todo: for leveled-storage, there are more cases)
	// - the Txos of RingCTPre and RingCT will be collected together and divided into rings,
	// - the Txos of Pseudonym and PseudonymCT will be collected and divided into rings with size 1.
	// - (todo: for leveled-storage, Pseudonym coins will not need three blocks to form rings.)

	//	2023.12.24 MLP Fork
	//	With the MLP_Fork, there are two TxVersions, say, TxVersion_Height_0 and TxVersion_Height_300000_MLPAUT,
	//	For TxVersion_Height_0, all Txos have the same privacy-level: RingCTPre, and all these Txos will be collected together and divided into rings.
	//	For TxVersion_Height_300000_MLPAUT, the Txos may have three privacy-level, say, RingCTPre, RingCT, and Pseudonym,
	//		the Txos of RingCTPre and RingCT will be collected together and divided into rings,
	//		the Txos of Pseudonym will be collected and divided into rings with size 1.
	//	NOTE: when there are more cases ,we need to hard code the ring-building process here.

	allCoinbaseRmTxoWithTxVersionInit := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionInit)
	allTransferRmTxoWithTxVersionInit := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionInit)

	allCoinbaseRmTxoWithTxVersionMLPAUTRCT := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTRCT)
	allCoinbaseRmTxoWithTxVersionMLPAUTSDN := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTSDN)
	allTransferRmTxoWithTxVersionMLPAUTRCT := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTRCT)
	allTransferRmTxoWithTxVersionMLPAUTSDN := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTSDN)

	// Note that the Aconcagua shares the same default allocation size as MLPAUT
	allCoinbaseRmTxoWithTxVersionAconcaguaRCT := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTRCT)
	allCoinbaseRmTxoWithTxVersionAconcaguaSDN := make([]*RingMemberTxo, 0, defaultCoinbaseRmTxoNumWithTxVersionMLPAUTSDN)
	allTransferRmTxoWithTxVersionAconcaguaRCT := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTRCT)
	allTransferRmTxoWithTxVersionAconcaguaSDN := make([]*RingMemberTxo, 0, defaultTransferRmTxoNumWithTxVersionMLPAUTSDN)

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
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's first transaction is not coinbase transaction", i))
		}

		//	(3) tx hash
		txHash := cbTx.Hash()
		copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])

		for outIndex, txOut := range cbTx.MsgTx().TxOuts {
			//	(4) outIndex
			txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

			// todo: To be backward compatible, here still uses DoubleHashH, even after Aconcagua upgrade. will have a new BuildRing function for Aconcagua.
			//txoOrderHash := chainhash.DoubleHashH(txoSortStr)
			txoOrderHash := txoOrderHashForBuildingRing(ringBlockVersion, txoSortStr)

			ringMemberTxo := NewRingMemberTxo(txOut.Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)

			if txOut.Version != cbTx.MsgTx().Version {
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's coinbase transaction's %d -th txo has a version different from that of tx", i, outIndex))
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
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's coinbase transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, outIndex, privacyLevel))
				}

			case wire.TxVersion_Height_464000_Aconcagua:
				privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
				if err != nil {
					return nil, err
				}
				switch privacyLevel {
				case abecryptoxkey.PrivacyLevelRINGCTPre, abecryptoxkey.PrivacyLevelRINGCT:
					allCoinbaseRmTxoWithTxVersionAconcaguaRCT = append(allCoinbaseRmTxoWithTxVersionAconcaguaRCT, ringMemberTxo)

				case abecryptoxkey.PrivacyLevelPSEUDONYM, abecryptoxkey.PrivacyLevelPSEUDONYMCT:
					allCoinbaseRmTxoWithTxVersionAconcaguaSDN = append(allCoinbaseRmTxoWithTxVersionAconcaguaSDN, ringMemberTxo)

				default:
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's coinbase transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, outIndex, privacyLevel))
				}

			default:
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's coinbase transaction's version is not supported", i))
			}
		}

		//	transfer transactions
		for t, trTx := range blocks[i].Transactions()[1:] {

			isCbTx, err = trTx.IsCoinBase()
			if err != nil {
				return nil, err
			}
			if isCbTx {
				return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's %d -th transaction is a coinbase transaction", i, t))
			}

			//	(3) tx hash
			txHash = trTx.Hash()
			copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range trTx.MsgTx().TxOuts {
				//	(4) outIndex
				txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

				// todo: To be backward compatible, here still uses DoubleHashH, even after Aconcagua upgrade. will have a new BuildRing function for Aconcagua.
				//txoOrderHash := chainhash.DoubleHashH(txoSortStr)
				txoOrderHash := txoOrderHashForBuildingRing(ringBlockVersion, txoSortStr)

				ringMemberTxo := NewRingMemberTxo(txOut.Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)

				if txOut.Version != trTx.MsgTx().Version {
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's %d -th transaction's %d -th txo has a version different from that of tx", i, t, outIndex))
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
						return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's %d -th transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, t, outIndex, privacyLevel))
					}

				case wire.TxVersion_Height_464000_Aconcagua:
					privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
					if err != nil {
						return nil, err
					}
					switch privacyLevel {
					case abecryptoxkey.PrivacyLevelRINGCTPre, abecryptoxkey.PrivacyLevelRINGCT:
						allTransferRmTxoWithTxVersionAconcaguaRCT = append(allTransferRmTxoWithTxVersionAconcaguaRCT, ringMemberTxo)

					case abecryptoxkey.PrivacyLevelPSEUDONYM, abecryptoxkey.PrivacyLevelPSEUDONYMCT:
						allTransferRmTxoWithTxVersionAconcaguaSDN = append(allTransferRmTxoWithTxVersionAconcaguaSDN, ringMemberTxo)

					default:
						return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's %d -th transaction's %d -th TxOut's PrivacyLevel (%d) is not supported.", i, t, outIndex, privacyLevel))
					}

				default:
					return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: the %d -th input block's %d -th transaction's version is not supported", i, t))
				}
			}
		}
	}

	log.Debugf("BuildTxoRingsAconcagua: %d blocks are building rings for (ringBlockHeight %d ringBlockVersion %d) : "+
		"coinBaseRmTxoNumTxVersionInit = %d, transferRmTxoNumTxVersionInit = %d, "+
		"coinBaseRmTxoNumTxVersionMLPAUTRCT = %d, coinBaseRmTxoNumTxVersionMLPAUTSDN = %d, "+
		"transferRmTxoNumTxVersionMLPAUTRCT = %d, transferRmTxoNumTxVersionMLPAUTSDN = %d, "+
		"coinBaseRmTxoNumTxVersionAconcaguaRCT = %d, coinBaseRmTxoNumTxVersionAconcaguaSDN = %d, "+
		"transferRmTxoNumTxVersionAconcaguaRCT = %d, transferRmTxoNumTxVersionAconcaguaSDN = %d ",
		blockNumPerRingGroup, ringBlockHeight, ringBlockVersion,
		len(allCoinbaseRmTxoWithTxVersionInit), len(allTransferRmTxoWithTxVersionInit),
		len(allCoinbaseRmTxoWithTxVersionMLPAUTRCT), len(allCoinbaseRmTxoWithTxVersionMLPAUTSDN),
		len(allTransferRmTxoWithTxVersionMLPAUTRCT), len(allTransferRmTxoWithTxVersionMLPAUTSDN),
		len(allCoinbaseRmTxoWithTxVersionAconcaguaRCT), len(allCoinbaseRmTxoWithTxVersionAconcaguaSDN),
		len(allTransferRmTxoWithTxVersionAconcaguaRCT), len(allTransferRmTxoWithTxVersionAconcaguaSDN),
	)

	//	todo: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
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

	cbTxoRingsWithTxVersionAconcaguaRCT, err := buildTxoRingsFromTxos(allCoinbaseRmTxoWithTxVersionAconcaguaRCT, ringBlockHeight, blockHashes, txoRingSize, true)
	if err != nil {
		return nil, err
	}

	trTxoRingsWithTxVersionAconcaguaRCT, err := buildTxoRingsFromTxos(allTransferRmTxoWithTxVersionAconcaguaRCT, ringBlockHeight, blockHashes, txoRingSize, false)
	if err != nil {
		return nil, err
	}

	cbTxoRingsWithTxVersionAconcaguaSDN, err := buildTxoRingsFromTxosForSingle(allCoinbaseRmTxoWithTxVersionAconcaguaSDN, ringBlockHeight, blockHashes, true)
	if err != nil {
		return nil, err
	}

	trTxoRingsWithTxVersionAconcaguaSDN, err := buildTxoRingsFromTxosForSingle(allTransferRmTxoWithTxVersionAconcaguaSDN, ringBlockHeight, blockHashes, false)
	if err != nil {
		return nil, err
	}

	rstRingNum := len(cbTxoRingsWithTxVersionInit) + len(trTxoRingsWithTxVersionInit) +
		len(cbTxoRingsWithTxVersionMLPAUTRCT) + len(trTxoRingsWithTxVersionMLPAUTRCT) +
		len(cbTxoRingsWithTxVersionMLPAUTSDN) + len(trTxoRingsWithTxVersionMLPAUTSDN) +
		len(cbTxoRingsWithTxVersionAconcaguaRCT) + len(trTxoRingsWithTxVersionAconcaguaRCT) +
		len(cbTxoRingsWithTxVersionAconcaguaSDN) + len(trTxoRingsWithTxVersionAconcaguaSDN)

	rstTxoRings := make(map[wire.RingId]*wire.TxoRing, rstRingNum)

	for i, txoRing := range cbTxoRingsWithTxVersionInit {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: cbTxoRingsWithTxVersionInit[%d], ring size = %d, , ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionInit {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: trTxoRingsWithTxVersionInit[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range cbTxoRingsWithTxVersionMLPAUTRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: cbTxoRingsWithTxVersionMLPAUTRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionMLPAUTRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: trTxoRingsWithTxVersionMLPAUTRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range cbTxoRingsWithTxVersionMLPAUTSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: cbTxoRingsWithTxVersionMLPAUTSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionMLPAUTSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: trTxoRingsWithTxVersionMLPAUTSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}

	for i, txoRing := range cbTxoRingsWithTxVersionAconcaguaRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: cbTxoRingsWithTxVersionAconcaguaRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionAconcaguaRCT {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: trTxoRingsWithTxVersionAconcaguaRCT[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range cbTxoRingsWithTxVersionAconcaguaSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: cbTxoRingsWithTxVersionAconcaguaSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}
	for i, txoRing := range trTxoRingsWithTxVersionAconcaguaSDN {
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRingsAconcagua: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockHashesStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
		log.Debugf("BuildTxoRingsAconcagua: trTxoRingsWithTxVersionAconcaguaSDN[%d], ring size = %d, ring id = %s", i, len(txoRing.TxOuts), txoRing.RingId())
		for index, outpoint := range txoRing.OutPointRing.OutPoints {
			log.Debugf("\t[%d] (%s,%d)", index, outpoint.TxHash, outpoint.Index)
		}
	}

	return rstTxoRings, nil

}

// txoOrderHashForBuildingRing returns a hash of the input txoSortStr, which will be used to order the Txos.
// Using such a hash rather than the txoSortStr to oder the Txos is to make the order is random and not controlled by attackers.
//
// Before Aconcagua fork, DoubleHashH is used to generate the hash, while since the Aconcagua fork, SHA3-256 is used.
func txoOrderHashForBuildingRing(blockVersion int32, txoSortStr []byte) chainhash.Hash {

	if blockVersion >= int32(wire.BlockVersionAconcagua) {
		return chainhash.ChainHash(txoSortStr)
	}

	return chainhash.DoubleHashH(txoSortStr)
}
