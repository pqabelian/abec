package blockchain

import (
	"fmt"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

func (view *UtxoRingViewpoint) newUtxoRingEntriesMLP(db database.DB, node *blockNode, block *abeutil.BlockAbe) error {
	if node == nil || block == nil {
		return AssertError("newUtxoRingEntriesFromNode is called with nil node or nil block.")
	}

	//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
	//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
	//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
	blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(node.height))
	txoRingSize := int(wire.GetTxoRingSizeByBlockHeight(node.height))
	//if !(node.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1) {
	if !(node.height%blockNumPerRingGroup == blockNumPerRingGroup-1) {
		return AssertError("newUtxoRingEntriesFromNode is called with node where node.height % BlockNumPerRingGroup != BlockNumPerRingGroup-1.")
	}

	if !view.bestHash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntriesFromNode is called with block's hash not equal to the view.bestHash")
	}

	if !node.hash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntries is called with block that has different hash with the node.")
	}

	ringBlockHeight := block.Height()
	//blockNum := wire.BlockNumPerRingGroup
	blockNum := int(blockNumPerRingGroup)
	nodeTmp := node
	blockTmp := block
	blocks := make([]*abeutil.BlockAbe, blockNum)
	for i := blockNum - 1; i >= 0; i-- {
		blocks[i] = blockTmp
		if i == 0 {
			break
		}

		nodeTmp = nodeTmp.parent
		if nodeTmp == nil {
			//return AssertError("a node with height % BlockNumPerRingGroup == BlockNumPerRingGroup-1 should have BlockNumPerRingGroup previous successive nodes.")
			return AssertError("newUtxoRingEntries is called with node that does not have (BlockNumPerRingGroup-1) previous successive blocks in database")
		}

		err := db.View(func(dbTx database.Tx) error {
			var err error
			blockTmp, err = dbFetchBlockByNodeAbe(dbTx, nodeTmp)
			return err
		})
		if err != nil {
			return err
		}
	}

	//node1 := node.parent
	//node0 := node1.parent
	//if node1 == nil || node0 == nil {
	//	return AssertError("a node with height %2 == 0 should have two previous successive nodes.")
	//}
	//
	//if !node.hash.IsEqual(block.Hash()) {
	//	return AssertError("newUtxoRingEntries is called with block that has different hash with the node.")
	//}
	//
	//block2 := block
	//var block1 *abeutil.BlockAbe
	//var block0 *abeutil.BlockAbe
	//err := db.View(func(dbTx database.Tx) error {
	//	var err error
	//	block1, err = dbFetchBlockByNodeAbe(dbTx, node1)
	//	if err != nil {
	//		return err
	//	}
	//	block0, err = dbFetchBlockByNodeAbe(dbTx, node0)
	//	return err
	//})
	//if err != nil {
	//	return err
	//}
	//
	//if block0 == nil || block1 == nil {
	//	return AssertError("newUtxoRingEntries is called with node that does not have 2 previous successive blocks in database")
	//}
	//
	//blocks := []*abeutil.BlockAbe{block0, block1, block2}
	//ringBlockHeight := blocks[2].Height()
	//blockNum := len(blocks)

	blockHashs := make([]*chainhash.Hash, blockNum)
	coinBaseRmTxoNum := 0
	transferRmTxoNum := 0
	for i := 0; i < blockNum; i++ {
		blockHashs[i] = blocks[i].Hash()

		coinBaseRmTxoNum += len(blocks[i].Transactions()[0].MsgTx().TxOuts)
		for _, tx := range blocks[i].Transactions()[1:] {
			transferRmTxoNum += len(tx.MsgTx().TxOuts)
		}
	}
	allCoinBaseRmTxos := make([]*RingMemberTxo, 0, coinBaseRmTxoNum)
	allTransferRmTxos := make([]*RingMemberTxo, 0, transferRmTxoNum)

	// str = block1.hash, block2.hash, block3.hash, blockhash, txHash, outIndex
	// all Txos are ordered by Hash(str), then grouped into rings
	txoSortStr := make([]byte, blockNum*chainhash.HashSize+chainhash.HashSize+chainhash.HashSize+1)
	for i := 0; i < blockNum; i++ {
		copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	for i := 0; i < blockNum; i++ {
		block := blocks[i]
		blockHash := block.Hash()
		blockHeight := block.Height()

		copy(txoSortStr[blockNum*chainhash.HashSize:], blockHash[:])

		coinBaseTx := block.Transactions()[0]
		txHash := coinBaseTx.Hash()
		copy(txoSortStr[(blockNum+1)*chainhash.HashSize:], txHash[:])
		for outIndex, txOut := range coinBaseTx.MsgTx().TxOuts {
			txoSortStr[(blockNum+2)*chainhash.HashSize] = uint8(outIndex)

			txoOrderHash := chainhash.DoubleHashH(txoSortStr)

			ringMemberTxo := NewRingMemberTxo(coinBaseTx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
			allCoinBaseRmTxos = append(allCoinBaseRmTxos, ringMemberTxo)
		}
		for _, tx := range block.Transactions()[1:] {
			txHash := tx.Hash()
			copy(txoSortStr[(blockNum+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range tx.MsgTx().TxOuts {
				txoSortStr[(blockNum+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := NewRingMemberTxo(tx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
				allTransferRmTxos = append(allTransferRmTxos, ringMemberTxo)
			}
		}
	}

	// TODO: change the version field in node and block to uint32 type?
	//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
	//	Here we should call blockNumPerRingGroup = wire.TxoRingSize()
	//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
	//txoRingSize := wire.TxoRingSize
	//	TODO: (2023.03.23) call NewUtxoRingEntriesFromBlocks and incorporate the resulting UtxoRingEntries to view.entries.
	err := view.NewUtxoRingEntriesFromTxos(allCoinBaseRmTxos, ringBlockHeight, blockHashs, txoRingSize, true)
	if err != nil {
		return err
	}

	err = view.NewUtxoRingEntriesFromTxos(allTransferRmTxos, ringBlockHeight, blockHashs, txoRingSize, false)
	if err != nil {
		return err
	}
	return nil

}

func BuildTxoRingsMLP(blockNumPerRingGroup int, txoRingSize int, blocks []*abeutil.BlockAbe) (txoRings map[wire.RingId]*wire.TxoRing, err error) {
	//blockNum := blockNumPerRingGroup

	if blockNumPerRingGroup < 1 {
		return nil, AssertError("BuildTxoRings: number of blocks is smaller than 1")
	}

	if len(blocks) != blockNumPerRingGroup {
		return nil, AssertError("BuildTxoRings: number of blocks does not match the parameter blockNumPerRingGroup")
	}

	for i := 0; i < blockNumPerRingGroup; i++ {
		if blocks[i] == nil {
			return nil, AssertError("NewUtxoRingEntriesFromBlocks: there are nil in the input blocks")
		}
	}

	ringBlockHeight := blocks[blockNumPerRingGroup-1].Height()
	for i := blockNumPerRingGroup - 1; i >= 0; i-- {
		if blocks[i].Height() != ringBlockHeight-(int32(blockNumPerRingGroup)-1-int32(i)) {
			return nil, AssertError("NewUtxoRingEntriesFromBlocks: the input blocks should have successive height")
		}
	}

	blockhashStr := make([]byte, blockNumPerRingGroup*chainhash.HashSize)
	//	blockhashStr is used only for the hint of hash-collision happening
	for i := 0; i < blockNumPerRingGroup; i++ {
		copy(blockhashStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	blockHashs := make([]*chainhash.Hash, blockNumPerRingGroup)
	coinBaseRmTxoNum := 0
	transferRmTxoNum := 0
	for i := 0; i < blockNumPerRingGroup; i++ {
		blockHashs[i] = blocks[i].Hash()

		coinBaseRmTxoNum += len(blocks[i].Transactions()[0].MsgTx().TxOuts)
		for _, tx := range blocks[i].Transactions()[1:] {
			transferRmTxoNum += len(tx.MsgTx().TxOuts)
		}
	}
	allCoinBaseRmTxos := make([]*RingMemberTxo, 0, coinBaseRmTxoNum)
	allTransferRmTxos := make([]*RingMemberTxo, 0, transferRmTxoNum)

	// str = block1.hash, block2.hash, block3.hash, blockhash, txHash, outIndex
	// all Txos are ordered by Hash(str), then grouped into rings
	txoSortStr := make([]byte, blockNumPerRingGroup*chainhash.HashSize+chainhash.HashSize+chainhash.HashSize+1)
	for i := 0; i < blockNumPerRingGroup; i++ {
		copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	for i := 0; i < blockNumPerRingGroup; i++ {
		block := blocks[i]
		blockHash := block.Hash()
		blockHeight := block.Height()

		copy(txoSortStr[blockNumPerRingGroup*chainhash.HashSize:], blockHash[:])

		coinBaseTx := block.Transactions()[0]
		txHash := coinBaseTx.Hash()
		copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])
		for outIndex, txOut := range coinBaseTx.MsgTx().TxOuts {
			txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

			txoOrderHash := chainhash.DoubleHashH(txoSortStr)

			ringMemberTxo := NewRingMemberTxo(coinBaseTx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
			allCoinBaseRmTxos = append(allCoinBaseRmTxos, ringMemberTxo)
		}
		for _, tx := range block.Transactions()[1:] {
			txHash := tx.Hash()
			copy(txoSortStr[(blockNumPerRingGroup+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range tx.MsgTx().TxOuts {
				txoSortStr[(blockNumPerRingGroup+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := NewRingMemberTxo(tx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
				allTransferRmTxos = append(allTransferRmTxos, ringMemberTxo)
			}
		}
	}

	// TODO: change the version field in node and block to uint32 type?
	//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
	//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
	//	Here we should call blockNumPerRingGroup = wire.TxoRingSize()
	//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
	//txoRingSize := wire.TxoRingSize
	cbTxoRings, err := buildTxoRingsFromTxos(allCoinBaseRmTxos, ringBlockHeight, blockHashs, txoRingSize, true)
	if err != nil {
		return nil, err
	}

	trTxoRings, err := buildTxoRingsFromTxos(allTransferRmTxos, ringBlockHeight, blockHashs, txoRingSize, false)
	if err != nil {
		return nil, err
	}

	rstTxoRings := make(map[wire.RingId]*wire.TxoRing, len(cbTxoRings)+len(trTxoRings))

	for _, txoRing := range cbTxoRings {
		//ringHash := txoRing.outPointRing.Hash()
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRings: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockhashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
	}
	for _, txoRing := range trTxoRings {
		//ringHash := txoRing.outPointRing.Hash()
		ringId := txoRing.RingId()
		if _, ok := rstTxoRings[ringId]; ok {
			return nil, AssertError(fmt.Sprintf("BuildTxoRings: Found a hash collision when calling BuildTxoRings with blocks (hash %v, ringHeight %d)",
				blockhashStr, ringBlockHeight))
		} else {
			rstTxoRings[ringId] = txoRing
		}
	}

	return rstTxoRings, nil

}
