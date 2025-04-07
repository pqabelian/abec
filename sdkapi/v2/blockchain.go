package v2

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
	"io"
)

func GetTxoRingSizeByBlockHeight(height int32) uint8 {
	return wire.GetTxoRingSizeByBlockHeight(height)
}

func GetBlockNumPerRingGroupByBlockHeight(height int32) uint8 {
	return wire.GetBlockNumPerRingGroupByBlockHeight(height)
}

type TxoRing struct {
	Version          uint32
	RingBlockHeight  int32
	OutPointRing     *OutPointRing
	SerializedTxOuts [][]byte
	IsCoinbase       bool
}

func (ring *TxoRing) RingId() (string, error) {
	wireTxoRing, err := txoRingToChainTxoRing(ring)
	if err != nil {
		return "", err
	}
	return wireTxoRing.RingId().String(), nil
}
func NewTxoRing(version uint32, ringBlockHeight int32, outPointRing *OutPointRing, serializedTxOuts [][]byte, isCoinbase bool) (*TxoRing, error) {
	return &TxoRing{
		Version:          version,
		RingBlockHeight:  ringBlockHeight,
		OutPointRing:     outPointRing,
		SerializedTxOuts: serializedTxOuts,
		IsCoinbase:       isCoinbase,
	}, nil
}
func txoRingToChainTxoRing(txoRing *TxoRing) (*wire.TxoRing, error) {
	wireOutPointRing, err := outPointRing2ChainOutPointRing(txoRing.OutPointRing)
	if err != nil {
		return nil, err
	}
	abeTxos := make([]*wire.TxOutAbe, len(txoRing.SerializedTxOuts))
	for i := 0; i < len(txoRing.SerializedTxOuts); i++ {
		abeTxos[i] = &wire.TxOutAbe{}
		err = wire.ReadTxOutAbe(bytes.NewReader(txoRing.SerializedTxOuts[i]), 0, txoRing.Version, abeTxos[i])
		if err != nil {
			return nil, err
		}
	}

	return &wire.TxoRing{
		Version:         txoRing.Version,
		RingBlockHeight: txoRing.RingBlockHeight,
		OutPointRing:    wireOutPointRing,
		TxOuts:          abeTxos,
		IsCoinbase:      txoRing.IsCoinbase,
	}, nil
}

func chainTxoRingToTxoRing(wireTxoRing *wire.TxoRing) (*TxoRing, error) {
	outPointRing, err := chainOutPointRing2OutPointRing(wireTxoRing.OutPointRing)
	if err != nil {
		return nil, err
	}
	serializedAbeTxos := make([][]byte, len(wireTxoRing.TxOuts))
	for i := 0; i < len(wireTxoRing.TxOuts); i++ {
		var buf bytes.Buffer
		err = wire.WriteTxOutAbe(&buf, 0, wireTxoRing.Version, wireTxoRing.TxOuts[i])
		if err != nil {
			return nil, err
		}
		serializedAbeTxos[i] = buf.Bytes()
	}

	return &TxoRing{
		Version:          wireTxoRing.Version,
		RingBlockHeight:  wireTxoRing.RingBlockHeight,
		OutPointRing:     outPointRing,
		SerializedTxOuts: serializedAbeTxos,
		IsCoinbase:       wireTxoRing.IsCoinbase,
	}, nil
}

func (ring *TxoRing) Serialize(w io.Writer) error {
	wireTxoRing, err := txoRingToChainTxoRing(ring)
	if err != nil {
		return err
	}
	return wireTxoRing.Serialize(w)
}

type OutPointRing struct {
	Version   uint32
	BlockIDs  []string
	OutPoints []*OutPoint
}

func NewOutPointRing(version uint32, blockIDs []string, outpoints []*OutPoint) (*OutPointRing, error) {
	return &OutPointRing{
		Version:   TxVersion,
		BlockIDs:  blockIDs,
		OutPoints: outpoints,
	}, nil
}

func outPointRing2ChainOutPointRing(outPointRing *OutPointRing) (*wire.OutPointRing, error) {
	var err error
	blockHashs := make([]*chainhash.Hash, len(outPointRing.BlockIDs))
	for i := 0; i < len(outPointRing.BlockIDs); i++ {
		blockHashs[i], err = chainhash.NewHashFromStr(outPointRing.BlockIDs[i])
		if err != nil {
			return nil, err
		}
	}
	outPoints := make([]*wire.OutPointAbe, len(outPointRing.OutPoints))
	for i := 0; i < len(outPointRing.OutPoints); i++ {
		outPoints[i] = wire.NewOutPointAbe((*chainhash.Hash)(outPointRing.OutPoints[i].TxId), outPointRing.OutPoints[i].Index)
	}

	return &wire.OutPointRing{
		Version:    outPointRing.Version,
		BlockHashs: blockHashs,
		OutPoints:  outPoints,
	}, nil
}
func chainOutPointRing2OutPointRing(outPointRing *wire.OutPointRing) (*OutPointRing, error) {
	var err error
	blockIDs := make([]string, len(outPointRing.BlockHashs))
	for i := 0; i < len(outPointRing.BlockHashs); i++ {
		blockIDs[i] = outPointRing.BlockHashs[i].String()
	}
	outPoints := make([]*OutPoint, len(outPointRing.OutPoints))
	for i := 0; i < len(outPointRing.OutPoints); i++ {
		outPoints[i], err = NewOutPointFromTxIdStr(outPointRing.OutPoints[i].TxHash.String(), outPointRing.OutPoints[i].Index)
		if err != nil {
			return nil, err
		}
	}

	return &OutPointRing{
		Version:   outPointRing.Version,
		BlockIDs:  blockIDs,
		OutPoints: outPoints,
	}, nil
}

func checkSerializedRingBlocks(serializedBlocksForRingGroup [][]byte) ([]*abeutil.BlockAbe, int, error) {
	blockNum := len(serializedBlocksForRingGroup)

	if blockNum == 0 {
		return nil, 0, errors.New("BuildTxoRings: blocks is empty")
	}

	var err error
	blocks := make([]*abeutil.BlockAbe, blockNum)
	for i := 0; i < blockNum; i++ {
		// todo: to confirm
		//	For example, in the function, blockNoWitness is used.
		//	We need to clarify these functions.
		blocks[i], err = abeutil.NewBlockFromBytesAbe(serializedBlocksForRingGroup[i])
		if err != nil {
			return nil, 0, err
		}

		//	assume the blocks are valid blocks in ledger, include:
		// (1) the Header contains its height. Based on this, we explicitly set the height of Block.
		if err = GetAndSetHeight(blocks[i]); err != nil {
			return nil, 0, err
		}
	}
	startBlockHeight := blocks[0].Height()
	blockNumPerRingGroup := wire.GetBlockNumPerRingGroupByBlockHeight(startBlockHeight)

	if int(blockNumPerRingGroup) != blockNum {
		return nil, 0, fmt.Errorf("the number of blocks does not match expectations with height")
	}

	ringSize := wire.GetTxoRingSizeByBlockHeight(startBlockHeight)
	for i := 0; i < int(blockNumPerRingGroup); i++ {
		height := blocks[i].Height()
		if height != startBlockHeight+int32(i) {
			return nil, 0, errors.New("the heights of input serializedBlocksForRingGroup are not successive")
		}

		if wire.GetBlockNumPerRingGroupByBlockHeight(height) != blockNumPerRingGroup {
			return nil, 0, errors.New("input serializedBlocksForRingGroup imply different blockNumPerRingGroup")
		}

		if wire.GetTxoRingSizeByBlockHeight(height) != ringSize {
			return nil, 0, errors.New("input serializedBlocksForRingGroup imply different RingSize")
		}
	}

	return blocks, int(ringSize), nil
}

func BuildTxoRingsFromRingBlocks(serializedBlocksForRingGroup [][]byte) ([]*TxoRing, error) {
	blocks, ringSize, err := checkSerializedRingBlocks(serializedBlocksForRingGroup)
	if err != nil {
		return nil, err
	}

	wireTxoRings, err := blockchain.BuildTxoRingsMLP(len(blocks), ringSize, blocks)
	if err != nil {
		return nil, err
	}

	txoRings := make([]*TxoRing, 0, len(wireTxoRings))
	for id := range wireTxoRings {
		txoRing, err := chainTxoRingToTxoRing(wireTxoRings[id])
		if err != nil {

		}
		txoRings = append(txoRings, txoRing)
	}
	return txoRings, nil
}
