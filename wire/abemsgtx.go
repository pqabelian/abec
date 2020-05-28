package wire

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/cryptosuite/salrs-go/salrs"
	"io"
	"strconv"
)

const (
	TxRingSize    = 7
	TxRingSizeMin = 4

	TxInputMaxNum = 5

	TxOutputMaxNum = 5

	defaultTxInputAlloc = 2

	defaultTxOutputAlloc = 2

	// currently it is a fixed length, as the address is a DPK
	AddressScriptMaxLen = salrs.DpkByteLen
	// to do
	WitnessItemMaxLen = 2000000

	// minTxPayload is the minimum payload size for a (transfer) transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	//  Version 4 bytes
	// + Varint number of transaction inputs 1 byte
	// + TxRingSize * (chainhash.HashSize+1) for one input
	// + Varint number of transaction outputs 1 byte
	// + chainhash.HashSize for one output
	// + commitment hash
	minTxPayloadAbe = 4 + 1 + TxRingSize*(chainhash.HashSize+1) + 1 + chainhash.HashSize + chainhash.HashSize
)

// MessageEncoding represents the wire message encoding format to be used.
type TxSerializeType uint8

const (
	// BaseEncoding encodes all messages in the default format specified
	// for the Bitcoin wire protocol.
	TxSeralizeContent TxSerializeType = 1 << iota

	// WitnessEncoding encodes all messages other than transaction messages
	// using the default Bitcoin wire protocol specification. For transaction
	// messages, the new encoding format detailed in BIP0144 will be used.
	/*	TxSeralizePersistent
		TxSeralizeWithTxo*/
	TxSeralizeFull
)

type TxOutAbe struct {
	//	Version 		int16	//	the version could be used in ABE protocol update
	ValueScript   int64
	AddressScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (txOut *TxOutAbe) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of AddressScript + AddressScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(txOut.AddressScript))) + len(txOut.AddressScript)
}

func (txOut *TxOutAbe) Serialize(w io.Writer) error {

	err := binarySerializer.PutUint64(w, littleEndian, uint64(txOut.ValueScript))
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, 0, txOut.AddressScript)
	if err != nil {
		return err
	}

	return nil
}

func (txOut *TxOutAbe) Deserialize(r io.Reader) error {
	err := readElement(r, &txOut.ValueScript)
	if err != nil {
		return err
	}

	addressScript, err := ReadVarBytes(r, 0, AddressScriptMaxLen, "AddressScript")
	if err != nil {
		return err
	}
	txOut.AddressScript = addressScript

	return nil
}

/*func (txOut *TxOutAbe) Hash() *chainhash.Hash {
	// Value 8 bytes + serialized varint size for the length of AddressScript + AddressScript bytes.
	buf := bytes.NewBuffer(make([]byte, 0, txOut.SerializeSize()))
	_ = txOut.Serialize(buf)
	hash := chainhash.DoubleHashH(buf.Bytes())
	return &hash
}*/

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOutAbe(valueScript int64, addressScript []byte) *TxOutAbe {
	return &TxOutAbe{
		ValueScript:   valueScript,
		AddressScript: addressScript,
	}
}

// OutPoint defines a ABE data type that is used to track previous transaction outputs.
// Note that the type of index depends on the TxOutPutMaxNum
type OutPointAbe struct {
	TxHash chainhash.Hash
	Index  uint8
}

func (outPoint *OutPointAbe) SerializeSize() int {
	return chainhash.HashSize + 1
}

func (outPoint *OutPointAbe) Serialize(w io.Writer) error {
	_, err := w.Write(outPoint.TxHash[:])
	if err != nil {
		return err
	}

	err = binarySerializer.PutUint8(w, outPoint.Index)
	if err != nil {
		return err
	}

	return nil
}

func (outPoint *OutPointAbe) Deserialize(r io.Reader) error {
	_, err := io.ReadFull(r, outPoint.TxHash[:])
	if err != nil {
		return err
	}
	outPoint.Index, err = binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	return nil
}

// String returns the OutPoint in the human-readable form "hash:index".
func (op OutPointAbe) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	offset := copy(buf[:], op.TxHash.String())
	buf[offset] = ':'
	buf = strconv.AppendUint(buf, uint64(op.Index), 10)
	return string(buf)
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPointAbe(txHash *chainhash.Hash, index uint8) *OutPointAbe {
	return &OutPointAbe{
		TxHash: *txHash,
		Index:  index,
	}
}

type OutPointRing struct {
	BlockHashs []*chainhash.Hash
	OutPoints  []*OutPointAbe
}

func (outPointRing *OutPointRing) SerializeSize() int {
	blockNum := len(outPointRing.BlockHashs)
	OutPointNum := len(outPointRing.OutPoints)
	return VarIntSerializeSize(uint64(blockNum)) + blockNum*chainhash.HashSize + VarIntSerializeSize(uint64(OutPointNum)) + OutPointNum*(chainhash.HashSize+1)
}

func (outPointRing *OutPointRing) Serialize(w io.Writer) error {
	err := WriteVarInt(w, 0, uint64(len(outPointRing.BlockHashs)))
	if err != nil {
		return err
	}
	for _, blockHash := range outPointRing.BlockHashs {
		_, err := w.Write(blockHash[:])
		if err != nil {
			return err
		}
	}

	for _, outPoint := range outPointRing.OutPoints {
		err = outPoint.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

func (outPointRing *OutPointRing) Deserialize(r io.Reader) error {

	blockNum, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if blockNum != 3 {
		return messageError("OutPointRing.Deserialize", "the ring must generated from transactions from 3 blocks")
	}

	outPointRing.BlockHashs = make([]*chainhash.Hash, blockNum)
	for i := uint64(0); i < blockNum; i++ {
		blockHash := chainhash.Hash{}
		_, err = io.ReadFull(r, blockHash[:])
		if err != nil {
			return err
		}
		outPointRing.BlockHashs[i] = &blockHash
	}

	ringSize, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if ringSize > TxRingSize {
		str := fmt.Sprintf("the ring size (%d) exceeds the allowed max ring size %d", ringSize, TxRingSize)
		return messageError("OutPointRing.Deserialize", str)
	}

	outPointRing.OutPoints = make([]*OutPointAbe, ringSize)
	for i := uint64(0); i < ringSize; i++ {
		outPoint := OutPointAbe{}

		_, err = io.ReadFull(r, outPoint.TxHash[:])
		if err != nil {
			return err
		}
		outPoint.Index, err = binarySerializer.Uint8(r)
		if err != nil {
			return err
		}

		outPointRing.OutPoints[i] = &outPoint
	}

	return nil
}

func (outPointRing *OutPointRing) Hash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, outPointRing.SerializeSize()))
	_ = outPointRing.Serialize(buf)

	return chainhash.DoubleHashH(buf.Bytes())
}

type TxInAbe struct {
	SerialNumber chainhash.Hash
	//	identify the consumed OutPoint
	PreviousOutPointRing *OutPointRing
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxInAbe(serialNumber *chainhash.Hash, previousOutPointRing *OutPointRing) *TxInAbe {
	return &TxInAbe{
		SerialNumber:         *serialNumber,
		PreviousOutPointRing: previousOutPointRing,
	}
}

/*func (txIn *TxInAbe) OutPointRingHash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, txIn.SerializeSizeOutPointRing()))
	_ = txIn.SerializeOutPointRing(buf)

	return chainhash.DoubleHashH(buf.Bytes())
}*/

// String returns the OutPoint in the human-readable form "hash:index".
func (txIn *TxInAbe) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	// TxHash:index; TxHash:index; ...; serialNumber
	//	index is at most 2 decimal digits; at this momembt, only 1 decimal digits
	strLen := (2*chainhash.HashSize + 1) + len(txIn.PreviousOutPointRing.BlockHashs)*(2*chainhash.HashSize+1) + len(txIn.PreviousOutPointRing.OutPoints)*(2*chainhash.HashSize+1+2+1)

	buf := make([]byte, strLen)

	start := 0
	start = start + copy(buf[start:], txIn.SerialNumber.String())
	buf[start] = '.'
	start = start + 1

	for _, blockHash := range txIn.PreviousOutPointRing.BlockHashs {
		start = start + copy(buf[start:], blockHash.String())
		buf[start] = ';'
		start = start + 1
	}
	buf[start-1] = '.'

	for _, outPoint := range txIn.PreviousOutPointRing.OutPoints {
		start = start + copy(buf[start:], outPoint.TxHash.String())
		buf[start] = ','
		start = start + 1

		start = start + copy(buf[start:], strconv.FormatUint(uint64(outPoint.Index), 10))

		buf[start] = ';'
		start = start + 1
	}
	buf[start-1] = '.'

	return string(buf)
}

func (txIn *TxInAbe) Hash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, txIn.SerializeSize()))
	_ = txIn.Serialize(buf)

	return chainhash.DoubleHashH(buf.Bytes())
}

/*func (txIn *TxInAbe)SerializeSizeOutPointRing() int{
	// chainhash.HashSize for SerialNumber
	// serialized varint size for the ring size
	// each ring member is a OutPoint, with size chainhash.HashSize + 1
	return VarIntSerializeSize(uint64(len(txIn.PreviousOutPointRing))) + len(txIn.PreviousOutPointRing) * (chainhash.HashSize + 1)
}*/

/*func (txIn *TxInAbe) SerializeOutPointRing(w io.Writer) error {
	err := WriteVarInt(w, 0, uint64(len(txIn.PreviousOutPointRing)))
	if err != nil {
		return err
	}
	for _, outPoint:= range txIn.PreviousOutPointRing {
		_, err := w.Write(outPoint.TxHash[:])
		if err != nil {
			return err
		}
		err = binarySerializer.PutUint8(w, outPoint.Index)
		if err != nil {
			return err
		}
	}

	return nil
}*/

func (txIn *TxInAbe) SerializeSize() int {
	// chainhash.HashSize for SerialNumber
	return chainhash.HashSize + txIn.PreviousOutPointRing.SerializeSize()
}

func (txIn *TxInAbe) Serialize(w io.Writer) error {
	_, err := w.Write(txIn.SerialNumber[:])
	if err != nil {
		return err
	}

	err = txIn.PreviousOutPointRing.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}

func (txIn *TxInAbe) Deserialize(r io.Reader) error {
	_, err := io.ReadFull(r, txIn.SerialNumber[:])
	if err != nil {
		return err
	}

	err = txIn.PreviousOutPointRing.Deserialize(r)
	if err != nil {
		return err
	}

	return nil
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxInAbe(w io.Writer, pver uint32, version int32, txIn *TxInAbe) error {
	_, err := w.Write(txIn.SerialNumber[:])
	if err != nil {
		return err
	}

	err = WriteVarInt(w, 0, uint64(len(txIn.PreviousOutPointRing.BlockHashs)))
	if err != nil {
		return err
	}
	for _, blockHash := range txIn.PreviousOutPointRing.BlockHashs {
		_, err := w.Write(blockHash[:])
		if err != nil {
			return err
		}
	}

	err = WriteVarInt(w, pver, uint64(len(txIn.PreviousOutPointRing.OutPoints)))
	for _, outPoint := range txIn.PreviousOutPointRing.OutPoints {
		_, err = w.Write(outPoint.TxHash[:])
		if err != nil {
			return err
		}
		err = binarySerializer.PutUint8(w, outPoint.Index)
		if err != nil {
			return err
		}
	}

	return nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxInAbe(r io.Reader, pver uint32, version int32, txIn *TxInAbe) error {
	_, errSn := io.ReadFull(r, txIn.SerialNumber[:])
	if errSn != nil {
		return errSn
	}

	blockNum, err := ReadVarInt(r, 0)
	if blockNum != 3 {
		return messageError("TxIn.readTxInAbe", "the ring must tagged with 3 block hashes")
	}

	txIn.PreviousOutPointRing.BlockHashs = make([]*chainhash.Hash, blockNum)
	for i := uint64(0); i < blockNum; i++ {
		blockHash := chainhash.Hash{}
		_, err = io.ReadFull(r, blockHash[:])
		if err != nil {
			return err
		}
		txIn.PreviousOutPointRing.BlockHashs[i] = &blockHash
	}

	ringSize, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if ringSize > TxRingSize {
		str := fmt.Sprintf("the ring size (%d) exceeds the allowed max ring size %d", ringSize, TxRingSize)
		return messageError("TxIn.readTxInAbe", str)
	}
	txIn.PreviousOutPointRing.OutPoints = make([]*OutPointAbe, ringSize)
	for i := uint64(0); i < ringSize; i++ {
		outPoint := OutPointAbe{}
		_, err = io.ReadFull(r, outPoint.TxHash[:])
		if err != nil {
			return err
		}
		outPoint.Index, err = binarySerializer.Uint8(r)
		if err != nil {
			return err
		}

		txIn.PreviousOutPointRing.OutPoints[i] = &outPoint
	}

	return nil
}

// writeTxOut encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxOutAbe(w io.Writer, pver uint32, version int32, txOut *TxOutAbe) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(txOut.ValueScript))
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, txOut.AddressScript)
	if err != nil {
		return err
	}

	return nil
}

// readTxOut reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxOutAbe(r io.Reader, pver uint32, version int32, txOut *TxOutAbe) error {
	err := readElement(r, &txOut.ValueScript)
	if err != nil {
		return err
	}

	addressScript, err := ReadVarBytes(r, pver, AddressScriptMaxLen, "AddressScript")
	if err != nil {
		return err
	}
	txOut.AddressScript = addressScript

	return nil
}

func writeTxWitnessAbe(w io.Writer, pver uint32, version int32, txWitness *TxWitnessAbe) error {
	err := WriteVarInt(w, pver, uint64(len(txWitness.Witness)))
	for _, witnessItem := range txWitness.Witness {
		err = WriteVarBytes(w, pver, witnessItem)
		if err != nil {
			return err
		}
	}

	return nil
}

// readTxOut reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxWitnessAbe(r io.Reader, pver uint32, version int32, txWitness *TxWitnessAbe) error {
	witItemNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if witItemNum > 0 {
		txWitness.Witness = make([][]byte, witItemNum)
		for i := uint64(0); i < witItemNum; i++ {
			witnessItem, err := ReadVarBytes(r, pver, WitnessItemMaxLen, "WitnessItem")
			if err != nil {
				return err
			}
			txWitness.Witness[i] = witnessItem
		}
	}

	return nil
}

type TxWitnessAbe struct {
	Witness [][]byte
}

func (txWitness *TxWitnessAbe) Hash() *chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, txWitness.SerializeSize()))
	_ = txWitness.Serialize(buf)
	hash := chainhash.DoubleHashH(buf.Bytes())
	return &hash
}

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input's witness.
func (txWitness TxWitnessAbe) SerializeSize() int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(txWitness.Witness)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range txWitness.Witness {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

func (txWitness TxWitnessAbe) Serialize(w io.Writer) error {
	err := WriteVarInt(w, 0, uint64(len(txWitness.Witness)))
	if err != nil {
		return err
	}

	for _, witItem := range txWitness.Witness {
		err = WriteVarBytes(w, 0, witItem)
		if err != nil {
			return err
		}
	}
	return nil
}

func (txWitness TxWitnessAbe) Deserialize(r io.Reader) error {
	witnessNum, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	txWitness.Witness = make([][]byte, witnessNum)
	for i := uint64(0); i < witnessNum; i++ {
		witItemLen, err := ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		witnessItem := make([]byte, witItemLen)

		_, err = io.ReadFull(r, witnessItem)
		if err != nil {
			return err
		}

		txWitness.Witness[i] = witnessItem
	}

	return nil
}

type MsgTxAbe struct {
	Version int32
	TxIns   []*TxInAbe
	//	TxOutHashs []*chainhash.Hash
	TxOuts []*TxOutAbe
	//	txWitnessHash chainhash.Hash
	TxWitness TxWitnessAbe // Each Tx has one witness, consisting all necessary information, for example, signatures for inputs, range proofs for outputs, balance between inputs and outputs
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTxAbe) AddTxIn(txIn *TxInAbe) {
	msg.TxIns = append(msg.TxIns, txIn)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTxAbe) AddTxOut(txOut *TxOutAbe) {
	msg.TxOuts = append(msg.TxOuts, txOut)
	//	msg.TxOutHashs = append(msg.TxOutHashs, txOut.Hash())
}

/*// SetWitness seth a witness for the transaction message.
func (msg *MsgTxAbe) SetWitness(txWitness *TxWitnessAbe) {
	msg.txWitness = *txWitness
//	msg.txWitnessHash = *txWitness.Hash()
}*/

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTxAbe) HasWitness() bool {
	witItemNum := len(msg.TxWitness.Witness)
	if witItemNum > 0 {
		for _, witItem := range msg.TxWitness.Witness {
			if len(witItem) > 0 {
				return true
			}
		}
	}

	return false
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTxAbe) IsCoinBaseTx() bool {
	if len(msg.TxIns) != 1 {
		return false
	}

	// The serialNumber of the consumed coin must be a zero hash.
	// Whatever ths ring members for the TxIns[0]
	// the ring members' (TXHash, index) can be used as coin-nonce
	txIn := msg.TxIns[0]
	if txIn.SerialNumber != chainhash.ZeroHash {
		return false
	}

	return true
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTxAbe) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	//	Version
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	//	Inputs
	err = WriteVarInt(w, 0, uint64(len(msg.TxIns)))
	if err != nil {
		return err
	}
	for _, txIn := range msg.TxIns {
		err = writeTxInAbe(w, pver, msg.Version, txIn)
		if err != nil {
			return err
		}
	}

	/*	//	ouputs: txo hash
		txoHashNum := len(msg.TxOutHashs)
		err = WriteVarInt(w, 0, uint64(txoHashNum))
		if err != nil {
			return err
		}
		for _, txOutHash := range msg.TxOutHashs {
			// here the hash of serialzed TXO is added, rather than the serialized TXO
			_, err = w.Write(txOutHash[:])
			if err != nil{
				return err
			}
		}*/

	/*	//	witness hash
		_, err = w.Write(msg.txWitnessHash[:])
		if err != nil{
			return err
		}
	*/
	// txo details
	txoNum := len(msg.TxOuts)
	/*	if txoNum != txoHashNum {
		str := fmt.Sprintf("the number of TXOs (%d) does not match the number of TxoHashs %d", txoNum, txoHashNum)
		return messageError("MsgTx.BtcEncode", str)
	}*/
	err = WriteVarInt(w, 0, uint64(txoNum))
	for _, txOut := range msg.TxOuts {
		err = writeTxOutAbe(w, pver, msg.Version, txOut)
		if err != nil {
			return err
		}
	}

	// witness details
	err = writeTxWitnessAbe(w, 0, msg.Version, &msg.TxWitness)
	if err != nil {
		return err
	}

	return nil
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTxAbe) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	//	TxIns
	txInNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if txInNum > uint64(TxInputMaxNum) {
		str := fmt.Sprintf("The numner of inputs exceeds the allowd max number [txInNum %d, max %d]", txInNum,
			TxInputMaxNum)
		return messageError("MsgTx.BtcDecode", str)
	}
	msg.TxIns = make([]*TxInAbe, txInNum)
	for i := uint64(0); i < txInNum; i++ {
		txIn := TxInAbe{}
		err = readTxInAbe(r, pver, msg.Version, &txIn)
		if err != nil {
			return err
		}
		msg.TxIns[i] = &txIn
	}

	/*	//	outputs: txohashs
		txOutHashNum, err := ReadVarInt(r, pver)
		if err != nil {
			return err
		}
		if txOutHashNum > uint64(TxOutputMaxNum) {
			str := fmt.Sprintf("The numner of outputs exceeds the allowd max number [txInNum %d, max %d]", txOutHashNum,
				TxOutputMaxNum)
			return messageError("MsgTx.BtcDecode", str)
		}
		msg.TxOutHashs = make([]*chainhash.Hash, txOutHashNum)
		for i := uint64(0); i < txOutHashNum; i++ {
			hash := chainhash.Hash{}
			_, err = io.ReadFull(r, hash[:])
			if err != nil {
				return err
			}
			msg.TxOutHashs[i] = &hash
		}

		//	witness hash
		_, err = io.ReadFull(r, msg.txWitnessHash[:])
		if err != nil {
			return err
		}*/

	//	txo details
	txoNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if txoNum > 0 {
		/*		if txoNum != txOutHashNum{
				str := fmt.Sprintf("the number of TXOs (%d) does not match the number of TxoHashs %d", txoNum, txOutHashNum)
				return messageError("MsgTx.BtcEncode", str)
			}*/
		msg.TxOuts = make([]*TxOutAbe, txoNum)
		for i := uint64(0); i < txoNum; i++ {
			txOut := TxOutAbe{}
			readTxOutAbe(r, pver, msg.Version, &txOut)
			msg.TxOuts[i] = &txOut
		}
	}

	//	witness details
	txWitness := TxWitnessAbe{}
	err = readTxWitnessAbe(r, pver, msg.Version, &txWitness)
	if err != nil {
		return err
	}
	msg.TxWitness = txWitness

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTxAbe) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTxAbe) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayloadAbe
}

// TxHash generates the Hash for the transaction.
// TxHash
func (msg *MsgTxAbe) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeContent()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

/*// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (msg *MsgTxAbe) TxHashFull() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize(TxSeralizeFull)))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}*/

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the bitcoin wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTxAbe) SerializeSizeContent() int {
	//	Version 4 bytes
	n := 4

	//	Inputs
	//	serialized varint size for input
	n = n + VarIntSerializeSize(uint64(len(msg.TxIns)))
	for _, txIn := range msg.TxIns {
		// serialized varint size for the ring size, and (chainhash.HashSize + 1) for each OutPoint
		n = n + txIn.SerializeSize()
	}

	/*	//	Outputs: Txo Hash
		//	serialized varint size for output number
		//	chainhash.HashSize for each TxOut
		n = n + VarIntSerializeSize(uint64(len(msg.TxOutHashs)))
		n = n + len(msg.TxOutHashs)*chainhash.HashSize*/

	/*	//	The above information is used to compute the fingerprint/hash that can be used to check the validity of the transaction
		//	Witness hash
		// here the hash of serialzed Witness is added, rather than the serialized Witness
		if serializeType >= TxSeralizePersistent {
			n = n + chainhash.HashSize
		}
		//	When a transaction is contained in block and stored in database, the hash of the witness should be included.
	*/

	//	Outputs: Txo Details
	/*	if serializeType >= TxSeralizeWithTxo {
		// 	serialized varint size for output number
		n = n + VarIntSerializeSize(uint64(len(msg.txOuts)))

		for  _, txOut := range msg.txOuts{
			n = n + txOut.SerializeSize()
		}
	}*/

	// 	serialized varint size for output number
	n = n + VarIntSerializeSize(uint64(len(msg.TxOuts)))
	for _, txOut := range msg.TxOuts {
		n = n + txOut.SerializeSize()
	}

	return n
}

func (msg *MsgTxAbe) SerializeSizeFull() int {
	//	Version 4 bytes
	/*	n := 4;

		//	Inputs
		//	serialized varint size for input
		n = n + VarIntSerializeSize(uint64(len(msg.TxIns)))
		for  _, txIn := range msg.TxIns{
			// serialized varint size for the ring size, and (chainhash.HashSize + 1) for each OutPoint
			n = n + VarIntSerializeSize(uint64(len(txIn.PreviousOutPointRing))) + len(txIn.PreviousOutPointRing) * (chainhash.HashSize + 1)
		}

			//	Outputs: Txo Hash
			//	serialized varint size for output number
			//	chainhash.HashSize for each TxOut
			n = n + VarIntSerializeSize(uint64(len(msg.TxOutHashs)))
			n = n + len(msg.TxOutHashs)*chainhash.HashSize

			//	The above information is used to compute the fingerprint/hash that can be used to check the validity of the transaction
			//	Witness hash
			// here the hash of serialzed Witness is added, rather than the serialized Witness
			if serializeType >= TxSeralizePersistent {
				n = n + chainhash.HashSize
			}
			//	When a transaction is contained in block and stored in database, the hash of the witness should be included.


		//	Outputs: Txo Details
		if serializeType >= TxSeralizeWithTxo {
			// 	serialized varint size for output number
			n = n + VarIntSerializeSize(uint64(len(msg.txOuts)))

			for  _, txOut := range msg.txOuts{
				n = n + txOut.SerializeSize()
			}
		}*/

	n := msg.SerializeSizeContent()

	//	Witness Details
	n = n + msg.TxWitness.SerializeSize()

	return n
}

func (msg *MsgTxAbe) Serialize(w io.Writer) error {
	//	version
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	//	inputs
	err = WriteVarInt(w, 0, uint64(len(msg.TxIns)))
	if err != nil {
		return err
	}
	for _, txIn := range msg.TxIns {
		err = txIn.Serialize(w)
		if err != nil {
			return err
		}
	}

	/*	//	ouputs: txo hash
		err = WriteVarInt(w, 0, uint64(len(msg.TxOutHashs)))
		if err != nil {
			return err
		}
		for _, txOutHash := range msg.TxOutHashs {
			// here the hash of serialzed TXO is added, rather than the serialized TXO
			_, err = w.Write(txOutHash[:])
			if err != nil{
				return err
			}
		}*/

	//	Txo Details
	err = WriteVarInt(w, 0, uint64(len(msg.TxOuts)))
	if err != nil {
		return err
	}
	for _, txOut := range msg.TxOuts {
		// here the serialized TXOs are  put
		err = txOut.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil

}

/*
// SerializeNoWitness encodes the transaction to w in an identical manner to
// Serialize, however even if the source transaction has inputs with witness
// data, the old serialization format will still be used.
func (msg *MsgTxAbe) Serialize(w io.Writer) error {

	err := msg.SerializeTxContent(w)
	if err != nil {
		return err
	}

	//	witness hash
	// here the hash of serialzed Witness is added, rather than the serialized Witness
	_, err = w.Write(msg.txWitnessHash[:])
	if err != nil{
			return err
		}

	return nil
}


func (msg *MsgTxAbe) SerializeTxos(w io.Writer) error {
	//	Txo Details
	err := WriteVarInt(w, 0, uint64(len(msg.txOuts)))
	if err != nil {
		return err
	}
	for _, txOut := range msg.txOuts {
		// here the serialized TXOs are  put
		err = txOut.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

func (msg *MsgTxAbe) SerializeWitness(w io.Writer) error {
	//	Witness Details
	err := msg.txWitness.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}*/

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTxAbe) Deserialize(r io.Reader) error {
	//	Version
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	//	inputs
	inputNum, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if inputNum > TxInputMaxNum {
		str := fmt.Sprintf("the number of inputs (%d) exceeds the allowed max number %d", inputNum, TxInputMaxNum)
		return messageError("MsgTx.Deserialize", str)
	}
	msg.TxIns = make([]*TxInAbe, inputNum)
	for i := uint64(0); i < inputNum; i++ {
		txIn := TxInAbe{}
		err = txIn.Deserialize(r)
		if err != nil {
			return err
		}
		msg.TxIns[i] = &txIn
	}

	/*	//	outputs: Txo Hash
		outputNum, err := ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		if outputNum > TxOutputMaxNum {
			str := fmt.Sprintf("the number of outputs (%d) exceeds the allowed max number %d", outputNum,	TxOutputMaxNum)
			return messageError("MsgTx.Deserialize", str)
		}
		msg.TxOutHashs = make([]*chainhash.Hash, outputNum)
		for i := uint64(0); i < outputNum; i++ {
			txoHash := chainhash.Hash{}
			_, err = io.ReadFull(r, txoHash[:])
			if err != nil {
				return err
			}
			msg.TxOutHashs[i] = &txoHash
		}

		//	witness hash
		_, err = io.ReadFull(r, msg.txWitnessHash[:])
		if err != nil {
			return err
		}*/

	txoNum, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if txoNum > TxOutputMaxNum {
		str := fmt.Sprintf("the number of outputs (%d) exceeds the allowed max number %d", inputNum, TxOutputMaxNum)
		return messageError("MsgTx.Deserialize", str)
	}
	msg.TxOuts = make([]*TxOutAbe, txoNum)
	for i := uint64(0); i < txoNum; i++ {
		txOut := TxOutAbe{}
		err = txOut.Deserialize(r)
		if err != nil {
			return err
		}
		msg.TxOuts[i] = &txOut
	}

	/*	// witness details
		txWitness := TxWitnessAbe{}
		err = txWitness.Deserialize(r)
		if err != nil {
			return err
		}
		msg.txWitness = txWitness*/

	return nil
}

// In summary, contains multiple hash-pointers for its TXOS, each for one TXO.
// In other words, block does not contain TxWitness, nor coinowner detail.
// Some full nodes will keep (txhash, txwitness) and (coinownerhash, coinownerdetail) in its database
// The key owner will keep its (coinownerhash, coinownerdetail) until the transaction spending this coin is confirmed safely.
// Note that the witnesses are needed only when the miners verifying the transactions,
// and once the corresponding transaction is safely confirmed, it is not useful any more.
// Also, the coinowner detail is useful only when the miners verifying the transactions which spend the coins,
// but in ABE, the transaction issuers must enable other users, who will use this TXO as his ring member,
// to know the coin detail. This means, the coindetail must be verified when verifying transactions and blocks.
// In other words, although coinowner details are not included in serializd transactions, they must be available durig consensus.
