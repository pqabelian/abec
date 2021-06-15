package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"github.com/abesuite/abec/abecrypto/pqringctparam"
	"github.com/abesuite/abec/chainhash"
)

// borrow something from msgtx.go
//	todo(ABE)
const (
	BlockNumPerRingGroup = 3

	TxRingSize = 7

	TxInputMaxNum = 5

	TxOutputMaxNum = 5

	defaultTxInputAlloc = 3

	defaultTxOutputAlloc = 3

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
	//	todo(ABE): could be more accurate

	TxPayloadMaxSize = 30000
	TxPayloadMinSize = 100
)

// OutPointAbe defines a ABE data type that is used to track previous transaction outputs.
// Note that the type of index depends on the TxOutPutMaxNum
//	todo(ABE): shall index be int8?
type OutPointAbe struct {
	TxHash chainhash.Hash
	Index  uint8 //	due to the large size of post-quantum crypto primitives, ABE will limit the number of outputs of each transaction
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
	copy(buf, op.TxHash.String())
	buf[2*chainhash.HashSize] = ':'
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

//	todo: shall the ringBlockHeight be added?
type OutPointRing struct {
	// TODO(abe): these three successive block hash can be replaced by the hash of block whose heigt equal to 3K+2
	Version    uint32            //	All TXOs in a ring has the same version, and this version is set to be the ring Version.
	BlockHashs []*chainhash.Hash //	the hashs for the blocks from which the ring was generated, at this moment it is 3 successive blocks
	OutPoints  []*OutPointAbe
}

func (outPointRing *OutPointRing) SerializeSize() int {
	// Version 4
	// length of BlockHash
	// BlockHashes Num * chainhash.HashSize
	// length of Outpoints
	// Outpoints Nun * (chainhash.HashSize + 1)
	blockNum := len(outPointRing.BlockHashs)
	OutPointNum := len(outPointRing.OutPoints)
	return 4 +
		VarIntSerializeSize(uint64(blockNum)) +
		blockNum*chainhash.HashSize +
		VarIntSerializeSize(uint64(OutPointNum)) +
		OutPointNum*(chainhash.HashSize+1)
}

func (outPointRing *OutPointRing) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	// TxHash:index; TxHash:index; ...; serialNumber
	//	index is at most 2 decimal digits; at this moment, only 1 decimal digits

	strLen := len(outPointRing.BlockHashs)*(2*chainhash.HashSize+1) + len(outPointRing.OutPoints)*(2*chainhash.HashSize+2) + 1
	// Version is not included in the string

	buf := make([]byte, strLen, strLen+10)

	pos := 0

	for _, blockHash := range outPointRing.BlockHashs {
		pos += copy(buf[pos:], blockHash.String())
		buf[pos] = ';'
		pos++
	}

	for _, outPoint := range outPointRing.OutPoints {
		pos += copy(buf[pos:], outPoint.TxHash.String())
		buf[pos] = ','
		pos++

		buf[pos] = outPoint.Index
		pos++

		buf[pos] = ';'
		pos++
	}
	buf[pos] = '.'
	pos++

	return string(buf[0:pos])
}

func (outPointRing *OutPointRing) Hash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, outPointRing.SerializeSize()))
	_ = WriteOutPointRing(buf, 0, outPointRing.Version, outPointRing)
	return chainhash.DoubleHashH(buf.Bytes())
}
func WriteOutPointRing(w io.Writer, pver uint32, version uint32, opr *OutPointRing) error {
	err := binarySerializer.PutUint32(w, littleEndian, opr.Version)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(opr.BlockHashs)))
	if err != nil {
		return err
	}
	for i := 0; i < len(opr.BlockHashs); i++ {
		_, err := w.Write(opr.BlockHashs[i][:])
		if err != nil {
			return err
		}
	}

	err = WriteVarInt(w, pver, uint64(len(opr.OutPoints)))
	if err != nil {
		return err
	}
	for i := 0; i < len(opr.OutPoints); i++ {
		err = writeOutPointAbe(w, pver, version, opr.OutPoints[i])
		if err != nil {
			return err
		}
	}

	return nil
}
func ReadOutPointRing(r io.Reader, pver uint32, version uint32, opr *OutPointRing) error {
	err := readElement(r, &opr.Version)
	if err != nil {
		return err
	}

	cnt, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if cnt != BlockNumPerRingGroup {
		str := fmt.Sprintf("the ring must generated from transactions from %d blocks", BlockNumPerRingGroup)
		return messageError("readOutPointRing", str)
	}
	opr.BlockHashs = make([]*chainhash.Hash, cnt)
	for i := 0; i < BlockNumPerRingGroup; i++ {
		tmp := chainhash.Hash{}
		_, err := io.ReadFull(r, tmp[:])
		if err != nil {
			return err
		}
		opr.BlockHashs[i] = &tmp
	}

	cnt, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if cnt > TxRingSize {
		str := fmt.Sprintf("the ring size (%d) exceeds the allowed max ring size %d", cnt, TxRingSize)
		return messageError("readOutPointRing", str)
	}
	opr.OutPoints = make([]*OutPointAbe, cnt)
	for i := 0; i < int(cnt); i++ {
		opr.OutPoints[i] = &OutPointAbe{}
		err = readOutPointAbe(r, pver, version, opr.OutPoints[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func writeOutPointAbe(w io.Writer, pver uint32, version uint32, op *OutPointAbe) error {
	_, err := w.Write(op.TxHash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint8(w, op.Index)
}

func readOutPointAbe(r io.Reader, pver uint32, version uint32, op *OutPointAbe) error {
	_, err := io.ReadFull(r, op.TxHash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint8(r)

	return err
}

func NewOutPointRing(version uint32, blockHashs []*chainhash.Hash, outPoints []*OutPointAbe) *OutPointRing {
	return &OutPointRing{
		version,
		blockHashs,
		outPoints,
	}
}

// TxOutAbe /* As TxOut may be fetched without the corresponding Tx, a version field is used.
type TxOutAbe struct {
	//	Version 		int16	//	the version could be used in ABE protocol update
	// ValueScript   []byte
	//	ValueScript   int64
	//	AddressScript []byte

	Version   uint32
	TxoScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (txOut *TxOutAbe) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of AddressScript + AddressScript bytes.
	//return VarIntSerializeSize(uint64(len(txOut.ValueScript))) + len(txOut.ValueScript) + VarIntSerializeSize(uint64(len(txOut.AddressScript))) + len(txOut.AddressScript)
	//return 8 + VarIntSerializeSize(uint64(len(txOut.AddressScript))) + len(txOut.AddressScript)
	return 4 + VarIntSerializeSize(uint64(len(txOut.TxoScript))) + len(txOut.TxoScript)
}

// WriteTxOutAbe encodes ti to the bitcoin protocol encoding for a transaction
// input (TxInAbe) to w.
func WriteTxOutAbe(w io.Writer, pver uint32, version uint32, txOut *TxOutAbe) error {
	err := binarySerializer.PutUint32(w, littleEndian, txOut.Version)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, txOut.TxoScript)
	if err != nil {
		return err
	}

	return nil
}

// ReadTxOutAbe reads the next sequence of bytes from r as a transaction input
// (TxInAbe).
func ReadTxOutAbe(r io.Reader, pver uint32, version uint32, txOut *TxOutAbe) error {
	err := readElement(r, &txOut.Version)
	if err != nil {
		return err
	}

	txoScript, err := ReadVarBytes(r, pver, pqringctparam.GetTxoSerializeSize(version), "TxoScript")
	if err != nil {
		return err
	}
	txOut.TxoScript = txoScript

	return nil
}

// NewTxOutAbe returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOutAbe(version uint32, txoScript []byte) *TxOutAbe {
	return &TxOutAbe{
		Version:   version,
		TxoScript: txoScript,
	}
}

//	SerialNumber appears only when some ring member is consumed in TxIn,
//	i.e. logically, SerialNumber accompanies with TxIn.
type TxInAbe struct {
	SerialNumber []byte
	//	identify the consumed OutPoint
	PreviousOutPointRing OutPointRing
}

// String returns the OutPoint in the human-readable form "hash:index".
func (txIn *TxInAbe) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	// TxHash:index; TxHash:index; ...; serialNumber
	//	index is at most 2 decimal digits; at this moment, only 1 decimal digits

	strLen := 2*pqringctparam.GetTxoSerialNumberLen(txIn.PreviousOutPointRing.Version) + 1 +
		len(txIn.PreviousOutPointRing.BlockHashs)*(2*chainhash.HashSize+1) + len(txIn.PreviousOutPointRing.OutPoints)*(2*chainhash.HashSize+2) + 1

	buf := make([]byte, strLen)

	pos := 0

	pos += copy(buf[pos:], hex.EncodeToString(txIn.SerialNumber[:]))
	buf[pos] = '.'
	pos++
	copy(buf[pos:], txIn.PreviousOutPointRing.String())

	return string(buf[0:pos])
}

func (txIn *TxInAbe) SerializeSize() int {
	// chainhash.HashSize for SerialNumber
	snLen := pqringctparam.GetTxoSerialNumberLen(txIn.PreviousOutPointRing.Version)
	return VarIntSerializeSize(uint64(snLen)) + snLen + txIn.PreviousOutPointRing.SerializeSize()
}

// writeTxIn encodes txIn to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxInAbe(w io.Writer, pver uint32, version uint32, txIn *TxInAbe) error {
	err := WriteVarBytes(w, pver, txIn.SerialNumber)
	if err != nil {
		return err
	}

	return WriteOutPointRing(w, pver, version, &txIn.PreviousOutPointRing)
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxInAbe(r io.Reader, pver uint32, version uint32, txIn *TxInAbe) error {
	var err error
	txIn.SerialNumber, err = ReadVarBytes(r, pver, uint32(pqringctparam.GetTxoSerialNumberLen(version)), "SerialNumber")
	if err != nil {
		return err
	}
	return ReadOutPointRing(r, pver, version, &txIn.PreviousOutPointRing)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxInAbe(serialNumber []byte, previousOutPointRing *OutPointRing) *TxInAbe {
	return &TxInAbe{
		SerialNumber:         serialNumber,
		PreviousOutPointRing: *previousOutPointRing,
	}
}

//	At this moment, TxIn is just a ring member (say, identified by (outpointRing, serialNumber)), so that we can use txIn.Serialize
//	If TxIn includes more information, this needs modification.
func (txIn *TxInAbe) RingMemberHash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, txIn.PreviousOutPointRing.SerializeSize()))
	_ = WriteOutPointRing(buf, 0, txIn.PreviousOutPointRing.Version, &txIn.PreviousOutPointRing)
	return chainhash.DoubleHashH(buf.Bytes())
}

//	Transfer Transaction:
//	len(TxOuts) >= 1; len(TxIns) >= 1;
//	len(TxWitness.Witnesses) = len(TxIns), each TxIn has a linkable ring signature and the serialNumber computed from the signature matches that in the TxIn
//	The number of Witness depends on the proof for authorizing and authenticating the transaction

//	Coinbase Transaction:
//	len(TxOuts) >= 1; len(TxIns) == 1;
//	len(TxWitness.Witnesses) == 0
//	TxIn[0].SerialNumber: 00...00 (ZeroHash), implying that this is a coinbase transaction, without consuming any TxOut,as the serialNumber is determined by the consumed TXO
//	TxIn[0].OutPointRing.BlockHashs:
//				blockhashs[0]: the height of the block (as each block has juts one coinbase transaction)
//				blockhashs[1]: the coinbase nonce
//				blockhashs[2]: any thing
//	TxIn[0].OutPointRing.OutPoints:
//				(TxHash0, index0): any thing
//				...
//				limited by TxRingSize
//	TxFee = 0
//	todo: For coinbase transaction, there is an additional function that returns the bytes in [blockhashs[2]] and later OutPoints

type MsgTxAbe struct {
	Version uint32
	TxIns   []*TxInAbe
	//	TxOutHashs []*chainhash.Hash
	TxOuts []*TxOutAbe
	//	txWitnessHash chainhash.Hash
	TxFee uint64

	TxMemo []byte

	//TxWitness *TxWitnessAbe // Each Tx has one witness, consisting all necessary information, for example, signatures for inputs, range proofs for outputs, balance between inputs and outputs
	TxWitness []byte
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTxAbe) AddTxIn(txIn *TxInAbe) {
	msg.TxIns = append(msg.TxIns, txIn)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTxAbe) AddTxOut(txOut *TxOutAbe) {
	msg.TxOuts = append(msg.TxOuts, txOut)
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTxAbe) HasWitness() bool {
	if msg.TxWitness == nil || len(msg.TxWitness) == 0 {
		return false
	}
	return true
}

func (msg *MsgTxAbe) IsCoinBase() bool {
	if len(msg.TxIns) != 1 {
		return false
	}

	// The serialNumber of the consumed coin must be a zero hash.
	// Whatever ths ring members for the TxIns[0]
	// the ring members' (TXHash, index) can be used as coin-nonce
	txIn := msg.TxIns[0]
	if bytes.Compare(txIn.SerialNumber, pqringctparam.GetNullSerialNumber(txIn.PreviousOutPointRing.Version)) != 0 {
		return false
	}

	return true
}

// TxHash generates the Hash for the transaction.
// TxHash
func (msg *MsgTxAbe) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

func (msg *MsgTxAbe) TxHashFull() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeFull()))
	_ = msg.SerializeFull(buf)
	return chainhash.DoubleHashH(buf.Bytes())
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
	msg.Version = version

	//	TxIns
	txInNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if txInNum > TxInputMaxNum {
		str := fmt.Sprintf("The numner of inputs exceeds the allowd max number [txInNum %d, max %d]", txInNum,
			TxInputMaxNum)
		return messageError("MsgTx.BtcDecode", str)
	}
	msg.TxIns = make([]*TxInAbe, txInNum)
	for i := uint64(0); i < txInNum; i++ {
		txIn := TxInAbe{}
		err = readTxInAbe(r, pver, version, &txIn)
		if err != nil {
			return err
		}
		msg.TxIns[i] = &txIn
	}

	// TxOuts
	txoNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	if txoNum > TxOutputMaxNum {
		str := fmt.Sprintf("The numner of inputs exceeds the allowd max number [txInNum %d, max %d]", txoNum,
			TxOutputMaxNum)
		return messageError("MsgTx.BtcDecode", str)
	}
	msg.TxOuts = make([]*TxOutAbe, txoNum)
	for i := uint64(0); i < txoNum; i++ {
		txOut := TxOutAbe{}
		err = ReadTxOutAbe(r, pver, version, &txOut)
		if err != nil {
			return err
		}
		msg.TxOuts[i] = &txOut
	}

	//	TxFee
	txFee, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxFee = txFee

	/*	txFee, err := binarySerializer.Uint64(r, littleEndian)
		if err != nil {
			return err
		}
		msg.TxFee = txFee*/

	//	TxMemo
	txMemo, err := ReadVarBytes(r, pver, pqringctparam.GetTxMemoMaxLen(msg.Version), "TxMemo")
	if err != nil {
		return err
	}
	msg.TxMemo = txMemo

	//	witness details
	/*	txWitness := TxWitnessAbe{}
		err = readTxWitnessAbe(r, pver, msg.Version, &txWitness)
		if err != nil {
			return err
		}
		msg.TxWitness = &txWitness*/

	if enc == WitnessEncoding {
		//	TxWitness
		txWitness, err := ReadVarBytes(r, pver, pqringctparam.GetTxWitnessMaxLen(msg.Version), "TxWitness")
		if err != nil {
			msg.TxWitness = nil
		}
		msg.TxWitness = txWitness
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTxAbe) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	//	Version
	err := binarySerializer.PutUint32(w, littleEndian, msg.Version)
	if err != nil {
		return err
	}

	//	TxIns
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

	// TxOuts
	err = WriteVarInt(w, 0, uint64(len(msg.TxOuts)))
	for _, txOut := range msg.TxOuts {
		err = WriteTxOutAbe(w, pver, msg.Version, txOut)
		if err != nil {
			return err
		}
	}

	//	TxFee
	err = WriteVarInt(w, 0, msg.TxFee)
	if err != nil {
		return err
	}

	/*	err = binarySerializer.PutUint64(w, littleEndian, msg.TxFee)
		if err != nil {
			return err
		}*/

	//	TxMemo
	err = WriteVarBytes(w, 0, msg.TxMemo)
	if err != nil {
		return err
	}

	if enc == WitnessEncoding && msg.HasWitness() {
		err = WriteVarBytes(w, 0, msg.TxWitness)
		if err != nil {
			return err
		}
	}

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

//	todo: Is it safe to use int as the size type?
//	Note that, in different system, int may be int16 or int32
func (msg *MsgTxAbe) SerializeSize() int {
	//	Version 4 bytes
	n := 4

	//	Inputs
	//	serialized varint size for input
	n = n + VarIntSerializeSize(uint64(len(msg.TxIns)))
	for _, txIn := range msg.TxIns {
		// serialized varint size for the ring size, and (chainhash.HashSize + 1) for each OutPoint
		n = n + txIn.SerializeSize()
	}

	// 	serialized varint size for output number
	n = n + VarIntSerializeSize(uint64(len(msg.TxOuts)))
	for _, txOut := range msg.TxOuts {
		n = n + txOut.SerializeSize()
	}

	//	TxFee
	n = n + VarIntSerializeSize(msg.TxFee)
	//	use 8 bytes store the transaction fee
	//n = n + 8

	//	TxMemo
	n = n + VarIntSerializeSize(uint64(len(msg.TxMemo))) + len(msg.TxMemo)

	return n
}

func (msg *MsgTxAbe) SerializeSizeFull() int {
	n := msg.SerializeSize()

	n = n + VarIntSerializeSize(uint64(len(msg.TxWitness))) + len(msg.TxWitness)

	return n
}

/**
Compute the size according to the Serialize function, and based on the crypto-scheme
The result is just appropriate, will be used to compute transaction fee
*/
func PrecomputeTrTxConSize(txVersion uint32, txIns []*TxInAbe, outputTxoNum uint8, txMemoLen uint32) uint32 {
	//	Version 4 bytes
	n := uint32(4)

	//	Inputs
	//	serialized varint size for input
	n = n + uint32(VarIntSerializeSize(uint64(len(txIns))))
	for _, txIn := range txIns {
		// serialized varint size for the ring size, and (chainhash.HashSize + 1) for each OutPoint
		n = n + uint32(txIn.SerializeSize())
	}

	// 	serialized varint size for output number
	n = n + uint32(VarIntSerializeSize(uint64(outputTxoNum)))
	txoScriptLen := pqringctparam.GetTxoSerializeSize(txVersion) // depending on the crypto-scheme
	n = n + uint32(outputTxoNum)*(uint32(4+VarIntSerializeSize(uint64(txoScriptLen)))+txoScriptLen)
	/*	for _, txOut := range msg.TxOuts {
		n = n + txOut.SerializeSize()
	}*/

	//	TxFee
	//	use 8
	n = n + 8

	//	TxMemo
	n = n + uint32(VarIntSerializeSize(uint64(txMemoLen))) + txMemoLen

	return n
}

func PrecomputeTrTxWitnessSize(txVersion uint32, txIns []*TxInAbe, outputTxoNum uint8) uint32 {
	inputRingSizes := make([]int, len(txIns))
	for i := 0; i < len(txIns); i++ {
		inputRingSizes[i] = len(txIns[i].PreviousOutPointRing.OutPoints)
	}

	return pqringctparam.GetTrTxWitnessSize(txVersion, inputRingSizes, outputTxoNum) // depending on the crypto-scheme
}

//	for computing TxId by hash, and for being serialized in block
func (msg *MsgTxAbe) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

func (msg *MsgTxAbe) SerializeFull(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

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
// todo: re-write the serialize/deserialze, even they are the same as encode/decode
// todo: serialize/deserialze should call the serialize of the components
func (msg *MsgTxAbe) Deserialize(r io.Reader) error {
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

func (msg *MsgTxAbe) DeserializeFull(r io.Reader) error {
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTxAbe(version uint32) *MsgTxAbe {
	return &MsgTxAbe{
		Version: version,
		TxIns:   make([]*TxInAbe, 0, defaultTxInputAlloc),
		TxOuts:  make([]*TxOutAbe, 0, defaultTxInOutAlloc),
	}
}

func NewStandardCoinbaseTxIn(nextBlockHeight int32, extraNonce uint64, version uint32) *TxInAbe {
	txIn := &TxInAbe{}

	txIn.SerialNumber = pqringctparam.GetNullSerialNumber(version)

	previousOutPointRing := OutPointRing{}
	previousOutPointRing.Version = version // this does not make sense, since this is an 'empty' ring
	previousOutPointRing.BlockHashs = make([]*chainhash.Hash, 3)
	hash0 := chainhash.Hash{}
	binary.BigEndian.PutUint32(hash0[0:4], uint32(nextBlockHeight))
	hash1 := chainhash.Hash{}
	binary.BigEndian.PutUint64(hash1[0:8], extraNonce)
	hash2 := chainhash.ZeroHash
	previousOutPointRing.BlockHashs[0] = &hash0
	previousOutPointRing.BlockHashs[1] = &hash1
	previousOutPointRing.BlockHashs[2] = &hash2

	previousOutPointRing.OutPoints = make([]*OutPointAbe, 1)
	outPointAbe := &OutPointAbe{
		TxHash: chainhash.ZeroHash,
		Index:  0,
	}
	previousOutPointRing.OutPoints[0] = outPointAbe

	txIn.PreviousOutPointRing = previousOutPointRing

	return txIn
}

//	the caller must have checked the format of the coinbaseTxMsg
func ExtractCoinbaseHeight(coinbaseTx *MsgTxAbe) int32 {
	blockhash0 := coinbaseTx.TxIns[0].PreviousOutPointRing.BlockHashs[0]
	blockHeight := int32(binary.BigEndian.Uint32(blockhash0[0:4]))
	return blockHeight
}

//func (txOut *TxOutAbe) Serialize(w io.Writer) error {
//	/*	err := WriteVarBytes(w, 0, txOut.ValueScript)
//		if err != nil {
//			return err
//		}*/
//	// Version
//	err := binarySerializer.PutUint32(w, littleEndian, txOut.Version)
//	if err != nil {
//		return err
//	}
//	// TxoScript
//	err = WriteVarBytes(w, 0, txOut.TxoScript)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (txOut *TxOutAbe) Deserialize(r io.Reader) error {
//	/*	valueScript, err := ReadVarBytes(r, 0, ValueScriptMaxLen, "ValueScript")
//		if err != nil {
//			return err
//		}
//		txOut.ValueScript = valueScript*/
//	var err error
//	txOut.Version, err = binarySerializer.Uint32(r, littleEndian)
//	if err != nil {
//		return err
//	}
//
//	txOut.TxoScript, err = ReadVarBytes(r, 0, pqringctparam.GetTxoScriptLen(txOut.Version), "TxoScript")
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

/*func (txOut *TxOutAbe) Hash() *chainhash.Hash {
	// Value 8 bytes + serialized varint size for the length of AddressScript + AddressScript bytes.
	buf := bytes.NewBuffer(make([]byte, 0, txOut.SerializeSize()))
	_ = txOut.Serialize(buf)
	hash := chainhash.DoubleHashH(buf.Bytes())
	return &hash
}*/

//func (outPoint *OutPointAbe) Serialize(w io.Writer) error {
//	_, err := w.Write(outPoint.TxHash[:])
//	if err != nil {
//		return err
//	}
//
//	err = binarySerializer.PutUint8(w, outPoint.Index)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (outPoint *OutPointAbe) Deserialize(r io.Reader) error {
//	_, err := io.ReadFull(r, outPoint.TxHash[:])
//	if err != nil {
//		return err
//	}
//	outPoint.Index, err = binarySerializer.Uint8(r)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (outPointRing *OutPointRing) Serialize(w io.Writer) error {
//	err := binarySerializer.PutUint32(w, littleEndian, outPointRing.Version)
//	if err != nil {
//		return err
//	}
//
//	err = WriteVarInt(w, 0, uint64(len(outPointRing.BlockHashs)))
//	if err != nil {
//		return err
//	}
//	for _, blockHash := range outPointRing.BlockHashs {
//		_, err := w.Write(blockHash[:])
//		if err != nil {
//			return err
//		}
//	}
//
//	err = WriteVarInt(w, 0, uint64(len(outPointRing.OutPoints)))
//	if err != nil {
//		return err
//	}
//
//	for _, outPoint := range outPointRing.OutPoints {
//		err = outPoint.Serialize(w)
//		if err != nil {
//			return err
//		}
//	}
//
//	return nil
//}
//
//func (outPointRing *OutPointRing) Deserialize(r io.Reader) error {
//	var err error
//	outPointRing.Version, err = binarySerializer.Uint32(r, littleEndian)
//	if err != nil {
//		return err
//	}
//
//	blockNum, err := ReadVarInt(r, 0)
//	if err != nil {
//		return err
//	}
//
//	if blockNum != BlockNumPerRingGroup {
//		return messageError("OutPointRing.Deserialize", "the ring must generated from transactions from 3 blocks")
//	}
//
//	outPointRing.BlockHashs = make([]*chainhash.Hash, blockNum)
//	for i := uint64(0); i < blockNum; i++ {
//		blockHash := &chainhash.Hash{}
//		_, err = io.ReadFull(r, blockHash[:])
//		if err != nil {
//			return err
//		}
//		outPointRing.BlockHashs[i] = blockHash
//	}
//
//	ringSize, err := ReadVarInt(r, 0)
//	if err != nil {
//		return err
//	}
//	if ringSize > TxRingSize {
//		str := fmt.Sprintf("the ring size (%d) exceeds the allowed max ring size %d", ringSize, TxRingSize)
//		return messageError("OutPointRing.Deserialize", str)
//	}
//
//	outPointRing.OutPoints = make([]*OutPointAbe, ringSize)
//	for i := uint64(0); i < ringSize; i++ {
//		outPoint := &OutPointAbe{}
//		err = outPoint.Deserialize(r)
//		if err != nil {
//			return err
//		}
//		outPointRing.OutPoints[i] = outPoint
//	}
//
//	return nil
//}

/*func (txIn *TxInAbe) OutPointRingHash() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, txIn.SerializeSizeOutPointRing()))
	_ = txIn.SerializeOutPointRing(buf)

	return chainhash.DoubleHashH(buf.Bytes())
}*/

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

//func (txIn *TxInAbe) Serialize(w io.Writer) error {
//	_, err := w.Write(txIn.SerialNumber[:])
//	if err != nil {
//		return err
//	}
//
//	err = txIn.PreviousOutPointRing.Serialize(w)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (txIn *TxInAbe) Deserialize(r io.Reader) error {
//	txIn.SerialNumber = make([]byte, pqringctparam.GetTxoSerialNumberLen(txIn.PreviousOutPointRing.Version))
//	_, err := r.Read(txIn.SerialNumber[:])
//	if err != nil {
//		return err
//	}
//
//	err = txIn.PreviousOutPointRing.Deserialize(r)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (txWitness TxWitnessAbe) Serialize(w io.Writer) error {
//	err := WriteVarInt(w, 0, uint64(len(txWitness.Witnesses)))
//	if err != nil {
//		return err
//	}
//
//	for _, witItem := range txWitness.Witnesses {
//		err = WriteVarBytes(w, 0, witItem)
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}
//
//func (txWitness *TxWitnessAbe) Deserialize(r io.Reader) error {
//	witnessNum, err := ReadVarInt(r, 0)
//	if err != nil {
//		return err
//	}
//
//	txWitness.Witnesses = make([]Witness, witnessNum)
//	for i := uint64(0); i < witnessNum; i++ {
//		witItemLen, err := ReadVarInt(r, 0)
//		if err != nil {
//			return err
//		}
//		witnessItem := make([]byte, witItemLen)
//
//		_, err = io.ReadFull(r, witnessItem)
//		if err != nil {
//			return err
//		}
//
//		txWitness.Witnesses[i] = witnessItem
//	}
//
//	return nil
//}

/*// SetWitness seth a witness for the transaction message.
func (msg *MsgTxAbe) SetWitness(txWitness *TxWitnessAbe) {
	msg.txWitness = *txWitness
//	msg.txWitnessHash = *txWitness.Hash()
}*/

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
/*func (msg *MsgTxAbe) HasWitness() bool {
	if msg.TxWitness == nil {
		return false
	}

	witItemNum := len(msg.TxWitness.Witnesses)
	if witItemNum > 0 {
		for _, witItem := range msg.TxWitness.Witnesses {
			if len(witItem) > 0 {
				return true
			}
		}
	}

	return false
}*/

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

////	each transaction has a TxWitness, which consists of multiple Witness([]byte)
//type Witness []byte
//type TxWitnessAbe struct {
//	Witnesses []Witness
//}
//
//// SerializeSize returns the number of bytes it would take to serialize the the
//// transaction input's witness.
//func (txWitness TxWitnessAbe) SerializeSize() int {
//	// A varint to signal the number of elements the witness has.
//	n := VarIntSerializeSize(uint64(len(txWitness.Witnesses)))
//
//	// For each element in the witness, we'll need a varint to signal the
//	// size of the element, then finally the number of bytes the element
//	// itself comprises.
//	for _, witItem := range txWitness.Witnesses {
//		n += VarIntSerializeSize(uint64(len(witItem)))
//		n += len(witItem)
//	}
//
//	return n
//}
//func writeTxWitnessAbe(w io.Writer, pver uint32, version uint32, txWitness *TxWitnessAbe) error {
//	if txWitness == nil {
//		err := WriteVarInt(w, pver, uint64(0))
//		if err != nil {
//			return err
//		}
//		return nil
//	}
//
//	err := WriteVarInt(w, pver, uint64(len(txWitness.Witnesses)))
//	for _, witnessItem := range txWitness.Witnesses {
//		err = WriteVarBytes(w, pver, witnessItem)
//		if err != nil {
//			return err
//		}
//	}
//
//	return nil
//}
//
//// readTxOut reads the next sequence of bytes from r as a transaction input
//// (TxIn).
//func readTxWitnessAbe(r io.Reader, pver uint32, version uint32, txWitness *TxWitnessAbe) error {
//	witItemNum, err := ReadVarInt(r, pver)
//	if err != nil {
//		return err
//	}
//	txWitness.Witnesses = make([]Witness, witItemNum)
//	if witItemNum > 0 {
//		for i := uint64(0); i < witItemNum; i++ {
//			witnessItem, err := ReadVarBytes(r, pver, pqringctparam.GetTxWitnessMaxLen(version), "WitnessItem")
//			if err != nil {
//				return err
//			}
//			txWitness.Witnesses[i] = witnessItem
//		}
//	}
//
//	return nil
//}
