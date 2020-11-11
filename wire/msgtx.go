package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abesalrs"
	"io"
	"strconv"

	"github.com/abesuite/abec/chainhash"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + chainhash.HashSize

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// MinTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	MinTxOutPayload = 9

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / MinTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// freeListMaxScriptSize is the size of each buffer in the free list
	// that	is used for deserializing scripts from the wire before they are
	// concatenated into a single contiguous buffers.  This value was chosen
	// because it is slightly more than twice the size of the vast majority
	// of all "standard" scripts.  Larger scripts are still deserialized
	// properly as the free list will simply be bypassed for them.
	freeListMaxScriptSize = 512

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deserialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	freeListMaxItems = 12500

	// maxWitnessItemsPerInput is the maximum number of witness items to
	// be read for the witness data for a single TxIn. This number is
	// derived using a possible lower bound for the encoding of a witness
	// item: 1 byte for length + 1 byte for the witness item itself, or two
	// bytes. This value is then divided by the currently allowed maximum
	// "cost" for a transaction.
	maxWitnessItemsPerInput = 500000

	// maxWitnessItemSize is the maximum allowed size for an item within
	// an input's witness data. This number is derived from the fact that
	// for script validation, each pushed item onto the stack must be less
	// than 10k bytes.
	maxWitnessItemSize = 11000
)

// witnessMarkerBytes are a pair of bytes specific to the witness encoding. If
// this sequence is encoutered, then it indicates a transaction has iwtness
// data. The first byte is an always 0x00 marker byte, which allows decoders to
// distinguish a serialized transaction with witnesses from a regular (legacy)
// one. The second byte is the Flag field, which at the moment is always 0x01,
// but may be extended in the future to accommodate auxiliary non-committed
// fields.
var witessMarkerBytes = []byte{0x00, 0x01}

// scriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that have a cap according to the
// freeListMaxScriptSize constant.  It is used to provide temporary buffers for
// deserializing scripts in order to greatly reduce the number of allocations
// required.
//
// The caller can obtain a buffer from the free list by calling the Borrow
// function and should return it via the Return function when done using it.
type scriptFreeList chan []byte

// Borrow returns a byte slice from the free list with a length according the
// provided size.  A new buffer is allocated if there are any items available.
//
// When the size is larger than the max size allowed for items on the free list
// a new buffer of the appropriate size is allocated and returned.  It is safe
// to attempt to return said buffer via the Return function as it will be
// ignored and allowed to go the garbage collector.
func (c scriptFreeList) Borrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}
	return buf[:size]
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the Borrow function.  Any slices that are not of the appropriate size, such
// as those whose size is greater than the largest allowed free list item size
// are simply ignored so they can go to the garbage collector.
func (c scriptFreeList) Return(buf []byte) {
	// Ignore any buffers returned that aren't the expected size for the
	// free list.
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	// Return the buffer to the free list when it's not full.  Otherwise let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for script deserialization.  As
// previously described, this free list is maintained to significantly reduce
// the number of allocations.
var scriptPool scriptFreeList = make(chan []byte, freeListMaxItems)

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          TxWitness
	Sequence         uint32
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Witness:          witness,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the the
// transaction input's witness.
func (t TxWitness) SerializeSize() int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(t)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range t {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

// TxHash generates the Hash for the transaction.
func (msg *MsgTx) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeStripped()))
	_ = msg.SerializeNoWitness(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (msg *MsgTx) WitnessHash() chainhash.Hash {
	if msg.HasWitness() {
		buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
		_ = msg.Serialize(buf)
		return chainhash.DoubleHashH(buf.Bytes())
	}

	return msg.TxHash()
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Deep copy the old signature script.
		var newScript []byte
		oldScript := oldTxIn.SignatureScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureScript:  newScript,
			Sequence:         oldTxIn.Sequence,
		}

		// If the transaction is witnessy, then also copy the
		// witnesses.
		if len(oldTxIn.Witness) != 0 {
			// Deep copy the old witness data.
			newTxIn.Witness = make([][]byte, len(oldTxIn.Witness))
			for i, oldItem := range oldTxIn.Witness {
				newItem := make([]byte, len(oldItem))
				copy(newItem, oldItem)
				newTxIn.Witness[i] = newItem
			}
		}

		// Finally, append this fully copied txin.
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{
			Value:    oldTxOut.Value,
			PkScript: newScript,
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return &newTx
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = int32(version)

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// A count of zero (meaning no TxIn's to the uninitiated) indicates
	// this is a transaction with witness data.
	var flag [1]byte
	if count == 0 && enc == WitnessEncoding {
		// Next, we need to read the flag, which is a single byte.
		if _, err = io.ReadFull(r, flag[:]); err != nil {
			return err
		}

		// At the moment, the flag MUST be 0x01. In the future other
		// flag types may be supported.
		if flag[0] != 0x01 {
			str := fmt.Sprintf("witness tx but flag byte is %x", flag)
			return messageError("MsgTx.BtcDecode", str)
		}

		// With the Segregated Witness specific fields decoded, we can
		// now read in the actual txin count.
		count, err = ReadVarInt(r, pver)
		if err != nil {
			return err
		}
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// returnScriptBuffers is a closure that returns any script buffers that
	// were borrowed from the pool when there are any deserialization
	// errors.  This is only valid to call before the final step which
	// replaces the scripts with the location in a contiguous buffer and
	// returns them.
	returnScriptBuffers := func() {
		for _, txIn := range msg.TxIn {
			if txIn == nil {
				continue
			}

			if txIn.SignatureScript != nil {
				scriptPool.Return(txIn.SignatureScript)
			}

			for _, witnessElem := range txIn.Witness {
				if witnessElem != nil {
					scriptPool.Return(witnessElem)
				}
			}
		}
		for _, txOut := range msg.TxOut {
			if txOut == nil || txOut.PkScript == nil {
				continue
			}
			scriptPool.Return(txOut.PkScript)
		}
	}

	// Deserialize the inputs.
	var totalScriptSize uint64
	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		ti := &txIns[i]
		msg.TxIn[i] = ti
		err = readTxIn(r, pver, msg.Version, ti)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(ti.SignatureScript))
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxOutPerMessage) {
		returnScriptBuffers()
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the outputs.
	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is borrowed
		// and needs to be returned to the pool on error.
		to := &txOuts[i]
		msg.TxOut[i] = to
		err = readTxOut(r, pver, msg.Version, to)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSize += uint64(len(to.PkScript))
	}

	// If the transaction's flag byte isn't 0x00 at this point, then one or
	// more of its inputs has accompanying witness data.
	if flag[0] != 0 && enc == WitnessEncoding {
		for _, txin := range msg.TxIn {
			// For each input, the witness is encoded as a stack
			// with one or more items. Therefore, we first read a
			// varint which encodes the number of stack items.
			witCount, err := ReadVarInt(r, pver)
			if err != nil {
				returnScriptBuffers()
				return err
			}

			// Prevent a possible memory exhaustion attack by
			// limiting the witCount value to a sane upper bound.
			if witCount > maxWitnessItemsPerInput {
				returnScriptBuffers()
				str := fmt.Sprintf("too many witness items to fit "+
					"into max message size [count %d, max %d]",
					witCount, maxWitnessItemsPerInput)
				return messageError("MsgTx.BtcDecode", str)
			}

			// Then for witCount number of stack items, each item
			// has a varint length prefix, followed by the witness
			// item itself.
			txin.Witness = make([][]byte, witCount)
			for j := uint64(0); j < witCount; j++ {
				txin.Witness[j], err = readScript(r, pver,
					maxWitnessItemSize, "script witness item")
				if err != nil {
					returnScriptBuffers()
					return err
				}
				totalScriptSize += uint64(len(txin.Witness[j]))
			}
		}
	}

	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		returnScriptBuffers()
		return err
	}

	// Create a single allocation to house all of the scripts and set each
	// input signature script and output public key script to the
	// appropriate subslice of the overall contiguous buffer.  Then, return
	// each individual script buffer back to the pool so they can be reused
	// for future deserializations.  This is done because it significantly
	// reduces the number of allocations the garbage collector needs to
	// track, which in turn improves performance and drastically reduces the
	// amount of runtime overhead that would otherwise be needed to keep
	// track of millions of small allocations.
	//
	// NOTE: It is no longer valid to call the returnScriptBuffers closure
	// after these blocks of code run because it is already done and the
	// scripts in the transaction inputs and outputs no longer point to the
	// buffers.
	var offset uint64
	scripts := make([]byte, totalScriptSize)
	for i := 0; i < len(msg.TxIn); i++ {
		// Copy the signature script into the contiguous buffer at the
		// appropriate offset.
		signatureScript := msg.TxIn[i].SignatureScript
		copy(scripts[offset:], signatureScript)

		// Reset the signature script of the transaction input to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(signatureScript))
		end := offset + scriptSize
		msg.TxIn[i].SignatureScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(signatureScript)

		for j := 0; j < len(msg.TxIn[i].Witness); j++ {
			// Copy each item within the witness stack for this
			// input into the contiguous buffer at the appropriate
			// offset.
			witnessElem := msg.TxIn[i].Witness[j]
			copy(scripts[offset:], witnessElem)

			// Reset the witness item within the stack to the slice
			// of the contiguous buffer where the witness lives.
			witnessElemSize := uint64(len(witnessElem))
			end := offset + witnessElemSize
			msg.TxIn[i].Witness[j] = scripts[offset:end:end]
			offset += witnessElemSize

			// Return the temporary buffer used for the witness stack
			// item to the pool.
			scriptPool.Return(witnessElem)
		}
	}
	for i := 0; i < len(msg.TxOut); i++ {
		// Copy the public key script into the contiguous buffer at the
		// appropriate offset.
		pkScript := msg.TxOut[i].PkScript
		copy(scripts[offset:], pkScript)

		// Reset the public key script of the transaction output to the
		// slice of the contiguous buffer where the script lives.
		scriptSize := uint64(len(pkScript))
		end := offset + scriptSize
		msg.TxOut[i].PkScript = scripts[offset:end:end]
		offset += scriptSize

		// Return the temporary script buffer to the pool.
		scriptPool.Return(pkScript)
	}

	return nil
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
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// DeserializeNoWitness decodes a transaction from r into the receiver, where
// the transaction encoding format within r MUST NOT utilize the new
// serialization format created to encode transaction bearing witness data
// within inputs.
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := binarySerializer.PutUint32(w, littleEndian, uint32(msg.Version))
	if err != nil {
		return err
	}

	// If the encoding version is set to WitnessEncoding, and the Flags
	// field for the MsgTx aren't 0x00, then this indicates the transaction
	// is to be encoded using the new witness inclusionary structure
	// defined in BIP0144.
	doWitness := enc == WitnessEncoding && msg.HasWitness()
	if doWitness {
		// After the txn's Version field, we include two additional
		// bytes specific to the witness encoding. The first byte is an
		// always 0x00 marker byte, which allows decoders to
		// distinguish a serialized transaction with witnesses from a
		// regular (legacy) one. The second byte is the Flag field,
		// which at the moment is always 0x01, but may be extended in
		// the future to accommodate auxiliary non-committed fields.
		if _, err := w.Write(witessMarkerBytes); err != nil {
			return err
		}
	}

	count := uint64(len(msg.TxIn))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = writeTxIn(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = WriteTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	// If this transaction is a witness transaction, and the witness
	// encoded is desired, then encode the witness for each of the inputs
	// within the transaction.
	if doWitness {
		for _, ti := range msg.TxIn {
			err = writeTxWitness(w, pver, msg.Version, ti.Witness)
			if err != nil {
				return err
			}
		}
	}

	return binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTx) HasWitness() bool {
	for _, txIn := range msg.TxIn {
		if len(txIn.Witness) != 0 {
			return true
		}
	}

	return false
}

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
func (msg *MsgTx) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//
	// Passing a encoding type of WitnessEncoding to BtcEncode for MsgTx
	// indicates that the transaction's witnesses (if any) should be
	// serialized according to the new serialization structure defined in
	// BIP0144.
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes the transaction to w in an identical manner to
// Serialize, however even if the source transaction has inputs with witness
// data, the old serialization format will still be used.
func (msg *MsgTx) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTx) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTx) SerializeSize() int {
	n := msg.baseSize()

	if msg.HasWitness() {
		// The marker, and flag fields take up two additional bytes.
		n += 2

		// Additionally, factor in the serialized size of each of the
		// witnesses for each txin.
		for _, txin := range msg.TxIn {
			n += txin.Witness.SerializeSize()
		}
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the transaction, excluding any included witness data.
func (msg *MsgTx) SerializeSizeStripped() int {
	return msg.baseSize()
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw serialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTx) PkScriptLocs() []int {
	numTxOut := len(msg.TxOut)
	if numTxOut == 0 {
		return nil
	}

	// The starting offset in the serialized transaction of the first
	// transaction output is:
	//
	// Version 4 bytes + serialized varint size for the number of
	// transaction inputs and outputs + serialized size of each transaction
	// input.
	n := 4 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(numTxOut))

	// If this transaction has a witness input, the an additional two bytes
	// for the marker, and flag byte need to be taken into account.
	if len(msg.TxIn) > 0 && msg.TxIn[0].Witness != nil {
		n += 2
	}

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numTxOut)
	for i, txOut := range msg.TxOut {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + serialized varint size for the length of
		// PkScript.
		n += 8 + VarIntSerializeSize(uint64(len(txOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(txOut.PkScript)
	}

	return pkScriptLocs
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func readOutPoint(r io.Reader, pver uint32, version int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint32(r, littleEndian)
	return err
}

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, op.Index)
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhaustion attacks and forced panics through malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, messageError("readScript", str)
	}

	b := scriptPool.Borrow(count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		scriptPool.Return(b)
		return nil, err
	}
	return b, nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn) error {
	err := readOutPoint(r, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	ti.SignatureScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction input signature script")
	if err != nil {
		return err
	}

	return readElement(r, &ti.Sequence)
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxIn(w io.Writer, pver uint32, version int32, ti *TxIn) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, ti.SignatureScript)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, ti.Sequence)
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOut(r io.Reader, pver uint32, version int32, to *TxOut) error {
	err := readElement(r, &to.Value)
	if err != nil {
		return err
	}

	to.PkScript, err = readScript(r, pver, MaxMessagePayload,
		"transaction output public key script")
	return err
}

// WriteTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
//
// NOTE: This function is exported in order to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}

// writeTxWitness encodes the bitcoin protocol encoding for a transaction
// input's witness into to w.
func writeTxWitness(w io.Writer, pver uint32, version int32, wit [][]byte) error {
	err := WriteVarInt(w, pver, uint64(len(wit)))
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = WriteVarBytes(w, pver, item)
		if err != nil {
			return err
		}
	}
	return nil
}

//	todo(ABE)

// todo: the AddressScriptMaxLen may depend on the length of derived address and the rules that txscript builds an AddressScript from a derived address
var AddressScriptMaxLen = uint32(abesalrs.DpkByteLen + 10)
var ValueScriptMaxLen = uint32(10) //	todo (ABE): in salrs, it is just a int64; but for latter full version, it will be a commitment

const (
	BlockNumPerRingGroup = 3

	TxRingSize = 7

	TxInputMaxNum = 5

	TxOutputMaxNum = 20

	defaultTxInputAlloc = 3

	defaultTxOutputAlloc = 3

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
	//	todo(ABE): could be more accurate
	TxPayloadMaxSize = 30000
	TxPayloadMinSize = 100
)

type TxOutAbe struct {
	//	Version 		int16	//	the version could be used in ABE protocol update
	//ValueScript   []byte
	ValueScript   int64
	AddressScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (txOut *TxOutAbe) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of AddressScript + AddressScript bytes.
	//return VarIntSerializeSize(uint64(len(txOut.ValueScript))) + len(txOut.ValueScript) + VarIntSerializeSize(uint64(len(txOut.AddressScript))) + len(txOut.AddressScript)
	return 8 + VarIntSerializeSize(uint64(len(txOut.AddressScript))) + len(txOut.AddressScript)
}

func (txOut *TxOutAbe) Serialize(w io.Writer) error {
	/*	err := WriteVarBytes(w, 0, txOut.ValueScript)
		if err != nil {
			return err
		}*/

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
	/*	valueScript, err := ReadVarBytes(r, 0, ValueScriptMaxLen, "ValueScript")
		if err != nil {
			return err
		}
		txOut.ValueScript = valueScript*/

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
//	todo(ABE): shall index be int8?
type OutPointAbe struct {
	TxHash chainhash.Hash
	Index  uint8 //	due to the large size of post-quantum crypto primitives, ABE will limit the number of outputs of each transaction
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

	start := 0

	start = start + copy(buf[start:], op.TxHash.String())
	buf[start] = ':'

	start = start + 1
	start = start + copy(buf[start:], strconv.FormatUint(uint64(op.Index), 10))
	buf[start] = '.'
	start = start + 1

	return string(buf[0:start])
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
	BlockHashs []*chainhash.Hash //	the hashs for the blocks from which the ring was generated, at this moment it is 3 successive blocks
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

	err = WriteVarInt(w, 0, uint64(len(outPointRing.OutPoints)))
	if err != nil {
		return err
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

	if blockNum != BlockNumPerRingGroup {
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

func (outPointRing *OutPointRing) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	// TxHash:index; TxHash:index; ...; serialNumber
	//	index is at most 2 decimal digits; at this moment, only 1 decimal digits
	strLen := len(outPointRing.BlockHashs)*(2*chainhash.HashSize+1) + len(outPointRing.OutPoints)*(2*chainhash.HashSize+1+2+1)

	buf := make([]byte, strLen)

	start := 0

	for _, blockHash := range outPointRing.BlockHashs {
		start = start + copy(buf[start:], blockHash.String())
		buf[start] = ';'
		start = start + 1
	}
	buf[start-1] = '.'

	for _, outPoint := range outPointRing.OutPoints {
		start = start + copy(buf[start:], outPoint.TxHash.String())
		buf[start] = ','
		start = start + 1

		start = start + copy(buf[start:], strconv.FormatUint(uint64(outPoint.Index), 10))

		buf[start] = ';'
		start = start + 1
	}
	buf[start-1] = '.'

	return string(buf[0:start])
}

func NewOutPointRing(blockHashs []*chainhash.Hash, outPoints []*OutPointAbe) *OutPointRing {
	return &OutPointRing{
		BlockHashs: blockHashs,
		OutPoints:  outPoints,
	}
}

//	SerialNumber appears only when some ring member is consumed in TxIn,
//	i.e. logically, SerialNumber accompanies with TxIn.
type TxInAbe struct {
	SerialNumber chainhash.Hash
	//	identify the consumed OutPoint
	PreviousOutPointRing OutPointRing
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxInAbe(serialNumber *chainhash.Hash, previousOutPointRing *OutPointRing) *TxInAbe {
	return &TxInAbe{
		SerialNumber:         *serialNumber,
		PreviousOutPointRing: *previousOutPointRing,
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
	//	index is at most 2 decimal digits; at this moment, only 1 decimal digits
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

	return string(buf[0:start])
}

//	At this moment, TxIn is just a ring member (say, identified by (outpointRing, serialNumber)), so that we can use txIn.Serialize
//	If TxIn includes more information, this needs modification.
func (txIn *TxInAbe) RingMemberHash() chainhash.Hash {
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

	err = WriteVarInt(w, 0, uint64(len(txIn.PreviousOutPointRing.OutPoints)))
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
	/*	err := WriteVarBytes(w, pver, txOut.ValueScript)
		if err != nil {
			return err
		}*/

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
	if txWitness == nil {
		err := WriteVarInt(w, pver, uint64(0))
		if err != nil {
			return err
		}
		return nil
	}

	err := WriteVarInt(w, pver, uint64(len(txWitness.Witnesses)))
	for _, witnessItem := range txWitness.Witnesses {
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
	txWitness.Witnesses = make([]Witness, witItemNum)
	if witItemNum > 0 {
		for i := uint64(0); i < witItemNum; i++ {
			witnessItem, err := ReadVarBytes(r, pver, WitnessItemMaxLen, "WitnessItem")
			if err != nil {
				return err
			}
			txWitness.Witnesses[i] = witnessItem
		}
	}

	return nil
}

//	each transaction has a TxWitness, which consists of multiple Witness([]byte)
type Witness []byte
type TxWitnessAbe struct {
	Witnesses []Witness
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
	n := VarIntSerializeSize(uint64(len(txWitness.Witnesses)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range txWitness.Witnesses {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

func (txWitness TxWitnessAbe) Serialize(w io.Writer) error {
	err := WriteVarInt(w, 0, uint64(len(txWitness.Witnesses)))
	if err != nil {
		return err
	}

	for _, witItem := range txWitness.Witnesses {
		err = WriteVarBytes(w, 0, witItem)
		if err != nil {
			return err
		}
	}
	return nil
}

func (txWitness *TxWitnessAbe) Deserialize(r io.Reader) error {
	witnessNum, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	txWitness.Witnesses = make([]Witness, witnessNum)
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

		txWitness.Witnesses[i] = witnessItem
	}

	return nil
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
	Version int32
	TxIns   []*TxInAbe
	//	TxOutHashs []*chainhash.Hash
	TxOuts []*TxOutAbe
	//	txWitnessHash chainhash.Hash
	TxFee     int64
	TxWitness *TxWitnessAbe // Each Tx has one witness, consisting all necessary information, for example, signatures for inputs, range proofs for outputs, balance between inputs and outputs
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
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise.
func (msg *MsgTxAbe) IsCoinBase() bool {
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

	//	TxFee
	err = WriteVarInt(w, 0, uint64(msg.TxFee))
	if err != nil {
		return err
	}

	// witness details
	err = writeTxWitnessAbe(w, 0, msg.Version, msg.TxWitness)
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

	//	TxFee
	txFee, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxFee = int64(txFee)

	//	witness details
	txWitness := TxWitnessAbe{}
	err = readTxWitnessAbe(r, pver, msg.Version, &txWitness)
	if err != nil {
		return err
	}
	msg.TxWitness = &txWitness

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
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return chainhash.DoubleHashH(buf.Bytes())
}

func (msg *MsgTxAbe) TxHashFull() chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSizeFull()))
	_ = msg.SerializeFull(buf)
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

	//	TxFee
	n = n + VarIntSerializeSize(uint64(msg.TxFee))

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

	n := msg.SerializeSize()

	//	Witness Details
	if msg.TxWitness == nil {
		return n
	} else {
		return n + msg.TxWitness.SerializeSize()
	}
}

//	for computing TxId by hash, and for being serialized in block
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

	//	TxFee
	err = WriteVarInt(w, 0, uint64(msg.TxFee))
	if err != nil {
		return err
	}

	/*	//	TxWitness
		err = msg.TxWitness.Serialize(w)
		if err != nil {
			return err
		}*/

	return nil

}

func (msg *MsgTxAbe) SerializeFull(w io.Writer) error {
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

	//	TxFee
	err = WriteVarInt(w, 0, uint64(msg.TxFee))
	if err != nil {
		return err
	}

	//	TxWitness
	if msg.TxWitness != nil {
		err = msg.TxWitness.Serialize(w)
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

	//	TxFee
	txFee, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.TxFee = int64(txFee)

	/*	// witness details
		txWitness := TxWitnessAbe{}
		err = txWitness.Deserialize(r)
		if err != nil {
			return err
		}
		msg.txWitness = txWitness*/

	return nil
}
func (msg *MsgTxAbe) DeserializeFull(r io.Reader) error {
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

	//	TxFee
	txFee, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	msg.TxFee = int64(txFee)

	// witness details
	txWitness := &TxWitnessAbe{}
	err = txWitness.Deserialize(r)
	//TODO(abe):MUST restore this
	//if err != nil {
	//	return err
	//}
	msg.TxWitness = txWitness

	return nil
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTxAbe(version int32) *MsgTxAbe {
	return &MsgTxAbe{
		Version: version,
		TxIns:   make([]*TxInAbe, 0, defaultTxInputAlloc),
		TxOuts:  make([]*TxOutAbe, 0, defaultTxInOutAlloc),
	}
}

func NewStandardCoinbaseTxIn(nextBlockHeight int32, extraNonce uint64) *TxInAbe {
	txIn := TxInAbe{}
	txIn.SerialNumber = chainhash.ZeroHash

	previousOutPointRing := OutPointRing{}
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

	return &txIn
}

//	the caller must have checked the format of the coinbaseTxMsg
func ExtractCoinbaseHeight(coinbaseTx *MsgTxAbe) int32 {
	blockhash0 := coinbaseTx.TxIns[0].PreviousOutPointRing.BlockHashs[0]
	blockHeight := int32(binary.BigEndian.Uint32(blockhash0[0:4]))
	return blockHeight
}
