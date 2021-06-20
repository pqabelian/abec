package blockchain

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/pqringctparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
	"io"
	"sort"
)

//	Abe to do: we may need add the fields: the Height and hash of the representive block
// UtxoEntry houses details about an individual transaction output in a utxo
// view such as whether or not it was contained in a coinbase tx, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
type UtxoRingEntry struct {
	/*	// NOTE: Additions, deletions, or modifications to the order of the
		// definitions in this struct should not be changed without considering
		// how it affects alignment on 64-bit platforms.  The current order is
		// specifically crafted to result in minimal padding.  There will be a
		// lot of these in memory, so a few extra bytes of padding adds up.

		amount      int64
		pkScript    []byte // The public key script for the output.
		blockHeight int32  // Height of block containing tx.

		// packedFlags contains additional info about output such as whether it
		// is a coinbase, whether it is spent, and whether it has been modified
		// since it was loaded.  This approach is used in order to reduce memory
		// usage since there will be a lot of these in memory.
		packedFlags txoFlags*/

	Version uint32
	//	ringHash	chainhash.Hash	//	the hash of ring members, i.e. OutPoint(txHash, index)
	ringBlockHeight int32
	outPointRing    *wire.OutPointRing
	txOuts          []*wire.TxOutAbe
	//	generatingBlockHeights []int32	// height of block that generates txOuts[i]
	serialNumbers       [][]byte //	when a member is consumed, a corresponding serilaNumber is added
	consumingBlockHashs []*chainhash.Hash
	//	consumingBlockHeights	[]int32
	//	height of block that consumes txOuts[i],
	//	when len(serilaNumbers) = len(txOuts) and the last consumingBlockHeight is safe,
	//	the UtxoRingEntry can be removed, store to databse, or even deleted from database

	packedFlags txoFlags
}

// errDeserialize signifies that a problem was encountered when deserializing
// data.
type errUtxoRingDeserialize string

// Error implements the error interface.
func (e errUtxoRingDeserialize) Error() string {
	return string(e)
}

// isUtxoRingErr returns whether or not the passed error is an errDeserialize
// error.
func isUtxoRingDeserializeErr(err error) bool {
	_, ok := err.(errUtxoRingDeserialize)
	return ok
}

func (entry *UtxoRingEntry) IsSpent(serialNumber []byte) bool {

	/*	if len(entry.serialNumbers) == len(entry.txOuts) {
		return true
	}*/

	for _, sn := range entry.serialNumbers {
		if bytes.Compare(sn, serialNumber) == 0 {
			return true
		}
	}

	return false
}

func (entry *UtxoRingEntry) IsAllSpent() bool {

	if len(entry.serialNumbers) == len(entry.txOuts) {
		return true
	}

	return false
}

func (entry *UtxoRingEntry) IsCoinBase() bool {
	return entry.packedFlags&tfCoinBase == tfCoinBase
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *UtxoRingEntry) isModified() bool {
	return entry.packedFlags&tfModified == tfModified
}

// BlockHeight returns the height of the block containing the output.
func (entry *UtxoRingEntry) RingBlockHeight() int32 {
	/*
		ringBlockHeight := int32(-1)
		for _, blkHeight := range entry.generatingBlockHeights{
			if blkHeight > ringBlockHeight {
				ringBlockHeight = blkHeight
			}
		}

		//	each 3 blocks form a group
		if ringBlockHeight % 3 == 0 {
			return ringBlockHeight
		}

		ringBlockHeight = ringBlockHeight + 1
		if ringBlockHeight % 3 == 0 {
			return ringBlockHeight
		}

		ringBlockHeight = ringBlockHeight + 1
		return ringBlockHeight*/

	return entry.ringBlockHeight
}

// BlockHeight returns the height of the block containing the output.
func (entry *UtxoRingEntry) OutPointRing() *wire.OutPointRing {
	return entry.outPointRing
}

func (entry *UtxoRingEntry) TxOuts() []*wire.TxOutAbe {
	return entry.txOuts
}

func (entry *UtxoRingEntry) SerialNumbers() [][]byte {
	return entry.serialNumbers
}

func (entry *UtxoRingEntry) ConsumingBlockHashs() []*chainhash.Hash {
	return entry.consumingBlockHashs
}

func (entry *UtxoRingEntry) SerializeSize() int {

	//	utxoRingHeaderCode
	//	blockHeight and IsCoinBase
	utxoRingHeaderCode := uint64(entry.RingBlockHeight()) << 1
	if entry.IsCoinBase() {
		utxoRingHeaderCode |= 0x01
	}

	n := wire.VarIntSerializeSize(utxoRingHeaderCode)
	n = n + wire.VarIntSerializeSize(uint64(entry.Version))
	//	outPointRing
	n = n + entry.outPointRing.SerializeSize()

	//	ring size
	n = n + wire.VarIntSerializeSize(uint64(len(entry.txOuts)))

	//	txOuts
	for _, txOut := range entry.txOuts {
		n = n + txOut.SerializeSize()
	}

	/*	//	GeneratingBlockHeights
		for _, generatingBlockHeight := range entry.generatingBlockHeights {
			n = n + wire.VarIntSerializeSize(uint64(generatingBlockHeight))
		}*/

	//	number of consumed (serialNumbers)
	n = n + wire.VarIntSerializeSize(uint64(len(entry.serialNumbers)))

	//	serialNumbers
	n = n + len(entry.serialNumbers)*chainhash.HashSize

	//	ConsumingBlockHashs
	n = n + len(entry.consumingBlockHashs)*chainhash.HashSize

	/*	//	ConsumingBlockHeights
		for _, consumingBlockHeight := range entry.consumingBlockHeights {
			n = n + wire.VarIntSerializeSize(uint64(consumingBlockHeight))
		}*/

	return n
}

func (entry *UtxoRingEntry) Serialize(w io.Writer) error {
	//	utxoRingHeaderCode
	//	blockHeight and IsCoinBase
	utxoRingHeaderCode := uint64(entry.RingBlockHeight()) << 1
	if entry.IsCoinBase() {
		utxoRingHeaderCode |= 0x01
	}
	err := wire.WriteVarInt(w, 0, utxoRingHeaderCode)
	if err != nil {
		return err
	}

	err = wire.WriteVarInt(w, 0, uint64(entry.Version))
	if err != nil {
		return err
	}

	err = wire.WriteOutPointRing(w, 0, entry.Version, entry.outPointRing)
	if err != nil {
		return err
	}


		//	ring size
		if len(entry.txOuts) != len(entry.outPointRing.OutPoints) {
			return AssertError(fmt.Sprintf("The size of txOuts does not match the numner of OutPoints"))
		}
		err = wire.WriteVarInt(w, 0, uint64(len(entry.txOuts)))
		if err != nil {
			return err
		}

		//	txOuts
		for _, txOut := range entry.txOuts {
			err = wire.WriteTxOutAbe(w, 0, entry.Version, txOut)
			if err != nil {
				return err
			}
		}

		/*	//	GeneratingBlockHeights
			if len(entry.generatingBlockHeights) != len(entry.txOuts) {
				return AssertError(fmt.Sprintf("The size of GeneratingBlockHeights does not match the ring size"))
			}
			for _, generatingBlockHeight := range entry.generatingBlockHeights {
				err = wire.WriteVarInt(w, 0, uint64(generatingBlockHeight))
				if err != nil {
					return err
				}
			}*/

		//	number of consumed (serialNumbers)
		if len(entry.serialNumbers) > len(entry.txOuts) {
			return AssertError(fmt.Sprintf("The size of consumed serialNumbers exceeds the ring size"))
		}
		err = wire.WriteVarInt(w, 0, uint64(len(entry.serialNumbers)))
		if err != nil {
			return err
		}
		for _, serialNumber := range entry.serialNumbers {
			_, err = w.Write(serialNumber[:])
			if err != nil {
				return err
			}
		}
		if len(entry.consumingBlockHashs) != len(entry.serialNumbers) {
			return AssertError(fmt.Sprintf("The number of consumed serialNumbers does not mathc the number of corresponidng block hashes"))
		}
		for _, consumingBlockHash := range entry.consumingBlockHashs {
			_, err = w.Write(consumingBlockHash[:])
			if err != nil {
				return err
			}
		}

		/*
			if len(entry.consumingBlockHeights) != len(entry.serialNumbers) {
				return AssertError(fmt.Sprintf("The size of consumed serialNumbers exceeds the ring size"))
			}
			for _, consumingBlockHeight := range entry.consumingBlockHeights {
				err = wire.WriteVarInt(w, 0, uint64(consumingBlockHeight))
				if err != nil {
					return err
				}
			}*/


	return nil
}

func (entry *UtxoRingEntry) Deserialize(r io.Reader) error {
	//	utxoRingHeaderCode
	//	blockHeight and IsCoinBase
	utxoRingHeaderCode, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	isCoinBase := utxoRingHeaderCode&0x01 != 0
	ringBlockHeight := int32(utxoRingHeaderCode >> 1)

	entry.ringBlockHeight = ringBlockHeight
	entry.packedFlags = 0
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	entry.Version = uint32(version)

	entry.outPointRing = &wire.OutPointRing{}
	err = wire.ReadOutPointRing(r, 0,entry.Version,entry.outPointRing)
	if err != nil {
		return err
	}


		//	ring size
		// TODO(abe): the ring size coule be than 4? 20210225
		ringSize, err := wire.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		if ringSize > wire.TxRingSize {
			return errUtxoRingDeserialize("The UtxoRingEntry to be deserlized has a ring size greater than the allowed max value")
		}
		if ringSize != uint64(len(entry.outPointRing.OutPoints)) {
			return errUtxoRingDeserialize("The UtxoRingEntry to be deserlized has a ring size does not match the size in OutPointRing")
		}

		entry.txOuts = make([]*wire.TxOutAbe, ringSize)
		//	txOuts
		for i := uint64(0); i < ringSize; i++ {
			txOut := wire.TxOutAbe{}
			err = wire.ReadTxOutAbe(r,0,entry.Version,&txOut)
			if err != nil {
				return err
			}
			entry.txOuts[i] = &txOut
		}

		/*	//	GeneratingBlockHeights
			entry.generatingBlockHeights = make([]int32, ringSize)
			for i := uint64(0); i < ringSize; i++ {
				generatingBlockHeight, err := wire.ReadVarInt(r, 0)
				if err != nil {
					return err
				}
				if int32(generatingBlockHeight) > ringBlockHeight {
					return errUtxoRingDeserialize("The UtxoRingEntry to be deserlized does not obey the protocol on the block height of the ring members and the ring.")
				}
				entry.generatingBlockHeights[i] = int32(generatingBlockHeight)
			}*/

		//	consumed serialNumbers
		consumedNum, err := wire.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		if consumedNum > ringSize {
			return errUtxoRingDeserialize("The UtxoRingEntry to be deserlized has a size of consumed serialNumbers that exceeds the ring size")
		}

		entry.serialNumbers = make([][]byte, consumedNum)
		//	serialNumbers
		for i := uint64(0); i < consumedNum; i++ {
			serialNumber := make([]byte, pqringctparam.GetTxoSerialNumberLen(entry.outPointRing.Version))
			_, err := io.ReadFull(r, serialNumber[:])
			if err != nil {
				return err
			}
			entry.serialNumbers[i] = serialNumber
		}
		//	consumingBlockHashs
		entry.consumingBlockHashs = make([]*chainhash.Hash, consumedNum)
		for i := uint64(0); i < consumedNum; i++ {
			consumingBlockHash := chainhash.Hash{}
			_, err := io.ReadFull(r, consumingBlockHash[:])
			if err != nil {
				return err
			}
			entry.consumingBlockHashs[i] = &consumingBlockHash
		}

		/*	//	consumingBlockHeights
			entry.consumingBlockHeights = make([]int32, consumedNum)
			for i := uint64(0); i < consumedNum; i++ {
				consumingBlockHeight, err := wire.ReadVarInt(r, 0)
				if err != nil {
					return err
				}
				entry.consumingBlockHeights[i] = int32(consumingBlockHeight)
			}*/


	return nil
}

//	This is a temporary method, which is used only for the SALRS version, where the coin value is public,
//	and only TXOs with the same value are grouped into a ring.
/*func (entry *UtxoRingEntry) Amount() int64 {
	amount := int64(-1)
	if len(entry.txOuts) >= 1 {
		amount = entry.txOuts[0].ValueScript
	}

	return amount
}*/

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
// The caller should check double-spending before calling this function
func (entry *UtxoRingEntry) Spend(serilaNumber []byte, blockHash *chainhash.Hash) {
	//	Abe to do: double spending?
	for i, sn := range entry.serialNumbers {
		if bytes.Compare(sn, serilaNumber) == 0 {
			if blockHash.IsEqual(entry.consumingBlockHashs[i]) {
				return
			}

			entry.consumingBlockHashs[i] = blockHash
			entry.packedFlags |= tfModified
			return
		}
	}

	entry.serialNumbers = append(entry.serialNumbers, serilaNumber)
	entry.consumingBlockHashs = append(entry.consumingBlockHashs, blockHash)
	entry.packedFlags |= tfModified
	// Mark the output as modified.
}

//	normaly, the unspent serialNumber should be the last one, as this function should be called in reverse order
func (entry *UtxoRingEntry) UnSpend(serilaNumber []byte, blockHash *chainhash.Hash) bool {
	for i, sn := range entry.serialNumbers {
		if bytes.Compare(sn, serilaNumber) == 0 {
			if blockHash.IsEqual(entry.consumingBlockHashs[i]) {
				copy(entry.serialNumbers[:i], entry.serialNumbers[i+1:])
				entry.serialNumbers = entry.serialNumbers[:len(entry.serialNumbers)-1]

				copy(entry.consumingBlockHashs[:i], entry.consumingBlockHashs[i+1:])
				entry.consumingBlockHashs = entry.consumingBlockHashs[:len(entry.consumingBlockHashs)-1]

				entry.packedFlags |= tfModified

				return true
			} else {
				return false
			}
		}
	}

	return false
}

// Clone returns a shallow copy of the utxo entry.
func (entry *UtxoRingEntry) Clone() *UtxoRingEntry {
	if entry == nil {
		return nil
	}

	utxoRing := UtxoRingEntry{}

	utxoRing.ringBlockHeight = entry.ringBlockHeight
	utxoRing.outPointRing = entry.outPointRing
	utxoRing.txOuts = entry.txOuts
	//	utxoRing.generatingBlockHeights = entry.generatingBlockHeights
	//	the above are invariant contents for utxoRing, so we use shallow copy
	spentTxoNum := len(entry.serialNumbers)
	utxoRing.serialNumbers = make([][]byte, spentTxoNum)
	utxoRing.consumingBlockHashs = make([]*chainhash.Hash, spentTxoNum)
	//	utxoRing.consumingBlockHeights = make([]int32, spentTxoNum)
	for i := 0; i < spentTxoNum; i++ {
		utxoRing.serialNumbers[i] = entry.serialNumbers[i]
		//		utxoRing.consumingBlockHeights[i] = entry.consumingBlockHeights[i]
		utxoRing.consumingBlockHashs[i] = entry.consumingBlockHashs[i]
	}
	utxoRing.packedFlags = entry.packedFlags

	return &utxoRing
}

func (entry *UtxoRingEntry) IsSame(obj *UtxoRingEntry) bool {
	if entry == nil {
		if obj == nil {
			return true
		} else {
			return false
		}
	}

	entrySize := entry.SerializeSize()
	objSize := obj.SerializeSize()
	if entrySize != objSize {
		return false
	}

	bufEntry := bytes.NewBuffer(make([]byte, 0, entrySize))
	err := entry.Serialize(bufEntry)
	if err != nil {
		return false
	}

	bufObj := bytes.NewBuffer(make([]byte, 0, objSize))
	err = entry.Serialize(bufObj)
	if err != nil {
		return false
	}

	if !bytes.Equal(bufEntry.Bytes(), bufObj.Bytes()) {
		return false
	}

	return true
}

func initNewUtxoRingEntry(version uint32, ringBlockHeight int32, blockhashs []*chainhash.Hash, ringMemberTxos []*RingMemberTxo, isCoinBase bool) (*UtxoRingEntry, error) {

	ringSize := len(ringMemberTxos)
	if ringSize == 0 {
		return nil, nil
	}

	utxoRingEntry := &UtxoRingEntry{
		Version: version,
		ringBlockHeight: ringBlockHeight,
	}

	outPoints := make([]*wire.OutPointAbe, ringSize)
	txOuts := make([]*wire.TxOutAbe, ringSize)
	for i := 0; i < ringSize; i++ {
		outPoints[i] = ringMemberTxos[i].outPoint
		txOuts[i] = ringMemberTxos[i].txOut
		if txOuts[i].Version != version {
			return nil, errors.New("the TXOS to be in a ring do not have the same version")
		}
	}

	utxoRingEntry.outPointRing = wire.NewOutPointRing(version, blockhashs, outPoints)
	utxoRingEntry.txOuts = txOuts

	utxoRingEntry.serialNumbers = nil
	utxoRingEntry.consumingBlockHashs = nil

	utxoRingEntry.packedFlags = tfModified
	if isCoinBase {
		utxoRingEntry.packedFlags |= tfCoinBase
	}

	return utxoRingEntry, nil
}

// UtxoViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.

type UtxoRingViewpoint struct {
	entries  map[chainhash.Hash]*UtxoRingEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoRingViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *UtxoRingViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *UtxoRingViewpoint) LookupEntry(outPointRingHash chainhash.Hash) *UtxoRingEntry {
	return view.entries[outPointRingHash]
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *UtxoRingViewpoint) Entries() map[chainhash.Hash]*UtxoRingEntry {
	return view.entries
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *UtxoRingViewpoint) commit() {
	for outPointHash, entry := range view.entries {
		if entry == nil || (entry.isModified() && entry.IsAllSpent()) {
			delete(view.entries, outPointHash)
			continue
		}

		entry.packedFlags ^= tfModified
	}
}

// fetchInputUtxos loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *UtxoRingViewpoint) fetchInputUtxoRings(db database.DB, block *abeutil.BlockAbe) error {
	/*	// Build a map of in-flight transactions because some of the inputs in
		// this block could be referencing other transactions earlier in this
		// block which are not yet in the chain.
		txInFlight := map[chainhash.Hash]int{}
		transactions := block.Transactions()
		for i, tx := range transactions {
			txInFlight[*tx.Hash()] = i
		}

		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		neededSet := make(map[wire.OutPoint]struct{})
		for i, tx := range transactions[1:] {
			for _, txIn := range tx.MsgTx().TxIns {
				// It is acceptable for a transaction input to reference
				// the output of another transaction in this block only
				// if the referenced transaction comes before the
				// current one in this block.  Add the outputs of the
				// referenced transaction as available utxos when this
				// is the case.  Otherwise, the utxo details are still
				// needed.
				//
				// NOTE: The >= is correct here because i is one less
				// than the actual position of the transaction within
				// the block due to skipping the coinbase.
				originHash := &txIn.PreviousOutPoint.Hash
				if inFlightIndex, ok := txInFlight[*originHash]; ok &&
					i >= inFlightIndex {

					originTx := transactions[inFlightIndex]
					view.AddTxOuts(originTx, block.Height())
					continue
				}

				// Don't request entries that are already in the view
				// from the database.
				if _, ok := view.entries[txIn.PreviousOutPoint]; ok {
					continue
				}

				neededSet[txIn.PreviousOutPoint] = struct{}{}
			}
		}*/

	neededSet := make(map[chainhash.Hash]struct{})
	for _, tx := range block.Transactions()[1:] {
		for _, txIn := range tx.MsgTx().TxIns {
			// Don't request entries that are already in the view
			// from the database.
			if _, ok := view.entries[txIn.PreviousOutPointRing.Hash()]; !ok {
				neededSet[txIn.PreviousOutPointRing.Hash()] = struct{}{}
			}
		}
	}

	// Request the input utxos from the database.
	return view.fetchUtxoRingsMain(db, neededSet)
}

// fetchUtxosMain fetches unspent transaction output data about the provided
// set of outpoints from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested outpoint.  Spent outputs, or those which otherwise don't exist,
// will result in a nil entry in the view.
//	Abe to do: to get the UtxoRings for main chain, should fetch from db
func (view *UtxoRingViewpoint) fetchUtxoRingsMain(db database.DB, outPointRings map[chainhash.Hash]struct{}) error {
	// Nothing to do if there are no requested outputs.
	if len(outPointRings) == 0 {
		return nil
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return db.View(func(dbTx database.Tx) error {
		for outPointRingHash, _ := range outPointRings {
			entry, err := dbFetchUtxoRingEntry(dbTx, outPointRingHash)
			if err != nil {
				return err
			}

			view.entries[outPointRingHash] = entry
		}

		return nil
	})
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewUtxoRingViewpoint() *UtxoRingViewpoint {
	return &UtxoRingViewpoint{
		entries: make(map[chainhash.Hash]*UtxoRingEntry),
	}
}

// FetchUtxoRingView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
//	todo(ABE): ABE does not fetch the utxos for the outputs, as it is impossible to have duplicate transactions
// This function is safe for concurrent access however the returned view is NOT.
func (b *BlockChain) FetchUtxoRingView(tx *abeutil.TxAbe) (*UtxoRingViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction.
	neededSet := make(map[chainhash.Hash]struct{})

	if !tx.IsCoinBase() {
		for _, txIn := range tx.MsgTx().TxIns {
			neededSet[txIn.PreviousOutPointRing.Hash()] = struct{}{}
		}
	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	view := NewUtxoRingViewpoint()
	b.chainLock.RLock()
	err := view.fetchUtxoRingsMain(b.db, neededSet)
	b.chainLock.RUnlock()
	return view, err
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
/*func (view *UtxoRingViewpoint) connectTransaction(tx *abeutil.Tx, blockHeight int32, stxos *[]SpentTxOut) error {
	// Coinbase transactions don't have any inputs to spend.
	if IsCoinBase(tx) {
		// Add the transaction's outputs as available utxos.
		view.AddTxOuts(tx, blockHeight)
		return nil
	}

	// Spend the referenced utxos by marking them spent in the view and,
	// if a slice was provided for the spent txout details, append an entry
	// to it.
	for _, txIn := range tx.MsgTx().TxIn {
		// Ensure the referenced utxo exists in the view.  This should
		// never happen unless there is a bug is introduced in the code.
		entry := view.entries[txIn.PreviousOutPoint]
		if entry == nil {
			return AssertError(fmt.Sprintf("view missing input %v",
				txIn.PreviousOutPoint))
		}

		// Only create the stxo details if requested.
		if stxos != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentTxOut{
				Amount:     entry.Amount(),
				PkScript:   entry.PkScript(),
				Height:     entry.BlockHeight(),
				IsCoinBase: entry.IsCoinBase(),
			}
			*stxos = append(*stxos, stxo)
		}

		// Mark the entry as spent.  This is not done until after the
		// relevant details have been accessed since spending it might
		// clear the fields from memory in the future.
		entry.Spend()
	}

	// Add the transaction's outputs as available utxos.
	view.AddTxOuts(tx, blockHeight)
	return nil
}*/

//Abe to do: In ABE, the connectTransaction algorithm only 'spend' TxoRings, does not generate new TxoRing.
//	Only the blocks with height%3 ==0 will trigger the generation of new TxoRings.
func (view *UtxoRingViewpoint) connectTransaction(tx *abeutil.TxAbe, blockhash *chainhash.Hash, stxos *[]*SpentTxOutAbe) error {
	// Coinbase transactions don't have any inputs to spend.
	if tx.IsCoinBase() {
		/*		// Add the transaction's outputs as available utxos.
				view.AddTxOuts(tx, blockHeight)*/
		return nil
	}

	// Spend the referenced utxos by marking them spent in the view and,
	// if a slice was provided for the spent txout details, append an entry
	// to it.
	for _, txIn := range tx.MsgTx().TxIns {
		// Ensure the referenced utxo exists in the view.  This should
		// never happen unless there is a bug is introduced in the code.
		outPointRingHash := txIn.PreviousOutPointRing.Hash()
		entry := view.entries[outPointRingHash]
		if entry == nil {
			return AssertError(fmt.Sprintf("view missing input %s",
				txIn.String()))
		}
		if entry.IsSpent(txIn.SerialNumber) {
			//	here, if multiple transactions consume the same txo (identified by serialnumber), it will be detected
			return AssertError(fmt.Sprintf("Transaction (hash = %v) is attemting to double spneding with input %s",
				tx.MsgTx().TxHash(), txIn.String()))
		}

		// Only create the stxo details if requested.
		if stxos != nil {
			// Populate the stxo details using the utxo entry.
			stxo := new(SpentTxOutAbe)
			copy(stxo.SerialNumber[:], txIn.SerialNumber[:])
			stxo.UtxoRing = entry.Clone()

			*stxos = append(*stxos, stxo)
		}

		// Mark the entry as spent.  This is not done until after the
		// relevant details have been accessed since spending it might
		// clear the fields from memory in the future.
		entry.Spend(txIn.SerialNumber, blockhash)
	}

	// Add the transaction's outputs as available utxos.
	//	view.AddTxOuts(tx, blockHeight)
	return nil
}

// connectTransactions updates the view by adding all new utxos created by all
// of the transactions in the passed block, marking all utxos the transactions
// spend as spent, and setting the best hash for the view to the passed block.
// In addition, when the 'stxos' argument is not nil, it will be updated to
// append an entry for each spent txout.
func (view *UtxoRingViewpoint) connectTransactions(block *abeutil.BlockAbe, stxos *[]*SpentTxOutAbe) error {
	for _, tx := range block.Transactions() {
		err := view.connectTransaction(tx, block.Hash(), stxos)
		if err != nil {
			return err
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
//	Abe to do: use the spendJournal to collect and update utxoRing
func (view *UtxoRingViewpoint) disconnectTransactions(db database.DB, block *abeutil.BlockAbe, stxos []*SpentTxOutAbe) error {
	// Sanity check the correct number of stxos are provided.
	if len(stxos) != countSpentOutputsAbe(block) {
		return AssertError("disconnectTransactions called with bad " +
			"spent transaction out information")
	}

	// Loop backwards through all transactions so everything is unspent in
	// reverse order. This is necessary since multiples transactions in one block may spend different serialNumbers of the same ring,
	// and the corresponding STXOs were generated forward.
	//	Here, we directly use STXOs to restore the UtxoRing, without considering the transactions in the block
	for i := len(stxos) - 1; i >= 0; i-- {
		stxo := stxos[i]
		utxoRingEntry := view.entries[stxo.UtxoRing.outPointRing.Hash()]

		if utxoRingEntry != nil {
			unSpend := utxoRingEntry.UnSpend(stxo.SerialNumber, block.Hash())
			if !unSpend {
				return AssertError("disconnectTransactions called with bad " +
					"spent transaction out information: fail to unspend")
			}
			if !utxoRingEntry.IsSame(stxo.UtxoRing) {
				return AssertError("disconnectTransactions called with bad " +
					"spent transaction out information: the resulting Utxo of unspending is different from the one in STXO")
			}

		} else {
			//	actually, can directly use the following codes to unspend
			//	the above codes in if{} has the same effect, but with strictest check.
			//	At initial development, the strictesct check may help find potential situations
			loadUtxoRing := stxo.UtxoRing.Clone()
			loadUtxoRing.packedFlags |= tfModified
			view.entries[loadUtxoRing.outPointRing.Hash()] = loadUtxoRing
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

func (view *UtxoRingViewpoint) newUtxoRingEntries(db database.DB, node *blockNode, block *abeutil.BlockAbe) error {
	if node == nil || block == nil {
		return AssertError("newUtxoRingEntriesFromNode is called with nil node or nil block.")
	}

	if !(node.height%3 == 2) {
		return AssertError("newUtxoRingEntriesFromNode is called with node where node.height % 3 != 2.")
	}

	if !view.bestHash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntriesFromNode is called with block's hash not equal to the view.bestHash")
	}

	node1 := node.parent
	node0 := node1.parent
	if node1 == nil || node0 == nil {
		return AssertError("a node with height %2 == 0 should have two previous successive nodes.")
	}

	if !node.hash.IsEqual(block.Hash()) {
		return AssertError("newUtxoRingEntries is called with block that has different hash with the node.")
	}

	block2 := block
	var block1 *abeutil.BlockAbe
	var block0 *abeutil.BlockAbe
	err := db.View(func(dbTx database.Tx) error {
		var err error
		block1, err = dbFetchBlockByNodeAbe(dbTx, node1)
		if err != nil {
			return err
		}
		block0, err = dbFetchBlockByNodeAbe(dbTx, node0)
		return err
	})
	if err != nil {
		return err
	}

	if block0 == nil || block1 == nil {
		return AssertError("newUtxoRingEntries is called with node that does not have 2 previous successive blocks in database")
	}

	blocks := []*abeutil.BlockAbe{block0, block1, block2}
	ringBlockHeight := blocks[2].Height()
	blocksNum := len(blocks)

	blockHashs := make([]*chainhash.Hash, blocksNum)
	coinBaseRmTxoNum := 0
	transferRmTxoNum := 0
	for i := 0; i < blocksNum; i++ {
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
	txoSortStr := make([]byte, blocksNum*chainhash.HashSize+chainhash.HashSize+chainhash.HashSize+1)
	for i := 0; i < blocksNum; i++ {
		copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	for i := 0; i < blocksNum; i++ {
		block := blocks[i]
		blockHash := block.Hash()
		blockHeight := block.Height()

		copy(txoSortStr[blocksNum*chainhash.HashSize:], blockHash[:])

		coinBaseTx := block.Transactions()[0]
		txHash := coinBaseTx.Hash()
		copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])
		for outIndex, txOut := range coinBaseTx.MsgTx().TxOuts {
			txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

			txoOrderHash := chainhash.DoubleHashH(txoSortStr)

			ringMemberTxo := NewRingMemberTxo(coinBaseTx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
			allCoinBaseRmTxos = append(allCoinBaseRmTxos, ringMemberTxo)
		}
		for _, tx := range block.Transactions()[1:] {
			txHash := tx.Hash()
			copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range tx.MsgTx().TxOuts {
				txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := NewRingMemberTxo(tx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
				allTransferRmTxos = append(allTransferRmTxos, ringMemberTxo)
			}
		}
	}
	// TODO: change the version field in node and block to uint32 type?
	err = view.NewUtxoRingEntriesFromTxos(allCoinBaseRmTxos, ringBlockHeight, blockHashs, true)
	if err != nil {
		return err
	}

	err = view.NewUtxoRingEntriesFromTxos(allTransferRmTxos, ringBlockHeight, blockHashs, false)
	if err != nil {
		return err
	}
	return nil

}

/*func (view *UtxoRingViewpoint) newUtxoRingEntriesFromBlocks(blocks []*abeutil.BlockAbe) error {
	if len(blocks) != 3 {
		return AssertError("newUtxoRingEntriesFromBlocks called with not 3 blocks" )
	}

	if blocks[0] == nil || blocks[1] == nil || blocks[2] == nil {
		return AssertError("newUtxoRingEntriesFromBlocks called with nil blocks" )
	}

	if !(blocks[2].Height() >= 3 && blocks[2].Height() % 3 == 0) {
		return AssertError("newUtxoRingEntriesFromBlocks called with blocks with height % 3 != 0" )
	}

	if !( blocks[2].Height() == blocks[1].Height()+1 && blocks[1].Height() == blocks[0].Height()+1 ) {
		return AssertError("newUtxoRingEntriesFromBlocks called with blocks not successive" )
	}

	if !view.bestHash.IsEqual(blocks[2].Hash()) {
		return AssertError("newUtxoRingEntriesFromBlocks called with block's hash not equal to the view.bestHash" )
	}

	ringBlockHeight := blocks[2].Height()

	blocksNum := len(blocks)

	blockHashs := make([]*chainhash.Hash, blocksNum)
	coinBaseRmTxoNum := 0
	transferRmTxoNum := 0
	for i:=0; i<blocksNum; i++ {
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
	txoSortStr := make([]byte, blocksNum*chainhash.HashSize + chainhash.HashSize + chainhash.HashSize + 1)
	for i:=0; i < blocksNum; i++ {
		copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
	}

	for i:=0; i < blocksNum; i++ {
		block := blocks[i]
		blockHash := block.Hash()
		blockHeight := block.Height()

		copy(txoSortStr[blocksNum*chainhash.HashSize:], blockHash[:])

		coinBaseTx := block.Transactions()[0]
		txHash := coinBaseTx.Hash()
		copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])
		for outIndex, txOut := range coinBaseTx.MsgTx().TxOuts {
			txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

			txoOrderHash := chainhash.DoubleHashH(txoSortStr)

			ringMemberTxo := NewRingMemberTxo(&txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
			allCoinBaseRmTxos = append( allCoinBaseRmTxos, ringMemberTxo )
		}

		for _, tx := range block.Transactions()[1:] {
			txHash := tx.Hash()
			copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])

			for outIndex, txOut := range tx.MsgTx().TxOuts {
				txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := NewRingMemberTxo(&txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
				allTransferRmTxos = append( allTransferRmTxos, ringMemberTxo )
			}
		}
	}

	err := view.NewUtxoRingEntriesFromTxos( allCoinBaseRmTxos, ringBlockHeight, blockHashs,true )
	if err != nil {
		return err
	}

	err = view.NewUtxoRingEntriesFromTxos( allTransferRmTxos, ringBlockHeight, blockHashs,false )
	if err != nil {
		return err
	}

	return nil
}*/

func (view *UtxoRingViewpoint) NewUtxoRingEntriesFromTxos(ringMemberTxos []*RingMemberTxo, ringBlockHeight int32, blockhashs []*chainhash.Hash, isCoinBase bool) error {

	if len(ringMemberTxos) == 0 {
		return nil
	}

	// sort
	sort.Sort(ByOrderHashRingMemberTxo(ringMemberTxos))

	txoNum := len(ringMemberTxos)

	//	group Txos to rings
	normalRingNum := txoNum / wire.TxRingSize
	remainderTxoNum := txoNum % wire.TxRingSize

	//	totalRingNum := normalRingNum
	if remainderTxoNum != 0 {
		//	implies 0 < remainderTxoNum < wire.TxRingSize
		//		totalRingNum += 1

		if normalRingNum >= 1 {
			//	divide (the last normalRing and the remainder Txos) into 2 rings with ring_1.size = ring_2.size or ring_1.size = ring_2.size + 1
			normalRingNum -= 1
		} // else {
		// implies 	normalRingNum == 0
		//	the remainder forms the only ring
		//	}
	}

	for i := 0; i < normalRingNum; i++ {
		// rings with size wire.TxRingSize
		start := i * wire.TxRingSize
		utxoRingEntry, err := initNewUtxoRingEntry(ringMemberTxos[start].version, ringBlockHeight, blockhashs, ringMemberTxos[start:start+wire.TxRingSize], isCoinBase)
		if err != nil {
			return err
		}

		outPointRingHash := utxoRingEntry.outPointRing.Hash()
		if existingUtxoRing, ok := view.entries[outPointRingHash]; ok {
			return AssertError(fmt.Sprintf("Found a hash collision when calling NewUtxoRingEntriesFromTxos with block (hash %v, height %d),"+
				"with the UtxoRings generated with block (height %d)", view.bestHash, ringBlockHeight, existingUtxoRing.ringBlockHeight))
		} else {
			view.entries[outPointRingHash] = utxoRingEntry
		}
	}

	remainderTxoNum = txoNum - normalRingNum*wire.TxRingSize
	if remainderTxoNum > wire.TxRingSize {
		//	divide (the last normalRing and the remainder Txos) into 2 rings with sizes remainderTxoNum/2
		ringSize1 := remainderTxoNum / 2
		if remainderTxoNum%2 != 0 {
			ringSize1 += 1
		}

		// rings with size1
		start := normalRingNum * wire.TxRingSize
		utxoRingEntry1, err := initNewUtxoRingEntry(ringMemberTxos[start].version, ringBlockHeight, blockhashs, ringMemberTxos[start:start+ringSize1], isCoinBase)
		if err != nil {
			return err
		}

		outPointRingHash1 := utxoRingEntry1.outPointRing.Hash()
		if existingUtxoRing, ok := view.entries[outPointRingHash1]; ok {
			return AssertError(fmt.Sprintf("Found a hash collision when calling NewUtxoRingEntriesFromTxos with block (hash %v, height %d),"+
				"with the UtxoRings generated with block (height %d)", view.bestHash, ringBlockHeight, existingUtxoRing.ringBlockHeight))
		} else {
			view.entries[outPointRingHash1] = utxoRingEntry1
		}

		// rings with size2
		start = start + ringSize1
		utxoRingEntry2, err := initNewUtxoRingEntry(ringMemberTxos[start].version, ringBlockHeight, blockhashs, ringMemberTxos[start:], isCoinBase)
		if err != nil {
			return err
		}

		outPointRingHash2 := utxoRingEntry2.outPointRing.Hash()
		if existingUtxoRing, ok := view.entries[outPointRingHash2]; ok {
			return AssertError(fmt.Sprintf("Found a hash collision when calling NewUtxoRingEntriesFromTxos with block (hash %v, height %d),"+
				"with the UtxoRings generated with block (height %d)", view.bestHash, ringBlockHeight, existingUtxoRing.ringBlockHeight))
		} else {
			view.entries[outPointRingHash2] = utxoRingEntry2
		}

	} else if remainderTxoNum > 0 {
		//	one ring with size = remainderTxoNum
		start := normalRingNum * wire.TxRingSize
		utxoRingEntry, err := initNewUtxoRingEntry(ringMemberTxos[start].version, ringBlockHeight, blockhashs, ringMemberTxos[start:], isCoinBase)
		if err != nil {
			return err
		}

		outPointRingHash := utxoRingEntry.outPointRing.Hash()
		if existingUtxoRing, ok := view.entries[outPointRingHash]; ok {
			return AssertError(fmt.Sprintf("Found a hash collision when calling NewUtxoRingEntriesFromTxos with block (hash %v, height %d),"+
				"with the UtxoRings generated with block (height %d)", view.bestHash, ringBlockHeight, existingUtxoRing.ringBlockHeight))
		} else {
			view.entries[outPointRingHash] = utxoRingEntry
		}
	}

	return nil
}

type RingMemberTxo struct {
	version     uint32
	orderHash   *chainhash.Hash
	blockHash   *chainhash.Hash
	blockHeight int32
	outPoint    *wire.OutPointAbe
	txOut       *wire.TxOutAbe
}

func NewRingMemberTxo(version uint32, orderHash *chainhash.Hash, blockHash *chainhash.Hash, blockHeight int32, txHash *chainhash.Hash, outIndex uint8, txOut *wire.TxOutAbe) *RingMemberTxo {
	ringMemberTxo := RingMemberTxo{}
	ringMemberTxo.version = version
	ringMemberTxo.orderHash = orderHash

	ringMemberTxo.blockHash = blockHash
	ringMemberTxo.blockHeight = blockHeight
	ringMemberTxo.outPoint = wire.NewOutPointAbe(txHash, outIndex)
	ringMemberTxo.txOut = txOut

	return &ringMemberTxo
}

type ByOrderHashRingMemberTxo []*RingMemberTxo

func (x ByOrderHashRingMemberTxo) Len() int {
	return len(x)
}

func (x ByOrderHashRingMemberTxo) Less(i, j int) bool {
	return x[i].orderHash.String() < x[j].orderHash.String()
}

func (x ByOrderHashRingMemberTxo) Swap(i, j int) {
	x[i], x[j] = x[j], x[i]
}

// FetchUtxoEntry loads and returns the requested unspent transaction output
// from the point of view of the end of the main chain.
//
// NOTE: Requesting an output for which there is no data will NOT return an
// error.  Instead both the entry and the error will be nil.  This is done to
// allow pruning of spent transaction outputs.  In practice this means the
// caller must check if the returned entry is nil before invoking methods on it.
//
// This function is safe for concurrent access however the returned entry (if
// any) is NOT.
func (b *BlockChain) FetchUtxoRingEntry(outPointRing *wire.OutPointRing) (*UtxoRingEntry, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	ringHash := outPointRing.Hash()
	var entry *UtxoRingEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = dbFetchUtxoRingEntry(dbTx, ringHash)
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}
