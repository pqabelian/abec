package blockchain

import (
	"fmt"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/database"
)

// maybeAcceptBlockAbe potentially accepts a block into the block chain and, if
// accepted, returns whether or not it is on the main chain.  It performs
// several validation checks which depend on its position within the block chain
// before adding it.  The block is expected to have already gone through
// ProcessBlock before calling this function with it.
//
// The flags are also passed to checkBlockContext and connectBestChain.  See
// their documentation for how the flags modify their behavior.
//
// This function MUST be called with the chain state lock held (for writes).
//  1. Ensure the block has previous block (not an orphan) and the previous block should be valid
//  2. Set height for new block
//  3. Check the sanity of block context (checkBlockContextAbe)
//  4. Store the new block into database (currently the witness has not been validated)
//  5. Add the new block into block index
//  6. Connect new block to the chain, including reorganization and switch main chain if needed (connectBestChainAbe)
//  7. Send NTBlockAccepted notification
//
// todo_DOME(MLP): reviewed on 2024.01.05
func (b *BlockChain) maybeAcceptBlockAbe(block *abeutil.BlockAbe, flags BehaviorFlags) (bool, error) {
	// The height of this block is one more than the referenced previous
	// block.
	prevHash := &block.MsgBlock().Header.PrevBlock
	prevNode := b.index.LookupNode(prevHash)
	if prevNode == nil {
		str := fmt.Sprintf("previous block %s is unknown", prevHash)
		return false, ruleError(ErrPreviousBlockUnknown, str)
	} else if b.index.NodeStatus(prevNode).KnownInvalid() {
		str := fmt.Sprintf("previous block %s is known to be invalid", prevHash)
		return false, ruleError(ErrInvalidAncestorBlock, str)
	}

	blockHeight := prevNode.height + 1
	block.SetHeight(blockHeight)

	// The block must pass all the validation rules which depend on the
	// position of the block within the blockchain.
	// reviewed on 2024.01.03, by Alice for MLP
	err := b.checkBlockContextAbe(block, prevNode, flags)
	if err != nil {
		return false, err
	}

	// Insert the block into the database if it's not already there.  Even
	// though it is possible the block will ultimately fail to connect, it
	// has already passed all proof-of-work and validity tests which means
	// it would be prohibitively expensive for an attacker to fill up the
	// disk with a bunch of blocks that fail to connect.  This is necessary
	// since it allows block download to be decoupled from the much more
	// expensive connection logic.  It also has some other nice properties
	// such as making blocks that never become part of the main chain or
	// blocks that fail to connect available for further analysis.
	err = b.db.Update(func(dbTx database.Tx) error {
		return dbStoreBlockAbe(dbTx, block)
	})
	if err != nil {
		return false, err
	}

	// Create a new block node for the block and add it to the node index. Even
	// if the block ultimately gets connected to the main chain, it starts out
	// on a side chain.
	blockHeader := &block.MsgBlock().Header
	// todo: (EthashPoW)
	newNode, err := b.newBlockNode(blockHeader, prevNode)
	if err != nil {
		return false, err
	}

	newNode.status = statusDataStored

	b.index.AddNode(newNode)
	err = b.index.flushToDB()
	if err != nil {
		return false, err
	}

	// Connect the passed block to the chain while respecting proper chain
	// selection according to the chain with the most proof of work.  This
	// also handles validation of the transaction scripts.
	// todo_DONE(MLP): reviewed on 2024.01.03
	isMainChain, err := b.connectBestChainAbe(newNode, block, flags)
	if err != nil {
		return false, err
	}

	// Notify the caller that the new block was accepted into the block
	// chain.  The caller would typically want to react by relaying the
	// inventory to other peers.
	func() {
		b.chainLock.Unlock()
		defer b.chainLock.Lock()
		b.sendNotification(NTBlockAccepted, block)
	}()

	return isMainChain, nil
}
