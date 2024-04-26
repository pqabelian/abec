18/04/2024
# database
1. [`database/interface.go` StoreBlock & HasBlock](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/interface.go#L242)  
   
    ```go 
    type Tx interface {
        ...
        StoreBlock(block *abeutil.Block) error       
        StoreBlockAbe(block *abeutil.BlockAbe) error

        HasBlock(hash *chainhash.Hash) (bool, error)   
        HasBlockAbe(hash *chainhash.Hash) (bool, error) 
        ...
    }
    ```
   - Nowhere to use `StoreBlock` 
   
   - <details>
        <summary>Use `HasBlock` in </summary>

        - [`blockchain\chainio.go func dbStoreBlockAbe(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/chainio.go#L1943) dbTx.HasBlock or dbTx.HasBlockAbe?
  
            ```go
            // Abe to do
            func dbStoreBlockAbe(dbTx database.Tx,      block *abeutil.BlockAbe) error {
	            hasBlock, err := dbTx.HasBlock(block.Hash())
	            if err != nil {
		            return err
	            }
	            if hasBlock {
		            return nil
	            }
	            return dbTx.StoreBlockAbe(block)
            }
            ```
        -  [`blockchain\process.go func (b *BlockChain) blockExists(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/process.go#L47) dbTx.HasBlock or dbTx.HasBlockAbe?
            ```go
             func (b *BlockChain) blockExists(hash *chainhash.Hash) (bool, error) {
                ...
	            // Check in the database.
	            var exists bool
	            err := b.db.View(func(dbTx database.Tx) error {
		            var err error
		            exists, err = dbTx.HasBlock(hash)
		            if err != nil || !exists {
			            return err
		            }
                ...
	            return exists, err
            }
            ```
        -   [`database\cmd\dbtool\insecureimport.go func (bi *blockImporter) processBlock(serializedBlock []byte) (...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/cmd/dbtool/insecureimport.go#L124) tx.HasBlock or tx.HasBlockAbe?
            ```go
             func (bi *blockImporter) processBlock(serializedBlock []byte) (bool, error) {

	            block, err := abeutil.NewBlockFromBytesAbe(serializedBlock)
                ...

	            // Skip blocks that already exist.
	            var exists bool
	            err = bi.db.View(func(tx database.Tx) error {
		            exists, err = tx.HasBlock(block.Hash())
		            return err
	            })
                ...

	            // Don't bother trying to process orphans.
	            prevHash := &block.MsgBlock().Header.PrevBlock
	            if !prevHash.IsEqual(&zeroHash) {
		            var exists bool
		            err := bi.db.View(func(tx database.Tx) error {
			            exists, err = tx.HasBlock(prevHash)
			            return err
		            })
                    ...
	            }

	            // Put the blocks into the database with no checking of chain rules.
	            err = bi.db.Update(func(tx database.Tx) error {
		            //return tx.StoreBlock(block)
		            return tx.StoreBlockAbe(block)
	            })
                ...

	            return true, nil
            }
            ```
        </details>
1. [`database/ffldb/db.go func (tx *transaction) HasBlockAbe(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1320)  return tx.hasBlock not tx.[hasBlockAbe](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1166)?
    ```go 
    func (tx *transaction) HasBlockAbe(hash *chainhash.Hash) (bool, error) {
	    ...

	    return tx.hasBlock(hash), nil
    }
    ```
2. [`database/ffldb/db.go pendingBLocks & pendingBlockData`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L992)  
    ```go 
    type transaction struct {
        ...

	    // Blocks that need to be stored on commit.  The pendingBlocks map is
	    // kept to allow quick lookups of pending data by block hash.
	    pendingBlocks       map[chainhash.Hash]int
	    pendingBlockData    []pendingBlock
	    pendingBlocksAbe    map[chainhash.Hash]int
	    pendingBlockAbeData []pendingBlockAbe

        ...
    }
    ```
    - <details> 
        
        <summary>Use `pendingBLocks` in </summary>

        - [`database\ffldb\db.go func (tx *transaction) hasBlock(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1156) need to use hasBlock?
            ```go
            func (tx *transaction) hasBlock(hash *chainhash.Hash) bool {
	            // Return true if the block is pending to be written on commit since
	            // it exists from the viewpoint of this transaction.
	            if _, exists := tx.pendingBlocks[*hash]; exists {
		            return true
	            }

	            return tx.hasKey(bucketizedKey(blockIdxBucketID, hash[:]))
            }
            ```
            `hasBlock` is only used in [HasBlock](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1310) & [HasBlockAbe](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1320)

            ```go
            func (tx *transaction) HasBlock(hash *chainhash.Hash) (bool, error) {
                ...
	            return tx.hasBlock(hash), nil
            }

            // todo(ABE):
            func (tx *transaction) HasBlockAbe(hash *chainhash.Hash) (bool, error) {
                ...
                return tx.hasBlock(hash), nil
            }
            ``` 
        - [`database\ffldb\db.go func (tx *transaction) FetchBlock(...) & FetchBlockAbe(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1448) tx.pendingBlocks

            In FetchBlockAbe() should be tx.pendingBlocksAbe?
            ```go
            func (tx *transaction) FetchBlock(hash *chainhash.Hash) ([]byte, error) {

	            ...
                // When the block is pending to be written on commit return the bytes
	            // from there.
	            if idx, exists := tx.pendingBlocks[*hash]; exists {
		            return tx.pendingBlockData[idx].bytes, nil
	            }
                ...

	            return blockBytes, nil
            }
            func (tx *transaction) FetchBlockAbe(hash *chainhash.Hash) ([]byte, [][]byte, error) {
                ...
                // When the block is pending to be written on commit return the bytes
	            // from there.
	            if idx, exists := tx.pendingBlocks[*hash]; exists {
		            return tx.pendingBlockAbeData[idx].bytesNoWitness, tx.pendingBlockAbeData[idx].bytesWitness, nil
	            } 
                ...
                return blockBytes, witnesses, nil
            }

            ```
        - [`database\ffldb\db.go func (tx *transaction) FetchBlockWithoutWitness(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1523) tx.pendingBlocks or tx.pendingBlocksAbe?
            ```go
            func (tx *transaction) FetchBlockWithoutWitness(hash *chainhash.Hash) ([]byte, error) {

	            ...
                // When the block is pending to be written on commit return the bytes
	            // from there.
	            if idx, exists := tx.pendingBlocks[*hash]; exists {
		            return tx.pendingBlockAbeData[idx].bytesNoWitness, nil
	            }
                ...

	            return blockBytes, nil
            }
            ```
        </details>
    - <details>
  
        <summary>Use `pendingBLockData` in </summary>

        - [`database\ffldb\db.go func (tx *transaction) FetchBlock(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1448) need to use FetchBlock (see 4)?

            ```go
            func (tx *transaction) FetchBlock(hash *chainhash.Hash) ([]byte, error) {
                ...
	            if idx, exists := tx.pendingBlocks[*hash]; exists {
		            return tx.pendingBlockData[idx].bytes, nil
	            }
                ...
                return blockBytes, nil
            }
            ```

        - [`database\ffldb\db.go func (tx *transaction) writePendingAndCommit()`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1983) tx.pendingBlockData or tx.pendingBlockDataAbe?

            ```go
            func (tx *transaction) writePendingAndCommit() error {
                ...
	            // Loop through all of the pending blocks to store and write them.
	            for _, blockData := range tx.pendingBlockData {
                    ...
                }
                return tx.db.cache.commitTx(tx)
            }
            ```

    </details>
3. [`database/ffldb/db.go FetchBlock()`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1448)  need to use FetchBlock?
    ```go 
    func (tx *transaction) FetchBlock(hash *chainhash.Hash) ([]byte, error) {
	    // Ensure transaction state is valid.
	    if err := tx.checkClosed(); err != nil {
		    return nil, err
	    }

	    // When the block is pending to be written on commit return the bytes
	    // from there.
	    if idx, exists := tx.pendingBlocks[*hash]; exists {
		    return tx.pendingBlockData[idx].bytes, nil
	    }

	    // Lookup the location of the block in the files from the block index.
	    blockRow, err := tx.fetchBlockRow(hash)
	    if err != nil {
		    return nil, err
	    }
	    location := deserializeBlockLoc(blockRow)

	    // Read the block from the appropriate location.  The function also
	    // performs a checksum over the data to detect data corruption.
	    blockBytes, err := tx.db.store.readBlock(hash, location)
	    if err != nil {
		    return nil, err
	    }

	    return blockBytes, nil
    }
    ```

    <details>
    <summary>FetchBlock is used in</summary>

    - [`blockchain/indexers/manager.go func (m *Manager) Init(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/indexers/manager.go#L361C5-L361C45) dbTx.FetchBlock or dbTx.FetchBlockAbe?
        ```go
        func (m *Manager) Init(chain *blockchain.BlockChain, interrupt <-chan struct{}) error {
            // Rollback indexes to the main chain if their tip is an orphaned fork.
	        // This is fairly unlikely, but it can happen if the chain is
	        // reorganized while the index is disabled.  This has to be done in
	        // reverse order because later indexes can depend on earlier ones.
	        for i := len(m.enabledIndexes); i > 0; i-- {
                ...
                for !chain.MainChainHasBlock(hash) {
                    var block *abeutil.BlockAbe
			        err := m.db.View(func(dbTx database.Tx) error {
				        blockBytes, err := dbTx.FetchBlock(hash)
                        ...
                    }
                    ...
                }
                ...
            }
        ```
    - [`database/cmd/dbtool/fetchblock.go func (cmd *fetchBlockCmd) Execute(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/cmd/dbtool/fetchblock.go#L49) tx.FetchBlock or tx.FetchBlockAbe?
        ```go
        // Execute is the main entry point for the command.  It's invoked by the parser.
        func (cmd *fetchBlockCmd) Execute(args []string) error {
            ...
	        for i := len(m.enabledIndexes); i > 0; i-- {
                ...
                return db.View(func(tx database.Tx) error {
		            log.Infof("Fetching block %s", blockHash)
		            startTime := time.Now()
		            blockBytes, err := tx.FetchBlock(blockHash)
		            if err != nil {
			            return err
		            }
		            log.Infof("Loaded block in %v", time.Since(startTime))
		            log.Infof("Block Hex: %s", hex.EncodeToString(blockBytes))
		            return nil
	            })
            }
        ```
    - [`database/ffldb/db.go func (tx *transaction) FetchBlocks(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1570) need this function?
        ```go
        func (tx *transaction) FetchBlocks(hashes []chainhash.Hash) ([][]byte, error) {
	        // Ensure transaction state is valid.
	        if err := tx.checkClosed(); err != nil {
		        return nil, err
	        }

	        // NOTE: This could check for the existence of all blocks before loading
	        // any of them which would be faster in the failure case, however
	        // callers will not typically be calling this function with invalid
	        // values, so optimize for the common case.

	        // Load the blocks.
	        blocks := make([][]byte, len(hashes))
	        for i := range hashes {
		        var err error
		        blocks[i], err = tx.FetchBlock(&hashes[i])
		        if err != nil {
			    return nil, err
		        }
	        }

	        return blocks, nil
        }
        ```
    </details> 
4. [database/ffldb/reconcile.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/blockio.go#L1368) `func reconcileDB(...)` two errs, return which one?
    ```go
        // reconcileDB reconciles the metadata with the flat block files on disk.  It
        // will also initialize the underlying database if the create flag is set.
        func reconcileDB(pdb *db, nodeType wire.NodeType, create bool) (database.DB, error) {
            ...
            err = pdb.View(func(tx database.Tx) error {
                ...
                curFileNum, curOffset, err = deserializeWriteRow(writeRow)
                ...
                curWitnessFileNum, curWitnessOffset, err = deserializeWriteRow(writeRowForWitness)
		        return err
	        })
            ...
            return pdb, nil
        }
    ```

5. [database/ffldb/db.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/database/ffldb/db.go#L1983C1-L1983C55) `func (tx *transaction) writePendingAndCommit()` repeat for & pendingBlock struct pendingBlockAbe struct
   ```go
    func (tx *transaction) writePendingAndCommit() error {
        ...
        // Loop through all of the pending blocks to store and write them.
	    for _, blockData := range tx.pendingBlockData {
		    log.Tracef("Storing block %s", blockData.hash)
		    location, err := tx.db.store.writeBlock(blockData.bytes)//此处blockdata是pendingBlock类型
		    if err != nil {
			    rollback()
			    return err
		    }

		    // Add a record in the block index for the block.  The record
		    // includes the location information needed to locate the block
		    // on the filesystem as well as the block header since they are
		    // so commonly needed.
		    blockRow := serializeBlockLoc(location)
		    err = tx.blockIdxBucket.Put(blockData.hash[:], blockRow)
		    if err != nil {
			    rollback()
			    return err
		    }
	    }
        // Loop through all of the pending blocks to store and write them.
	    for _, blockData := range tx.pendingBlockAbeData {
		    log.Tracef("Storing block %s", blockData.hash)
		    location, err := tx.db.store.writeBlock(blockData.bytesNoWitness)//此处blockdata是pendingBlockAbe类型
		    if err != nil {
			    rollback()
			    return err
		    }

		    // Add a record in the block index for the block.  The record
		    // includes the location information needed to locate the block
		    // on the filesystem as well as the block header since they are
		    // so commonly needed.
		    blockRow := serializeBlockLoc(location)
		    err = tx.blockIdxBucket.Put(blockData.hash[:], blockRow)
		    if err != nil {
			    rollback()
			    return err
		    }//到此为止与上段for相同

		    // Write witnesses if exist.
		    if blockData.bytesWitness == nil {
			    continue
		    }
		    wLocation, err := tx.db.store.writeWitness(blockData.bytesWitness)
		    if err != nil {
			    rollback()
			    return err
		    }
		    witnessRow := serializeWitnessLoc(wLocation)
		    err = tx.witnessIdxBucket.Put(blockData.hash[:], witnessRow)
		    if err != nil {
			    rollback()
			    return err
		    }
	    }
   ```
# abeutil 

1. [abeutil/block.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/abeutil/block.go#L272) `func (b *Block) Transactions() []*Tx ` vs `func (b *BlockAbe) Transactions() []*TxAbe`
    
    `func (b *Block) Transactions()` is used in
  [blockchain/merkle.go `func ValidateWitnessCommitment(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/merkle.go#L409), but this function is not used
    ```go
    // ValidateWitnessCommitment validates the witness commitment (if any) found
    // within the coinbase transaction of the passed block.
    func ValidateWitnessCommitment(blk *abeutil.Block) error {
        if len(blk.Transactions()) == 0 {
		    ...
	    }
        coinbaseTx := blk.Transactions()[0]
        ...
        if !witnessFound {
		    for _, tx := range blk.Transactions() {
                ...
            }
        }
        ...
        witnessMerkleTree := BuildMerkleTreeStore(blk.Transactions(), true)
        ...
    }
    ```
	**After discussion:** delete
	
25/04/2024

2. [abeutil/block.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/abeutil/block.go#L29) `type Block struct` vs `type BlockAbe struct`.
   ```go
	type Block struct {
		msgBlock                 *wire.MsgBlock  // Underlying MsgBlock
		serializedBlock          []byte          // Serialized bytes for the block
		serializedBlockNoWitness []byte          // Serialized bytes for block w/o witness data
		blockHash                *chainhash.Hash // Cached block hash
		blockHeight              int32           // Height in the main block chain
		transactions             []*Tx           // Transactions
		txnsGenerated            bool            // ALL wrapped transactions generated
	}

	// Abe to do
	type BlockAbe struct {
		msgBlock                 *wire.MsgBlockAbe // Underlying MsgBlock
		serializedBlock          []byte            // Serialized bytes for the block
		serializedBlockNoWitness []byte            // Serialized bytes for block w/o witness data
		blockHash                *chainhash.Hash   // Cached block hash
		blockHeight              int32             // Height in the main block chain
		transactions             []*TxAbe          // Transactions
		txnsGenerated            bool              // ALL wrapped transactions generated
	}
   ```
    <details> 

	<summary> type Block struct is used in </summary>

  	- [abeutil/block.go `func (b *Block) MsgBlock() *wire.MsgBlock`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/abeutil/block.go#L82)

		```go
		// MsgBlock returns the underlying wire.MsgBlock for the Block.
		func (b *Block) MsgBlock() *wire.MsgBlock {
		// Return the cached block.
			return b.msgBlock
		}
		```
	- [abeutil/block.go `func (b *Block) Bytes() ([]byte, error)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/abeutil/block.go#L100)

		```go
		func (b *Block) Bytes() ([]byte, error) {
			// Return the cached serialized bytes if it has already been generated.
			if len(b.serializedBlock) != 0 {
				return b.serializedBlock, nil
			}

			// Serialize the MsgBlock.
			w := bytes.NewBuffer(make([]byte, 0, b.msgBlock.SerializeSize()))
			err := b.msgBlock.Serialize(w)
			if err != nil {
				return nil, err
			}
			serializedBlock := w.Bytes()

			// Cache the serialized bytes and return them.
			b.serializedBlock = serializedBlock
			return serializedBlock, nil
		}
		```
	- [blockchain/validate.go `func CheckProofOfWork(block *abeutil.Block, powLimit *big.Int)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/validate.go#L541)
		```go
		func CheckProofOfWork(block *abeutil.Block, powLimit *big.Int) error {
			return checkProofOfWork(&block.MsgBlock().Header, nil, powLimit, BFNone)
		}
		```
	- [rpcclient/mining.go `func (c *Client) SubmitBlockAsync(block *abeutil.Block,...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/rpcclient/mining.go#L444)
		```go
		func (c *Client) SubmitBlockAsync(block *abeutil.Block, options *abejson.SubmitBlockOptions) FutureSubmitBlockResult {
			blockHex := ""
			if block != nil {
				blockBytes, err := block.Bytes()
				if err != nil {
					return newFutureError(err)
				}

				blockHex = hex.EncodeToString(blockBytes)
			}

			cmd := abejson.NewSubmitBlockCmd(blockHex, options)
			return c.sendCmd(cmd)
		}
		```
	- [rpcclient/mining.go `func (c *Client) SubmitBlock(block *abeutil.Block, ...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/rpcclient/mining.go#L460)
		```go
		// SubmitBlock attempts to submit a new block into the bitcoin network.
		func (c *Client) SubmitBlock(block *abeutil.Block, options *abejson.SubmitBlockOptions) error {
			return c.SubmitBlockAsync(block, options).Receive()
		}
		```
	</details>

3. [abeutil/tx.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/abeutil/tx.go#L21) `type Tx struct` vs `type TxAbe struct`.
	```go
	type Tx struct {
		msgTx         *wire.MsgTx     // Underlying MsgTx
		txHash        *chainhash.Hash // Cached transaction hash
		txHashWitness *chainhash.Hash // Cached transaction witness hash
		txHasWitness  *bool           // If the transaction has witness data
		txIndex       int             // Position within a block or TxIndexUnknown
	}

	type TxAbe struct {
		msgTx         *wire.MsgTxAbe  // Underlying MsgTx
		txHash        *chainhash.Hash // Cached transaction content hash
		txWitnessHash *chainhash.Hash // Cached transaction witness hash
		//	txPersistentHash	*chainhash.Hash // Cached transaction witness hash
		//	txHasTxoDetails *bool // if the transaction has txo details
		txHasWitness *bool // If the transaction has witness data
		txIndex      int   // Position within a block or TxIndexUnknown
	}
	```

# blockchain
1. [blockchain/validate.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/validate.go#L119) `func IsCoinBase(tx *abeutil.Tx) bool` vs `func IsCoinBaseAbe(tx *abeutil.TxAbe) bool` 
   ```go
	func IsCoinBase(tx *abeutil.Tx) bool {
		return IsCoinBaseTx(tx.MsgTx())
	}

	func IsCoinBaseAbe(tx *abeutil.TxAbe) (bool, error) {
		return tx.MsgTx().IsCoinBase()
	}
   ```
   	
	<details>
	<summary>`func IsCoinBase(tx *abeutil.Tx) bool` is used in</summary>

	- [blockchain/chain.go `func (b *BlockChain) calcSequenceLock(...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/chain.go#L396)
		```go
		func (b *BlockChain) calcSequenceLock(node *blockNode, tx *abeutil.Tx, utxoView *UtxoViewpoint, mempool bool) (*SequenceLock, error) {
			...
			mTx := tx.MsgTx()
			sequenceLockActive := mTx.Version >= 2 && csvSoftforkActive
			if !sequenceLockActive || IsCoinBase(tx) {
				return sequenceLock, nil
			}
			...
		}
		```
	- [blockchain/merkle.go `func ExtractWitnessCommitment(tx *abeutil.Tx)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/merkle.go#L348)
		```go
		func ExtractWitnessCommitment(tx *abeutil.Tx) ([]byte, bool) {
			// The witness commitment *must* be located within one of the coinbase
			// transaction's outputs.
			if !IsCoinBase(tx) {
				return nil, false
			}
			...
		}
		```
	- [blockchain/utxoviewpoint.go `func (view *UtxoViewpoint) AddTxOut(tx *abeutil.Tx,...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/utxoviewpoint.go#L190)
		```go
		func (view *UtxoViewpoint) AddTxOut(tx *abeutil.Tx, txOutIdx uint32, blockHeight int32) {
			...
			view.addTxOut(prevOut, txOut, IsCoinBase(tx), blockHeight)
		}
		```
	- [blockchain/utxoviewpoint.go `func (view *UtxoViewpoint) AddTxOuts(tx *abeutil.Tx,...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/utxoviewpoint.go#L209)
		```go
		func (view *UtxoViewpoint) AddTxOuts(tx *abeutil.Tx, blockHeight int32) {
			// Loop all of the transaction outputs and add those which are not
			// provably unspendable.
			isCoinBase := IsCoinBase(tx)
			...
		}
		```
	- [blockchain/utxoviewpoint.go `func (b *BlockChain) FetchUtxoView(tx *abeutil.Tx)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/blockchain/utxoviewpoint.go#L605)
		```go
		func (b *BlockChain) FetchUtxoView(tx *abeutil.Tx) (*UtxoViewpoint, error) {
			...
			if !IsCoinBase(tx) {
				for _, txIn := range tx.MsgTx().TxIn {
					neededSet[txIn.PreviousOutPoint] = struct{}{}
				}
			}
			...
		}
		```

# mining
1. [mining/minging.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mining/mining.go#L36) `type TxDesc struct` vs `type TxDescAbe struct` 
   ```go
	type TxDesc struct {
		// Tx is the transaction associated with the entry.
		Tx *abeutil.Tx

		// Added is the time when the entry was added to the source pool.
		Added time.Time

		// Height is the block height when the entry was added to the the source
		// pool.
		Height int32

		// Fee is the total fee the transaction associated with the entry pays.
		Fee int64

		// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
		FeePerKB int64
	}

	type TxDescAbe struct {
		// Tx is the transaction associated with the entry.
		Tx *abeutil.TxAbe

		// Added is the time when the entry was added to the source pool.
		Added time.Time

		// Height is the block height when the entry was added to the source
		// pool.
		Height int32

		// Fee is the total fee the transaction associated with the entry pays.
		Fee uint64

		// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
		FeePerKB uint64
	}
   ```

   `type TxDesc struct` is used in
   - [mempool/mempool.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L164) `type TxDesc struct` (`type TxDesc struct` vs `type TxDescAbe struct`?)
		```go
		type TxDesc struct {
			mining.TxDesc

			// StartingPriority is the priority of the transaction when it was added
			// to the pool.
			StartingPriority float64
		}	

		type TxDescAbe struct {
			mining.TxDescAbe

			// StartingPriority is the priority of the transaction when it was added
			// to the pool.
			StartingPriority float64
		}
		```
		mempool `type TxDesc struct` is used in

		- [mempool/mempool.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L198) `type TxPool struct`
  
			```go
			type TxPool struct {
				// The following variables must only be used atomically.
				lastUpdated int64 // last time pool was updated

				mtx           sync.RWMutex
				cfg           Config
				pool          map[chainhash.Hash]*TxDesc //	Abe todo: [txHash]TxDsec, the txs in pool, keyed by tx's hash
				orphans       map[chainhash.Hash]*orphanTx
				orphansByPrev map[wire.OutPoint]map[chainhash.Hash]*abeutil.Tx
				outpoints     map[wire.OutPoint]*abeutil.Tx //	Abe todo: [outPoint]Tx, outPoint is one of the TxIn of Tx
				pennyTotal    float64                       // exponentially decaying total for penny spends.
				lastPennyUnix int64                         // unix time of last ``penny spend''

				// nextExpireScan is the time after which the orphan pool will be
				// scanned in order to evict orphans.  This is NOT a hard deadline as
				// the scan will only run when an orphan is added to the pool as opposed
				// to on an unconditional timer.
				nextExpireScan time.Time

				//	todo(ABE):	begin
				poolAbe          map[chainhash.Hash]*TxDescAbe
				diskPool         map[chainhash.Hash]struct{}
				orphansAbe       map[chainhash.Hash]*orphanTxAbe
				outpointsAbe     map[chainhash.Hash]map[string]*abeutil.TxAbe                    //TODO(abe):why use two layers map                 //	corresponding to btc's outpoints, using hash rather then TxIn as the key for map
				orphansByPrevAbe map[chainhash.Hash]map[string]map[chainhash.Hash]*abeutil.TxAbe // corresponding to btc's orphansByPrev //TODO type transfer??? []byte -> string

				txMonitorMu  sync.Mutex
				txMonitoring bool
			}
			```
			**Note:** there are Abe fields and sans Abe fields
		- [mempool/mempool.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L2166) `func New(cfg *Config) *TxPool`
  
			```go
			func New(cfg *Config) *TxPool {
				return &TxPool{
					cfg:            *cfg,
					pool:           make(map[chainhash.Hash]*TxDesc),
					...
					outpoints:      make(map[wire.OutPoint]*abeutil.Tx),

					poolAbe:          make(map[chainhash.Hash]*TxDescAbe),
					...	
				}
			}
			```

# mempool
1. [mempool/mempool.go](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L164) `type TxDesc struct` vs `type TxDescAbe struct` and `type orphanTx struct` vs `type orphanTxAbe struct`
   ```go
	type orphanTx struct {
		tx         *abeutil.Tx
		tag        Tag
		expiration time.Time
	}

	type orphanTxAbe struct {
		tx         *abeutil.TxAbe
		tag        Tag
		expiration time.Time
	}
   ```
2. [mempool/mempool.go `func (mp *TxPool) removeOrphan(tx *abeutil.Tx, ...)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L235) vs `func (mp *TxPool) removeOrphanAbe(tx *abeutil.TxAbe)`?
   ```go
	func (mp *TxPool) removeOrphan(tx *abeutil.Tx, removeRedeemers bool) {
		// Nothing to do if passed tx is not an orphan.
		txHash := tx.Hash()
		otx, exists := mp.orphans[*txHash]
		if !exists {
			return
		}

		// Remove the reference from the previous orphan index.
		for _, txIn := range otx.tx.MsgTx().TxIn {
			orphans, exists := mp.orphansByPrev[txIn.PreviousOutPoint]
			if exists {
				delete(orphans, *txHash)

				// Remove the map entry altogether if there are no
				// longer any orphans which depend on it.
				if len(orphans) == 0 {
					delete(mp.orphansByPrev, txIn.PreviousOutPoint)
				}
			}
		}

		// Remove any orphans that redeem outputs from this one if requested.
		if removeRedeemers {
			prevOut := wire.OutPoint{Hash: *txHash}
			for txOutIdx := range tx.MsgTx().TxOut {
				prevOut.Index = uint32(txOutIdx)
				for _, orphan := range mp.orphansByPrev[prevOut] {
					mp.removeOrphan(orphan, true)
				}
			}
		}

		// Remove the transaction from the orphan pool.
		delete(mp.orphans, *txHash)
	}
   ```
	is used in
	- [mempool/mempool.go `func (mp *TxPool) RemoveOrphansByTag(tag Tag)`](https://github.com/JingnanHe/abec-cleancode/blob/main/abec/mempool/mempool.go#L164) uses `removeOrphan` not `removeOrphanAbe`
		```go
		func (mp *TxPool) RemoveOrphansByTag(tag Tag) uint64 {
			var numEvicted uint64
			mp.mtx.Lock()
			for _, otx := range mp.orphans {
				if otx.tag == tag {
					mp.removeOrphan(otx.tx, true)
					numEvicted++
				}
			}
			mp.mtx.Unlock()
			return numEvicted
		}
		```

