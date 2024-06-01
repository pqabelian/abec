18/04/2024
# database
1. [`database/interface.go` StoreBlock & HasBlock](https://github.com/pqabelian/abec/blob/main/database/interface.go#L242)  
   
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

        - [`blockchain\chainio.go func dbStoreBlockAbe(...)`](https://github.com/pqabelian/abec/blob/main/blockchain/chainio.go#L1943) dbTx.HasBlock or dbTx.HasBlockAbe?
  
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
        -  [`blockchain\process.go func (b *BlockChain) blockExists(...)`](https://github.com/pqabelian/abec/blob/main/blockchain/process.go#L47) dbTx.HasBlock or dbTx.HasBlockAbe?
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
        -   [`database\cmd\dbtool\insecureimport.go func (bi *blockImporter) processBlock(serializedBlock []byte) (...)`](https://github.com/pqabelian/abec/blob/main/database/cmd/dbtool/insecureimport.go#L124) tx.HasBlock or tx.HasBlockAbe?
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
1. [`database/ffldb/db.go func (tx *transaction) HasBlockAbe(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1320)  return tx.hasBlock not tx.[hasBlockAbe](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1166)?
    ```go 
    func (tx *transaction) HasBlockAbe(hash *chainhash.Hash) (bool, error) {
	    ...

	    return tx.hasBlock(hash), nil
    }
    ```
2. [`database/ffldb/db.go pendingBLocks & pendingBlockData`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L992)  
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

        - [`database\ffldb\db.go func (tx *transaction) hasBlock(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1156) need to use hasBlock?
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
            `hasBlock` is only used in [HasBlock](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1310) & [HasBlockAbe](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1320)

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
        - [`database\ffldb\db.go func (tx *transaction) FetchBlock(...) & FetchBlockAbe(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1448) tx.pendingBlocks

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
        - [`database\ffldb\db.go func (tx *transaction) FetchBlockWithoutWitness(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1523) tx.pendingBlocks or tx.pendingBlocksAbe?
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

        - [`database\ffldb\db.go func (tx *transaction) FetchBlock(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1448) need to use FetchBlock (see 4)?

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

        - [`database\ffldb\db.go func (tx *transaction) writePendingAndCommit()`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1983) tx.pendingBlockData or tx.pendingBlockDataAbe?

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
3. [`database/ffldb/db.go FetchBlock()`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1448)  need to use FetchBlock?
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

    - [`blockchain/indexers/manager.go func (m *Manager) Init(...)`](https://github.com/pqabelian/abec/blob/main/blockchain/indexers/manager.go#L361C5-L361C45) dbTx.FetchBlock or dbTx.FetchBlockAbe?
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
    - [`database/cmd/dbtool/fetchblock.go func (cmd *fetchBlockCmd) Execute(...)`](https://github.com/pqabelian/abec/blob/main/database/cmd/dbtool/fetchblock.go#L49) tx.FetchBlock or tx.FetchBlockAbe?
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
    - [`database/ffldb/db.go func (tx *transaction) FetchBlocks(...)`](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1570) need this function?
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
4. [database/ffldb/reconcile.go](https://github.com/pqabelian/abec/blob/main/database/ffldb/blockio.go#L1368) `func reconcileDB(...)` two errs, return which one?
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

5. [database/ffldb/db.go](https://github.com/pqabelian/abec/blob/main/database/ffldb/db.go#L1983C1-L1983C55) `func (tx *transaction) writePendingAndCommit()` repeat for & pendingBlock struct pendingBlockAbe struct
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

1. [abeutil/block.go](https://github.com/pqabelian/abec/blob/main/abeutil/block.go#L272) `func (b *Block) Transactions() []*Tx ` vs `func (b *BlockAbe) Transactions() []*TxAbe`
    
    `func (b *Block) Transactions()` is used in
  [blockchain/merkle.go `func ValidateWitnessCommitment(...)`](https://github.com/pqabelian/abec/blob/main/blockchain/merkle.go#L409), but this function is not used
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

2. [abeutil/block.go](https://github.com/pqabelian/abec/blob/main/abeutil/block.go#L29) `type Block struct` vs `type BlockAbe struct`.
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

  	- [abeutil/block.go `func (b *Block) MsgBlock() *wire.MsgBlock`](https://github.com/pqabelian/abec/blob/main/abeutil/block.go#L82)

		```go
		// MsgBlock returns the underlying wire.MsgBlock for the Block.
		func (b *Block) MsgBlock() *wire.MsgBlock {
		// Return the cached block.
			return b.msgBlock
		}
		```
	- [abeutil/block.go `func (b *Block) Bytes() ([]byte, error)`](https://github.com/pqabelian/abec/blob/main/abeutil/block.go#L100)

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
	- [blockchain/validate.go `func CheckProofOfWork(block *abeutil.Block, powLimit *big.Int)`](https://github.com/pqabelian/abec/blob/main/blockchain/validate.go#L541)
		```go
		func CheckProofOfWork(block *abeutil.Block, powLimit *big.Int) error {
			return checkProofOfWork(&block.MsgBlock().Header, nil, powLimit, BFNone)
		}
		```
	- [rpcclient/mining.go `func (c *Client) SubmitBlockAsync(block *abeutil.Block,...)`](https://github.com/pqabelian/abec/blob/main/rpcclient/mining.go#L444)
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
	- [rpcclient/mining.go `func (c *Client) SubmitBlock(block *abeutil.Block, ...)`](https://github.com/pqabelian/abec/blob/main/rpcclient/mining.go#L460)
		```go
		// SubmitBlock attempts to submit a new block into the bitcoin network.
		func (c *Client) SubmitBlock(block *abeutil.Block, options *abejson.SubmitBlockOptions) error {
			return c.SubmitBlockAsync(block, options).Receive()
		}
		```
	</details>

3. [abeutil/tx.go](https://github.com/pqabelian/abec/blob/main/abeutil/tx.go#L21) `type Tx struct` vs `type TxAbe struct`.
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
1. [blockchain/validate.go](https://github.com/pqabelian/abec/blob/main/blockchain/validate.go#L119) `func IsCoinBase(tx *abeutil.Tx) bool` vs `func IsCoinBaseAbe(tx *abeutil.TxAbe) bool` 
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

	- [blockchain/chain.go `func (b *BlockChain) calcSequenceLock(...)`](https://github.com/pqabelian/abec/blob/main/blockchain/chain.go#L396)
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
	- [blockchain/merkle.go `func ExtractWitnessCommitment(tx *abeutil.Tx)`](https://github.com/pqabelian/abec/blob/main/blockchain/merkle.go#L348)
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
	- [blockchain/utxoviewpoint.go `func (view *UtxoViewpoint) AddTxOut(tx *abeutil.Tx,...)`](https://github.com/pqabelian/abec/blob/main/blockchain/utxoviewpoint.go#L190)
		```go
		func (view *UtxoViewpoint) AddTxOut(tx *abeutil.Tx, txOutIdx uint32, blockHeight int32) {
			...
			view.addTxOut(prevOut, txOut, IsCoinBase(tx), blockHeight)
		}
		```
	- [blockchain/utxoviewpoint.go `func (view *UtxoViewpoint) AddTxOuts(tx *abeutil.Tx,...)`](https://github.com/pqabelian/abec/blob/main/blockchain/utxoviewpoint.go#L209)
		```go
		func (view *UtxoViewpoint) AddTxOuts(tx *abeutil.Tx, blockHeight int32) {
			// Loop all of the transaction outputs and add those which are not
			// provably unspendable.
			isCoinBase := IsCoinBase(tx)
			...
		}
		```
	- [blockchain/utxoviewpoint.go `func (b *BlockChain) FetchUtxoView(tx *abeutil.Tx)`](https://github.com/pqabelian/abec/blob/main/blockchain/utxoviewpoint.go#L605)
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
1. [mining/minging.go](https://github.com/pqabelian/abec/blob/main/mining/mining.go#L36) `type TxDesc struct` vs `type TxDescAbe struct` 
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
   - [mempool/mempool.go](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L164) `type TxDesc struct` (`type TxDesc struct` vs `type TxDescAbe struct`?)
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

		- [mempool/mempool.go](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L198) `type TxPool struct`
  
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
		- [mempool/mempool.go](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L2166) `func New(cfg *Config) *TxPool`
  
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
1. [mempool/mempool.go](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L164) `type TxDesc struct` vs `type TxDescAbe struct` and `type orphanTx struct` vs `type orphanTxAbe struct`
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
2. [mempool/mempool.go `func (mp *TxPool) removeOrphan(tx *abeutil.Tx, ...)`](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L235) vs `func (mp *TxPool) removeOrphanAbe(tx *abeutil.TxAbe)`?
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
	- [mempool/mempool.go `func (mp *TxPool) RemoveOrphansByTag(tag Tag)`](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L164) uses `removeOrphan` not `removeOrphanAbe`
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

02/05/2024
# wire
1. [wire/msgblock.go](https://github.com/pqabelian/abec/blob/main/wire/msgblock.go#L18) severl pairs sans Abe vs with Abe
   ```go
	const defaultTransactionAlloc = 2048
	const defaultTransactionAllocAbe = 2048

	// MaxBlocksPerMsg is the maximum number of blocks allowed per message.
	const MaxBlocksPerMsg = 500
	const MaxBlocksPerMsgAbe = 500

	// MaxBlockPayload is the maximum bytes a block message can be in bytes.
	// After Segregated Witness, the max block payload has been raised to 4MB.
	const MaxBlockPayload = 4000000

	// MaxBlockPayloadAbe is the maximum bytes a block message can be in bytes.
	// todo: The max block payload in abe is 8MB. However, it seems that there is bug in transaction
	// serialization currently. Hence, the MaxBlockPayload is temporarily  set as 800MB.
	const MaxBlockPayloadAbe = 800000000

	// maxTxPerBlock is the maximum number of transactions that could
	// possibly fit into a block.
	const maxTxPerBlock = (MaxBlockPayload / minTxPayload) + 1
	const maxTxPerBlockAbe = (MaxBlockPayloadAbe / TxPayloadMinSize) + 1

	// TxLoc holds locator data for the offset and length of where a transaction is
	// located within a MsgBlock data buffer.
	type TxLoc struct {
		TxStart int
		TxLen   int
	}
	type TxAbeLoc struct {
		TxStart      int
		TxLen        int
		WitnessStart int
		WitnessLen   int
	}

	// MsgBlock implements the Message interface and represents an abe
	// block message.  It is used to deliver block and transaction information in
	// response to a getdata message (MsgGetData) for a given block hash.
	type MsgBlock struct {
		Header       BlockHeader
		Transactions []*MsgTx
	}

	// MsgBlockAbe implements the Message interface and represents an abe
	// block message.  It is used to deliver block and transaction information in
	// response to a getdata message (MsgGetData) for a given block hash.
	type MsgBlockAbe struct {
		Header       BlockHeader
		Transactions []*MsgTxAbe
		WitnessHashs []*chainhash.Hash
	}
   ```
   - `defaultTransactionAlloc` is used in 
  
     	- [wire/msgprunedblock.go](https://github.com/pqabelian/abec/blob/main/wire/msgprunedblock.go#L174) `func NewMsgBlockPrunedFromMsgBlockAbe(block *MsgBlockAbe)` change to defaultTransactionAllocAbe?
			```go
			func NewMsgBlockPrunedFromMsgBlockAbe(block *MsgBlockAbe) (*MsgPrunedBlock, error) {
			res := &MsgPrunedBlock{
					Header:            block.Header,
					CoinbaseTx:        block.Transactions[0],
					TransactionHashes: make([]chainhash.Hash, 0, defaultTransactionAlloc),
					WitnessHashs:      make([]chainhash.Hash, 0, defaultTransactionAlloc),
				}
				...
			}
			```
		- used in & deleted [wire/msgblock.go](https://github.com/pqabelian/abec/blob/main/wire/msgblock.go#L698) `func NewMsgBlock(blockHeader *BlockHeader) *MsgBlock`
		- used in & deleted [wire/msgblock.go](https://github.com/pqabelian/abec/blob/main/wire/msgblock.go#L96) `func (msg *MsgBlockAbe) ClearTransactions() `
   - `MaxBlocksPerMsg` is used in // ?? `MaxBlocksPerMsgAbe` is not in use
     - [server.go](https://github.com/pqabelian/abec/blob/main/server.go#L724) `func (sp *serverPeer) OnGetBlocks(_ *peer.Peer, msg *wire.MsgGetBlocks)`
		```go
		func (sp *serverPeer) OnGetBlocks(_ *peer.Peer, msg 	*wire.MsgGetBlocks) {
			hashList, heights := chain.LocateBlocks(msg.BlockLocatorHashes, &msg.HashStop,
		wire.MaxBlocksPerMsg) // from the start node to hash stop node or max blockhash
			...
			// Send the inventory message if there is anything to send.
			if len(invMsg.InvList) > 0 {
				invListLen := len(invMsg.InvList)
				if invListLen == wire.MaxBlocksPerMsg {
					// Intentionally use a copy of the final hash so there
					// is not a reference into the inventory slice which
					// would prevent the entire slice from being eligible
					// for GC as soon as it's sent.
					continueHash := invMsg.InvList[invListLen-1].Hash
					sp.continueHash = &continueHash // the last one hash in the inv message
				}
				sp.QueueMessage(invMsg, nil)
			}
		}
		```
      	where OnGetBlocks is used in [server.go](https://github.com/pqabelian/abec/blob/main/server.go#L1803) `func newPeerConfig(sp *serverPeer) *peer.Config` didn't use OnGetBlocks? or change to MaxBlocksPerMsgAbe?
		```go
		func newPeerConfig(sp *serverPeer) *peer.Config {
			return &peer.Config{
				...
				OnGetBlocks:     sp.OnGetBlocks,
				...
			}
			...
		}
		```
	- `MaxBlockPayload = 4000000` and `MaxBlockPayloadAbe = 800000000` are different, s.t. `maxTxPerBlock` and `maxTxPerBlockAbe` are different
	- deleted `type TxLoc struct`
	- `MsgBlock` used in
		- [mining/mining.go](https://github.com/pqabelian/abec/blob/main/mining/mining.go#L198) deleted this field
			```go
			type BlockTemplate struct {
				// Block is a block that is ready to be solved by miners.  Thus, it is
				// completely valid with the exception of satisfying the proof-of-work
				// requirement.
				Block    *wire.MsgBlock
				BlockAbe *wire.MsgBlockAbe
				...
			}
			```
			which is used in [rpcserver.go](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L2064) change to BlockAbe?
			```go
				func (state *gbtWorkState) updateBlockTemplate(s *rpcServer, useCoinbaseValue bool, useOwnAddr bool, miningAddr []byte) error {
					...
					template.Block.Header.MerkleRoot = *merkles[len(merkles)-1]
				}
			```
		- [peer/log.go](https://github.com/pqabelian/abec/blob/main/peer/log.go#L159) `func messageSummary(msg wire.Message)` has Abe case, so delete it?
			```go
			// messageSummary returns a human-readable string which summarizes a message.
			// Not all messages have or need a summary.  This is used for debug logging.
			func messageSummary(msg wire.Message) string {
				switch msg := msg.(type) {
					case *wire.MsgBlock:
						header := &msg.Header
						return fmt.Sprintf("hash %s, ver %d, %d tx, %s", msg.BlockHash(),
						header.Version, len(msg.Transactions), header.Timestamp)

					case *wire.MsgBlockAbe:
						header := &msg.Header
						return fmt.Sprintf("hash %s, ver %d, %d tx, %s", msg.BlockHash(),
						header.Version, len(msg.Transactions), header.Timestamp)

					...
				}
				...
			}
			```
		- [rpcclient/chain.go](https://github.com/pqabelian/abec/blob/main/rpcclient/chain.go#L138) `func (r FutureGetBlockResult) Receive() (*wire.MsgBlock, error)` 
			```go
			func (r FutureGetBlockResult) Receive() (*wire.MsgBlock, error) {
				...
				// Deserialize the block and return it.
				var msgBlock wire.MsgBlock
				...
			}
			```
			here is another [Receive](https://github.com/pqabelian/abec/blob/main/rpcclient/chain.go#L199) for Abe
			```go
			func (r FutureGetBlockAbeResult) Receive() (*wire.MsgBlockAbe, error) {
				res, err := r.client.waitForGetBlockAbeRes(r.Response, r.hash, false, false)
				if err != nil {
					return nil, err
				}
				...
			}
			```

# Others
1. [rpcserverhelp.go](https://github.com/pqabelian/abec/blob/main/rpcserverhelp.go#L690)
   ```go
	var rpcResultTypes = map[string][]interface{}{
		...
		"getblock":              {(*string)(nil), (*abejson.GetBlockAbeVerboseResult)(nil)},
		"getblockabe":           {(*string)(nil), (*abejson.GetBlockAbeVerboseResult)(nil)}, //TODO(abe):after testing, this command will be replace by getblock
	
		...
	}
   ```
12/05/2024
# rpcclient
1. [rpcclient/notify.go `type NotificationHandlers struct`](https://github.com/pqabelian/abec/blob/main/rpcclient/notify.go#L83) OnBlockConnected  vs OnBlockAbeConnected, OnBlockDisconnected vs OnBlockAbeDisconnected
   ```go
	type NotificationHandlers struct {
		// OnBlockConnected is invoked when a block is connected to the longest
		// (best) chain.  It will only be invoked if a preceding call to
		// NotifyBlocks has been made to register for the notification and the
		// function is non-nil.
		//
		// Deprecated: Use OnFilteredBlockConnected instead.
		OnBlockConnected    func(hash *chainhash.Hash, height int32, t time.Time)
		OnBlockAbeConnected func(hash *chainhash.Hash, height int32, t time.Time)
		//	todo(ABE): ABE does not support filter.
		// OnFilteredBlockConnected is invoked when a block is connected to the
		...

		// OnBlockDisconnected is invoked when a block is disconnected from the
		// longest (best) chain.  It will only be invoked if a preceding call to
		// NotifyBlocks has been made to register for the notification and the
		// function is non-nil.
		//
		// Deprecated: Use OnFilteredBlockDisconnected instead.
		OnBlockDisconnected    func(hash *chainhash.Hash, height int32, t time.Time)
		OnBlockAbeDisconnected func(hash *chainhash.Hash, height int32, t time.Time)
		//	todo(ABE): ABE does not support filter.
		// OnFilteredBlockDisconnected is invoked when a block is disconnected
		...
	}
   ```
	- OnBlockConnected // Deprecated: Use OnFilteredBlockConnected instead. & ABE does not support filter. OnBlockDisconnected is same. So just keep the Abe version?
	- OnBlockConnected is used in 
		[rpcclient/notify.go `func (c *Client) handleNotification(ntfn *rawNotification)`](https://github.com/pqabelian/abec/blob/main/rpcclient/notify.go#L213)
		```go
		func (c *Client) handleNotification(ntfn *rawNotification) {
			// Ignore the notification if the client is not interested in any
			// notifications.
			if c.ntfnHandlers == nil {
				return
			}

			switch ntfn.Method {
			// OnBlockConnected
			//Note: abejson.BlockConnectedNtfnMethod is deprecated: Use FilteredBlockConnectedNtfnMethod instead.deprecateddefault
			case abejson.BlockConnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockConnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
				if err != nil {
					log.Warnf("Received invalid block connected "+
					"notification: %v", err)
					return
				}

				c.ntfnHandlers.OnBlockConnected(blockHash, blockHeight, blockTime)
			case abejson.BlockAbeConnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockAbeConnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
				if err != nil {
					log.Warnf("Received invalid block connected "+
					"notification: %v", err)
					return
				}

				c.ntfnHandlers.OnBlockAbeConnected(blockHash, blockHeight, blockTime)

			//	todo(ABE): ABE does not support filter.
			// OnFilteredBlockConnected
			//case abejson.FilteredBlockConnectedNtfnMethod:
			...
			}
			...
		}
		```
2. [rpcclient/wallet.go `type FutureSendToAddressResult chan *response`](https://github.com/pqabelian/abec/blob/main/rpcclient/wallet.go#L486) FutureSendToAddressResult vs FutureSendToAddressAbeResult
   ```go
	// FutureSendToAddressResult is a future promise to deliver the result of a
	// SendToAddressAsync RPC invocation (or an applicable error).
	type FutureSendToAddressResult chan *response
	type FutureSendToAddressAbeResult chan *response
   ```
	- FutureSendToAddressResult is used in
		```go
		func (c *Client) SendToAddressCommentAsync(address abeutil.Address,
		amount abeutil.Amount, comment,
		commentTo string) FutureSendToAddressResult {

			addr := address.EncodeAddress()
			cmd := abejson.NewSendToAddressCmd(addr, amount.ToABE(), &comment,
				&commentTo)				
			return c.sendCmd(cmd)
		}

		func (c *Client) SendToAddressComment(address abeutil.Address, amount abeutil.Amount, comment, commentTo string) (*chainhash.Hash, error) {
			return c.SendToAddressCommentAsync(address, amount, comment,
			commentTo).Receive()
		}
		```
# peer
1. [peer/log.go](https://github.com/pqabelian/abec/blob/main/peer/log.go#L187) wire.MsgTx is in msgtx.go which is replaced by msgtxabe.go, so delete this section?
   ```go
	func messageSummary(msg wire.Message) string {
		...
		case *wire.MsgTx:
			return fmt.Sprintf("hash %s, %d inputs, %d outputs, lock %s",
			msg.TxHash(), len(msg.TxIn), len(msg.TxOut),
			formatLockTime(msg.LockTime))

		case *wire.MsgTxAbe:
			return fmt.Sprintf("hash %s, %d inputs, %d outputs",
			msg.TxHash(), len(msg.TxIns), len(msg.TxOuts))
		...
	}
   ```
# mempool
1. [mempool/mempool.go `TxPool.pool` vs `TxPool.poolAbe`](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L198) discussed before. Can we change the use of pool to poolAbe?
   ```go
	// TxPool is used as a source of transactions that need to be mined into blocks
	// and relayed to other peers.  It is safe for concurrent access from multiple
	// peers.
	type TxPool struct {
		// The following variables must only be used atomically.
		lastUpdated int64 // last time pool was updated

		mtx sync.RWMutex
		cfg Config
		/*pool          map[chainhash.Hash]*TxDesc //	Abe todo: [txHash]TxDsec, the txs in pool, keyed by tx's hash
		orphans       map[chainhash.Hash]*orphanTx
		orphansByPrev map[wire.OutPoint]map[chainhash.Hash]*abeutil.Tx
		outpoints     map[wire.OutPoint]*abeutil.Tx //	Abe todo: [outPoint]Tx, outPoint is one of the TxIn of Tx
		*/
		pennyTotal    float64 // exponentially decaying total for penny spends.
		lastPennyUnix int64   // unix time of last ``penny spend''

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
   - pool is used in mempool.go [`func (mp *TxPool) Count`](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L1997) [`func (mp *TxPool) TxHashes() []*chainhash.Hash`](https://github.com/pqabelian/abec/blob/main/mempool/mempool.go#L2009) 
	```go
	// Count returns the number of transactions in the main pool.  It does not
	// include the orphan pool.
	//
	// This function is safe for concurrent access.
	func (mp *TxPool) Count() int {
		mp.mtx.RLock()
		count := len(mp.pool) + len(mp.diskPool)
		mp.mtx.RUnlock()

		return count
	}

	// TxHashes returns a slice of hashes for all of the transactions in the memory
	// pool.
	//
	// This function is safe for concurrent access.
	func (mp *TxPool) TxHashes() []*chainhash.Hash {
		mp.mtx.RLock()
		hashes := make([]*chainhash.Hash, len(mp.pool)+len(mp.diskPool))
		i := 0
		for hash := range mp.pool {
			hashCopy := hash
			hashes[i] = &hashCopy
			i++
		}
		...

		return hashes
	}
	```
# blockchain
1. [blockchain/validate.go `func IsFinalizedTransactionAbe(tx *abeutil.TxAbe, blockHeight int32, blockTime time.Time)`](https://github.com/pqabelian/abec/blob/main/blockchain/validate.go#L179) isn't used?
	```go
	// IsFinalizedTransaction determines whether or not a transaction is finalized.
	func IsFinalizedTransactionAbe(tx *abeutil.TxAbe, blockHeight int32, blockTime time.Time) bool {
		return true
	}
	```
# abeutil
1. [abeutil/address.go `type AddressAbe interface`](https://github.com/pqabelian/abec/blob/main/abeutil/address.go#L154) AddressAbe is not used? deleted
   ```go
	type Address interface{
		String() string
		EncodeAddress() string
		ScriptAddress() []byte
		IsForNet(*chaincfg.Params) bool
	}
	type AddressAbe interface{
		String() string
		EncodeAddress() string
		IsForNet(*chaincfg.Params) bool
	}
   ```

2. [abeutil/amount.go `func NewAmountAbe(f float64)`](https://github.com/pqabelian/abec/blob/main/abeutil/amount.go#L91) isn't used? deleted
	```go
	func NewAmountAbe(f float64) (Amount, error) {
		// The amount is only considered invalid if it cannot be represented
		// as an integer type.  This may happen if f is NaN or +-Infinity.
		switch {
		case math.IsNaN(f):
			fallthrough
		case math.IsInf(f, 1):
			fallthrough
		case math.IsInf(f, -1):
			return 0, errors.New("invalid ABE amount")
		}

		return round(f), nil
	}
	```

# abejson
1. [abejson/chainsvrcmds.go `type CreateRawTransactionCmd struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L79) CreateRawTransactionCmd vs CreateRawTransactionCmdAbe
   ```go
	// CreateRawTransactionCmd defines the createrawtransaction JSON-RPC command.
	//
	//	todo(ABE):
	type CreateRawTransactionCmd struct {
		Inputs   []TransactionInput
		Amounts  map[string]float64 `jsonrpcusage:"{\"address\":amount,...}"` // In BTC
		LockTime *int64
	}

	// TODO(abe): the type of txfee may need to change to a pointer point to float64
	type CreateRawTransactionCmdAbe struct {
		Inputs  []TransactionInputAbe
		Outputs []TransactionOutputAbe `jsonrpcusage:"{\"address\":\"amount\",...}"` // TODO: without value just a script
		Witness []byte
		Fee     string `json:"txfee"` // in Neutrino
	}
   ```
   - CreateRawTransactionCmd is used in [`func NewCreateRawTransactionCmd`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L98) (is not used?)
	```go
	func NewCreateRawTransactionCmd(inputs []TransactionInput, amounts map[string]float64,
	lockTime *int64) *CreateRawTransactionCmd {
		// to make sure we're serializing this to the empty list and not null, we
		// explicitly initialize the list
		if inputs == nil {
			inputs = []TransactionInput{}
		}
		return &CreateRawTransactionCmd{
			Inputs:   inputs,
			Amounts:  amounts,
			LockTime: lockTime,
		}
	}
	```
2. [abejson/chainsvrcmds.go `type GetBlockCmd struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L203) GetBlockCmd vs GetBlockAbeCmd
   ```go
	// GetBlockCmd defines the getblock JSON-RPC command.
	type GetBlockCmd struct {
		Hash      string
		Verbosity *int `jsonrpcdefault:"1"`
	}
	type GetBlockAbeCmd struct {
		Hash      string
		Verbosity *int `jsonrpcdefault:"1"`
	}
   ```

   - GetBlockCmd is used in 
     - [rpcserver.go `func handleGetBlockAbe`](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L1482) should be GetBlockAbeCmd?
		```go
		func handleGetBlockAbe(s *rpcServer, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
			var c *abejson.GetBlockAbeCmd
			if cc, ok := cmd.(*abejson.GetBlockCmd); ok {
				c = &abejson.GetBlockAbeCmd{
					Hash:      cc.Hash,
					Verbosity: cc.Verbosity,
				}
			} else {
				c = cmd.(*abejson.GetBlockAbeCmd)
			}
			...
		}
		```
3. [abejson/chainsvrcmds.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L146) DecodeRawTransactionCmd vs DecodeRawTransactionCmdAbe
   ```go
	// DecodeRawTransactionCmd defines the decoderawtransaction JSON-RPC command.
	//
	//	todo(ABE):
	type DecodeRawTransactionCmd struct {
		HexTx string
	}

	type DecodeRawTransactionCmdAbe struct {
		HexTx string
	}
   ```
   DecodeRawTransactionCmd is used in
   - [abejson/chainsvrcmds.go `func NewDecodeRawTransactionCmd`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L156)
	```go
	// NewDecodeRawTransactionCmd returns a new instance which can be used to issue
	// a decoderawtransaction JSON-RPC command.
	func NewDecodeRawTransactionCmd(hexTx string) *DecodeRawTransactionCmd {
		return &DecodeRawTransactionCmd{
			HexTx: hexTx,
		}
	}
	```
	which is used in [rpcclient/rawtransactions.go `func (c *Client) DecodeRawTransactionAsync`](https://github.com/pqabelian/abec/blob/main/rpcclient/rawtransactions.go#L192)
	```go
	func (c *Client) DecodeRawTransactionAsync(serializedTx []byte) FutureDecodeRawTransactionResult {
		txHex := hex.EncodeToString(serializedTx)
		cmd := abejson.NewDecodeRawTransactionCmd(txHex)
		return c.sendCmd(cmd)
	}
	```


4. [abejson/chainsvrcmds.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L845) SendRawTransactionCmd vs SendRawTransactionAbeCmd
   ```go
	// SendRawTransactionCmd defines the sendrawtransaction JSON-RPC command.
	type SendRawTransactionCmd struct {
		HexTx         string
		AllowHighFees *bool `jsonrpcdefault:"false"`
		MaxFeeRate    *int32
	}

	type SendRawTransactionAbeCmd struct {
		HexTx         string
		AllowHighFees *bool `jsonrpcdefault:"false"`
		MaxFeeRate    *int32
	}
   ```
   SendRawTransactionCmd is used in 
	- [abejson/chainsvrcmds.go `func NewBitcoindSendRawTransactionCmd`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L879) (is not used?)
		```go
		// NewSendRawTransactionCmd returns a new instance which can be used to issue a
		// sendrawtransaction JSON-RPC command to a bitcoind node.
		//
		// A 0 maxFeeRate indicates that a maximum fee rate won't be enforced.
		func NewBitcoindSendRawTransactionCmd(hexTx string, maxFeeRate int32) *SendRawTransactionCmd {
			return &SendRawTransactionCmd{
				HexTx:      hexTx,
				MaxFeeRate: &maxFeeRate,
			}
		}
		```
	- [rpcserver.go `func handleSendRawTransactionAbe`](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L4211) should be SendRawTransactionAbeCmd?
		```go
		func handleSendRawTransactionAbe(s *rpcServer, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
			var c *abejson.SendRawTransactionAbeCmd
			if cc, ok := cmd.(*abejson.SendRawTransactionCmd); ok {
				c = &abejson.SendRawTransactionAbeCmd{
					HexTx:         cc.HexTx,
					AllowHighFees: cc.AllowHighFees,
					MaxFeeRate:    cc.MaxFeeRate,
				}
			}
			...
		}
		```
5. [abejson/chainsvrcmds.go `func init()`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrcmds.go#L1025)
   ```go
	func init() {
		// No special flags for commands in this file.
		flags := UsageFlag(0)
		...
		MustRegisterCmd("createrawtransaction", (*CreateRawTransactionCmdAbe)(nil), flags)
		MustRegisterCmd("createrawtransactionAbe", (*CreateRawTransactionCmdAbe)(nil), flags)
		...
		MustRegisterCmd("decoderawtransaction", (*DecodeRawTransactionCmdAbe)(nil), flags)
		MustRegisterCmd("decoderawtransactionAbe", (*DecodeRawTransactionCmdAbe)(nil), flags)
		...
		MustRegisterCmd("getblock", (*GetBlockAbeCmd)(nil), flags)
		MustRegisterCmd("getblockabe", (*GetBlockAbeCmd)(nil), flags)
		...
		MustRegisterCmd("sendrawtransaction", (*SendRawTransactionAbeCmd)(nil), flags)
		MustRegisterCmd("sendrawtransactionabe", (*SendRawTransactionAbeCmd)(nil), flags)
		...
	
	}
	
   ```
6. [abejson/chainsvrresults.go `type TxRawResult struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrresults.go#L774) TxRawResult vs TxRawResultAbe
   ```go
	// TxRawResult models the data from the getrawtransaction command.
	//
	//	todo(ABE):
	type TxRawResult struct {
		Hex           string `json:"hex"`
		Txid          string `json:"txid"`
		Hash          string `json:"hash,omitempty"`
		Size          int32  `json:"size,omitempty"`
		Vsize         int32  `json:"vsize,omitempty"`
		Weight        int32  `json:"weight,omitempty"`
		Version       int32  `json:"version"`
		LockTime      uint32 `json:"locktime"`
		Vin           []Vin  `json:"vin"`
		Vout          []Vout `json:"vout"`
		BlockHash     string `json:"blockhash,omitempty"`
		Confirmations uint64 `json:"confirmations,omitempty"`
		Time          int64  `json:"time,omitempty"`
		Blocktime     int64  `json:"blocktime,omitempty"`
	}	
	type TxRawResultAbe struct {
		Hex           string     `json:"hex"`
		Txid          string     `json:"txid"`
		Hash          string     `json:"hash,omitempty"`
		Size          int32      `json:"size,omitempty"`
		Fullsize      int32      `json:"fullsize,omitempty"`
		Version       uint32     `json:"version"`
		Vin           []TxIn     `json:"vin"`
		Vout          []TxOutAbe `json:"vout"`
		Fee           float64    `json:"fee"`
		Witness       string     `json:"witness"`
		BlockHash     string     `json:"blockhash,omitempty"`
		Confirmations uint64     `json:"confirmations,omitempty"`
		Time          int64      `json:"time,omitempty"`
		Blocktime     int64      `json:"blocktime,omitempty"`
	}
   ```
   TxRawResult is used in
   - [abejson/chainsvrresults.go `type GetBlockAbeVerboseTxResult struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrresults.go#L166) should be TxRawResultAbe?
	```go
	type GetBlockAbeVerboseTxResult struct {
		...
		Tx            []TxRawResult `json:"tx,omitempty"`
		...
	}
	```
	- [abejson/chainsvrwsntfns.go `type TxAcceptedVerboseNtfn struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L322) 
		```go
		// TxAcceptedVerboseNtfn defines the txacceptedverbose JSON-RPC notification.
		//
		//	todo(ABE):
		type TxAcceptedVerboseNtfn struct {
			RawTx TxRawResult
		}
		```
		There is TxAcceptedVerboseNtfnAbe, but TxAcceptedVerboseNtfn is used in [abejson/chainsvrwsntfns.go `func init()`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L377) should be TxAcceptedVerboseNtfnAbe?
		```go
		func init() {
			// The commands in this file are only usable by websockets and are
			// notifications.
			flags := UFWebsocketOnly | UFNotification
			...
			MustRegisterCmd(TxAcceptedVerboseNtfnMethod, (*TxAcceptedVerboseNtfn)(nil), flags)
			...
		}
		```
	- [rpcclient/notify.go `type NotificationHandlers struct`](https://github.com/pqabelian/abec/blob/main/rpcclient/notify.go#L180)
		```go
		type NotificationHandlers struct {
			...
			// OnTxAccepted is invoked when a transaction is accepted into the
			// memory pool.  It will only be invoked if a preceding call to
			// NotifyNewTransactions with the verbose flag set to true has been
			// made to register for the notification and the function is non-nil.
			OnTxAcceptedVerbose func(txDetails *abejson.TxRawResult)
			...
		}
		```
	- [rpcclient/notify.go `func parseTxAcceptedVerboseNtfnParams`](https://github.com/pqabelian/abec/blob/main/rpcclient/notify.go#L790) 
		```go
		// parseTxAcceptedVerboseNtfnParams parses out details about a raw transaction
		// from the parameters of a txacceptedverbose notification.
		func parseTxAcceptedVerboseNtfnParams(params []json.RawMessage) (*abejson.TxRawResult, error) {
			...
			// Unmarshal first parameter as a raw transaction result object.
			var rawTx abejson.TxRawResult
			...
		}
		```
	- [rpcclient/rawtransactions.go `func (r FutureGetRawTransactionVerboseResult) Receive() `](https://github.com/pqabelian/abec/blob/main/rpcclient/rawtransactions.go#L126)
		```go
		// Receive waits for the response promised by the future and returns information
		// about a transaction given its hash.
		func (r FutureGetRawTransactionVerboseResult) Receive() (*abejson.TxRawResult, error) {
			...

			// Unmarshal result as a gettrawtransaction result object.
			var rawTxResult abejson.TxRawResult
			...
		}
		```
	- [rpcclient/rawtransactions.go `func (c *Client) GetRawTransactionVerbose `](https://github.com/pqabelian/abec/blob/main/rpcclient/rawtransactions.go#L161)
		```go
		// Receive waits for the response promised by the future and returns information
		// about a transaction given its hash.
		// GetRawTransactionVerbose returns information about a transaction given
		// its hash.
		//
		// See GetRawTransaction to obtain only the transaction already deserialized.
		func (c *Client) GetRawTransactionVerbose(txHash *chainhash.Hash) (*abejson.TxRawResult, error) {
			return c.GetRawTransactionVerboseAsync(txHash).Receive()
		}
		```
	- [rpcclient/rawtransactions.go `func (r FutureDecodeRawTransactionResult) Receive()`](https://github.com/pqabelian/abec/blob/main/rpcclient/rawtransactions.go#L171)
		```go
		// Receive waits for the response promised by the future and returns information
		// about a transaction given its serialized bytes.
		func (r FutureDecodeRawTransactionResult) Receive() (*abejson.TxRawResult, error) {
			...

			// Unmarshal result as a decoderawtransaction result object.
			var rawTxResult abejson.TxRawResult
			...
		}
		```
	- [rpcclient/rawtransactions.go `func (c *Client) DecodeRawTransaction`](https://github.com/pqabelian/abec/blob/main/rpcclient/rawtransactions.go#L200)
		```go
		// DecodeRawTransaction returns information about a transaction given its
		// serialized bytes.
		func (c *Client) DecodeRawTransaction(serializedTx []byte) (*abejson.TxRawResult, error) {
			return c.DecodeRawTransactionAsync(serializedTx).Receive()
		}
		```
	- [rpcserverhelp.go `var rpcResultTypes`](https://github.com/pqabelian/abec/blob/main/rpcserverhelp.go#L679)
		```go
		// rpcResultTypes specifies the result types that each RPC command can return.
		// This information is used to generate the help.  Each result type must be a
		// pointer to the type (or nil to indicate no return value).
		var rpcResultTypes = map[string][]interface{}{
			...
			"getrawtransaction":     {(*string)(nil), (*abejson.TxRawResult)(nil)},
			...
		}
		```
7. [abejson/chainsvrresults.go `type TxRawDecodeResult struct`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrresults.go#L829) TxRawDecodeResult vs TxRawDecodeResultAbe
   ```go
	// TxRawDecodeResult models the data from the decoderawtransaction command.
	//
	//	todo(ABE):
	type TxRawDecodeResult struct {
		Txid     string `json:"txid"`
		Version  int32  `json:"version"`
		Locktime uint32 `json:"locktime"`
		Vin      []Vin  `json:"vin"`
		Vout     []Vout `json:"vout"`
	}

	type TxRawDecodeResultAbe struct {
		Txid    string     `json:"txid"`
		Version uint32     `json:"version"`
		Vin     []TxIn     `json:"vin"`
		Vout    []TxOutAbe `json:"vout"`
		Fee     float64    `json:"fee"`
		Witness string     `json:"witness"`
	}
   ```
   TxRawDecodeResult is used in [rpcserverhelp.go `var rpcResultTypes`](https://github.com/pqabelian/abec/blob/main/rpcserverhelp.go#L683)
   ```go
	// rpcResultTypes specifies the result types that each RPC command can return.
	// This information is used to generate the help.  Each result type must be a
	// pointer to the type (or nil to indicate no return value).
	var rpcResultTypes = map[string][]interface{}{
		...
		"decoderawtransaction": {(*abejson.TxRawDecodeResult)(nil)},
		...
	}
   ```

16/05/2024
# abejson
1. [abejson/chainsvrwscmds.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwscmds.go#L184) RescanCmd is deprecated, use RescanBlocksCmd instead, then RescanAbeCmd?
   ```go
	// RescanCmd defines the rescan JSON-RPC command.
	//
	// Deprecated: Use RescanBlocksCmd instead.
	type RescanCmd struct {
		BeginBlock string
		Addresses  []string
		OutPoints  []OutPoint
		EndBlock   *string
	}
	type RescanAbeCmd struct {
		BeginBlock string
		EndBlock   *string
	}
   ```
   RescanCmd is used in 
	- [abejson/chainsvrwscmds.go `func NewRescanCmd`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwscmds.go#L202)
		```go
		func NewRescanCmd(beginBlock string, addresses []string, outPoints []OutPoint, endBlock *string) *RescanCmd {
			return &RescanCmd{
			BeginBlock: beginBlock,
			Addresses:  addresses,
			OutPoints:  outPoints,
			EndBlock:   endBlock,
			}
		}
		```
	- [abejson/chainsvrwscmds.go `func init()`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwscmds.go#L251)
		```go
		func init() {
			// The commands in this file are only usable by websockets.
			flags := UFWebsocketOnly
			...
			MustRegisterCmd("rescan", (*RescanCmd)(nil), flags)
			...
		}
		```
2. [abejson/chainsvrwsntfns.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L11) `BlockConnectedNtfnMethod` vs `BlockAbeConnectedNtfnMethod`, `BlockDisconnectedNtfnMethod` vs `BlockAbeDisconnectedNtfnMethod`
   ```go
	const (
		// BlockConnectedNtfnMethod is the legacy, deprecated method used for
		// notifications from the chain server that a block has been connected.
		//
		// Deprecated: Use FilteredBlockConnectedNtfnMethod instead.
		BlockConnectedNtfnMethod    = "blockconnected"
		BlockAbeConnectedNtfnMethod = "blockabeconnected"

		// BlockDisconnectedNtfnMethod is the legacy, deprecated method used for
		// notifications from the chain server that a block has been
		// disconnected.
		//
		// Deprecated: Use FilteredBlockDisconnectedNtfnMethod instead.
		BlockDisconnectedNtfnMethod    = "blockdisconnected"
		BlockAbeDisconnectedNtfnMethod = "blockabedisconnected"
		...
	}

   ```
   They are used in 
   - [abejson/chainsvrwscmds.go `func init()`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwscmds.go#L251)
  		```go
		func init() {
			// The commands in this file are only usable by websockets and are
			// notifications.
			flags := UFWebsocketOnly | UFNotification
			MustRegisterCmd(BlockConnectedNtfnMethod, (*BlockConnectedNtfn)(nil), flags)
			MustRegisterCmd(BlockAbeConnectedNtfnMethod, (*BlockAbeConnectedNtfn)(nil), flags)
			MustRegisterCmd(BlockDisconnectedNtfnMethod, (*BlockDisconnectedNtfn)(nil), flags)
			MustRegisterCmd(BlockAbeDisconnectedNtfnMethod, (*BlockAbeDisconnectedNtfn)(nil), flags)
			...
		}
		```
   - [rpcclient/notify.go](https://github.com/pqabelian/abec/blob/main/rpcclient/notify.go#L214)
		```go
		func (c *Client) handleNotification(ntfn *rawNotification) {
			switch ntfn.Method {
			// OnBlockConnected
			case abejson.BlockConnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockConnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
				if err != nil {
					log.Warnf("Received invalid block connected "+
					"notification: %v", err)
					return
				}

				c.ntfnHandlers.OnBlockConnected(blockHash, blockHeight, blockTime)
			case abejson.BlockAbeConnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockAbeConnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
				if err != nil {
					log.Warnf("Received invalid block connected "+
					"notification: %v", err)
					return
				}

				c.ntfnHandlers.OnBlockAbeConnected(blockHash, blockHeight, blockTime)
				...

			// OnBlockDisconnected
			case abejson.BlockDisconnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockDisconnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.	Params)
				if err != nil {
					log.Warnf("Received invalid block connected "+
				"notification: %v", err)
					return
				}

				c.ntfnHandlers.OnBlockDisconnected(blockHash, blockHeight, blockTime)
			case abejson.BlockAbeDisconnectedNtfnMethod:
				// Ignore the notification if the client is not interested in
				// it.
				if c.ntfnHandlers.OnBlockAbeDisconnected == nil {
					return
				}

				blockHash, blockHeight, blockTime, err := parseChainNtfnParams(ntfn.Params)
				if err != nil {
					log.Warnf("Received invalid block 	connected "+
				"notification: %v", err)
					return
				}
				c.ntfnHandlers.OnBlockAbeDisconnected(blockHash, blockHeight, blockTime)
				...
			}
		}
		```
3. [abejson/chainsvrwsntfns.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L82)
	```go
	// BlockConnectedNtfn defines the blockconnected JSON-RPC notification.
	//
	// Deprecated: Use FilteredBlockConnectedNtfn instead.
	type BlockConnectedNtfn struct {
		Hash   string
		Height int32
		Time   int64
	}
	type BlockAbeConnectedNtfn struct {
		Hash   string
		Height int32
		Time   int64
	}
	```
	BlockConnectedNtfn is used in 
	- [abejson/chainsvrwsntfns.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L97)
		```go
		// Deprecated: Use NewFilteredBlockConnectedNtfn instead.
		func NewBlockConnectedNtfn(hash string, height int32, time int64) *BlockConnectedNtfn {
			return &BlockConnectedNtfn{
				Hash:   hash,
				Height: height,
				Time:   time,
			}
		}
		```
	- [abejson/chainsvrwscmds.go `func init()`](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwscmds.go#L251)
  		```go
		func init() {
			// The commands in this file are only usable by websockets and are
			// notifications.
			flags := UFWebsocketOnly | UFNotification
			MustRegisterCmd(BlockConnectedNtfnMethod, (*BlockConnectedNtfn)(nil), flags)
			MustRegisterCmd(BlockAbeConnectedNtfnMethod, (*BlockAbeConnectedNtfn)(nil), flags)
			...
		}
		```
4. Similar case: [abejson/chainsvrwsntfns.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L115)
   ```go
	// Deprecated: Use FilteredBlockDisconnectedNtfn instead.
	type BlockDisconnectedNtfn struct {
		Hash   string
		Height int32
		Time   int64
	}
	type BlockAbeDisconnectedNtfn struct {
		Hash   string
		Height int32
		Time   int64
	}
   ```
5. Similar case: [abejson/chainsvrwsntfns.go](https://github.com/pqabelian/abec/blob/main/abejson/chainsvrwsntfns.go#L322)
	```go
	// TxAcceptedVerboseNtfn defines the txacceptedverbose JSON-RPC notification.
	//
	//	todo(ABE):	
	type TxAcceptedVerboseNtfn struct {
		RawTx TxRawResult
	}

	type TxAcceptedVerboseNtfnAbe struct {
		RawTx TxRawResultAbe
	}
	```
# Others
1. [rpcclient/notify.go] 
   ```go
	func parseTxAcceptedNtfnParams(params []json.RawMessage) (*chainhash.Hash,
	abeutil.Amount, error){
		...
		// Bounds check amount.
		amt, err := abeutil.NewAmount(famt)
		if err != nil {
			return nil, 0, err
		}
		...
	}
   ```
	
23/05/2024
1. [blockchain/chainio.go `func (b *BlockChain) initChainState()`](https://github.com/pqabelian/abec/blob/feature_cleancode/blockchain/chainio.go#L1583)
   ```go
	// initChainState attempts to load and initialize the chain state from the
	// database.  When the db does not yet contain any chain state, both it and the
	// chain state are initialized to the genesis block.
	func (b *BlockChain) initChainState() error {
		...
		// todo: 202207 need refactor to remove
		if !hasBlockIndex {
			err := migrateBlockIndex(b.db)
			if err != nil {
				return nil
			}
		}
		...
	}
   ```
	`migrateBlockIndex` is in [blockchain/upgrade.go](https://github.com/pqabelian/abec/blob/feature_cleancode/blockchain/upgrade.go#L49)
	```go
	// migrateBlockIndex migrates all block entries from the v1 block index bucket
	// to the v2 bucket. The v1 bucket stores all block entries keyed by block hash,
	// whereas the v2 bucket stores the exact same values, but keyed instead by
	// block height + hash.
	//
	//	todo: (EthashPoW) 202207 Need refactor to remove.
	func migrateBlockIndex(db database.DB) error {
		...
	}
	```
2. [server.go](https://github.com/pqabelian/abec/blob/feature_cleancode/server.go#L202)
   ```go
	// server provides an Abelian server for handling communications to and from Abelian peers.
	type server struct {
		...
		//	TODO:(Abelian) remove txScript, sigCache, and hashCache
		sigCache             *txscript.SigCache
		hashCache            *txscript.HashCache
		witnessCache         *txscript.WitnessCache
		...
	}
   ```
3. [server.go `func initListeners`](https://github.com/pqabelian/abec/blob/feature_cleancode/server.go#L2933) random port?
	```go
	// initListeners initializes the configured net listeners and adds any bound
	// addresses to the address manager. Returns the listeners and a NAT interface,
	// which is non-nil if UPnP is in use.
	func initListeners(amgr *netaddrmgr.NetAddrManager, listenAddrs []string, services wire.ServiceFlag) ([]net.Listener, NAT, error) {
		...
		for _, sip := range cfg.ExternalIPs {
			eport := uint16(defaultPort)
			host, portstr, err := net.SplitHostPort(sip)
			if err != nil {
				// no port, use default.
				// todo: 20220427. if no port, then use a random port
				host = sip
			}
			...
		}
		...
	}

	```

4. [rpcwebsocket.go](https://github.com/pqabelian/abec/blob/feature_cleancode/rpcwebsocket.go#L606)
   ```go
	// notificationHandler reads notifications and control messages from the queue
	// handler and processes one at a time.
	//
	//	TODO(ABE, MUST):
	func (m *wsNotificationManager) notificationHandler() {
		...
		case *notificationTxAcceptedByMempoolAbe:
				if n.isNew && len(txNotifications) != 0 {
					//m.notifyForNewTxAbe(txNotifications, n.tx)
				}

				//	todo(ABE): ABE does not support watchedOutPoints or watchedAddrs.
				//m.notifyForTx(watchedOutPoints, watchedAddrs, n.tx, nil)

				// TODO(ABE): ABE does not support filter.
				//m.notifyRelevantTxAccepted(n.tx, clients)
		...
	}
   ```
5. [rpcserver.go `func handleDecodeScript`](https://github.com/pqabelian/abec/blob/feature_cleancode/rpcserver.go#L1122)
	```go
	// handleDecodeScript handles decodescript commands.
	//
	//	todo(ABE): ABE does not use/support this?
	func handleDecodeScript(s *rpcServer, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
		...
	}
	```
30/05/2024
1. [rpcserver.go `func chainErrToGBTErrString(err error)`](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L2475) 
   ```go
	func chainErrToGBTErrString(err error) string {
		...
		//	todo(ABE): ABE does not use weight
		case blockchain.ErrBlockWeightTooHigh:
			return "bad-blk-weight"
		...
	}
   ```
   used in [rpcserver.go `handleGetBlockTemplateProposal`](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L2572)
 2. [rpcserver.go `func handleGetBlockTemplate`](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L2642)
   ```go
	// handleGetBlockTemplate implements the getblocktemplate command.
	func handleGetBlockTemplate(s *rpcServer, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
		...
		switch mode {
		case "template":
			return handleGetBlockTemplateRequest(s, request, closeChan)
		// todo (ABE): proposal is not supported yet, maybe deleted or implemented in the future
		case "proposal":
			return handleGetBlockTemplateProposal(s, request)
		}
	}
   ```
   handleGetBlockTemplateProposal is in [rpcserver.go](https://github.com/pqabelian/abec/blob/main/rpcserver.go#L2572)

3. [params.go](https://github.com/pqabelian/abec/blob/main/params.go#L42)
   ```go
	// TODO: To build a test net or not?
	// regressionNetParams contains parameters specific to the regression test
	// network (wire.TestNet).  NOTE: The RPC port is intentionally different
	// than the reference implementation - see the mainNetParams comment for
	// details.
	var regressionNetParams = params{
		Params: &chaincfg.RegressionNetParams,
		//rpcPort: "18334",
		rpcPort:        "18667",
		rpcPortGetWork: "18668",
	}

	// testNet3Params contains parameters specific to the test network (version 3)
	// (wire.TestNet3).  NOTE: The RPC port is intentionally different than the
	// reference implementation - see the mainNetParams comment for details.
	var testNet3Params = params{
		Params: &chaincfg.TestNet3Params,
		//rpcPort: "18334",
		rpcPort:        "18667",
		rpcPortGetWork: "18668",
	}

	// simNetParams contains parameters specific to the simulation test network
	// (wire.SimNet).
	var simNetParams = params{
		Params: &chaincfg.SimNetParams,
		//rpcPort: "18556",
		rpcPort:        "18889",
		rpcPortGetWork: "18890",
	}
   ```
4. [netaddrmgr/netaddrmanager.go](https://github.com/pqabelian/abec/blob/main/netaddrmgr/netaddrmanager.go#L29) btcd in comments
   ```go
	type NetAddrManager struct {
		mtx               sync.Mutex
		peersFile         string // store the peers to quicker build connection when the btcd restart
		...
	}
   ```