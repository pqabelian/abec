package main

import (
	"fmt"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/database"
	_ "github.com/pqabelian/abec/database/ffldb"
	"github.com/pqabelian/abec/wire"
	"os"
	"path/filepath"
)

const blockDbNamePrefix = "blocks"

var (
	cfg *config
)

// loadBlockDB opens the block database and returns a handle to it.
func loadBlockDB() (database.DB, error) {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + cfg.DbType
	dbPath := filepath.Join(cfg.DataDir, dbName)
	fmt.Printf("Loading block database from '%s'\n", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net, wire.UnsetNode, "")
	if err != nil {
		return nil, err
	}
	return db, nil
}

// findCandidates searches the chain backwards for checkpoint candidates and
// returns a slice of found candidates, if any.  It also stops searching for
// candidates at the last checkpoint that is already hard coded into chain
// since there is no point in finding candidates before already existing
// checkpoints.
func findCandidates(chain *blockchain.BlockChain, latestHash *chainhash.Hash) ([]*chaincfg.Checkpoint, error) {
	// Start with the latest block of the main chain.
	block, err := chain.BlockByHashAbe(latestHash)
	if err != nil {
		return nil, err
	}

	// Get the latest known checkpoint.
	latestCheckpoint := chain.LatestCheckpoint()
	if latestCheckpoint == nil {
		// Set the latest checkpoint to the genesis block if there isn't
		// already one.
		latestCheckpoint = &chaincfg.Checkpoint{
			Hash:   activeNetParams.GenesisHash,
			Height: 0,
		}
	}

	// The latest known block must be at least the last known checkpoint
	// plus required checkpoint confirmations.
	checkpointConfirmations := int32(blockchain.CheckpointConfirmations)
	requiredHeight := latestCheckpoint.Height + checkpointConfirmations
	if block.Height() < requiredHeight {
		return nil, fmt.Errorf("the block database is only at height "+
			"%d which is less than the latest checkpoint height "+
			"of %d plus required confirmations of %d",
			block.Height(), latestCheckpoint.Height,
			checkpointConfirmations)
	}

	// For the first checkpoint, the required height is any block after the
	// genesis block, so long as the chain has at least the required number
	// of confirmations (which is enforced above).
	if len(activeNetParams.Checkpoints) == 0 {
		requiredHeight = 1
	}

	// Indeterminate progress setup.
	numBlocksToTest := block.Height() - requiredHeight
	progressInterval := (numBlocksToTest / 100) + 1 // min 1
	fmt.Print("Searching for candidates")
	defer fmt.Println()

	// Loop backwards through the chain to find checkpoint candidates.
	candidates := make([]*chaincfg.Checkpoint, 0, cfg.NumCandidates)
	numTested := int32(0)
	for len(candidates) < cfg.NumCandidates && block.Height() > requiredHeight {
		// Display progress.
		if numTested%progressInterval == 0 {
			fmt.Print(".")
		}

		// Determine if this block is a checkpoint candidate.
		isCandidate, err := chain.IsCheckpointCandidateAbe(block)
		if err != nil {
			return nil, err
		}

		// All checks passed, so this node seems like a reasonable
		// checkpoint candidate.
		if isCandidate {
			checkpoint := chaincfg.Checkpoint{
				Height: block.Height(),
				Hash:   block.Hash(),
			}
			candidates = append(candidates, &checkpoint)
		}

		prevHash := &block.MsgBlock().Header.PrevBlock
		block, err = chain.BlockByHashAbe(prevHash)
		if err != nil {
			return nil, err
		}
		numTested++
	}
	return candidates, nil
}

func CheckCandidates(chain *blockchain.BlockChain, height int32) (bool, error) {
	// Start with the latest block of the main chain.
	blockHash, err := chain.BlockHashByHeight(height)
	if err != nil {
		return false, err
	}

	block, err := chain.BlockByHashAbe(blockHash)
	if err != nil {
		return false, err
	}

	// Get the latest known checkpoint.
	latestCheckpoint := chain.LatestCheckpoint()
	if latestCheckpoint == nil {
		// Set the latest checkpoint to the genesis block if there isn't
		// already one.
		latestCheckpoint = &chaincfg.Checkpoint{
			Hash:   activeNetParams.GenesisHash,
			Height: 0,
		}
	}

	// The latest known block must be at least the last known checkpoint
	// plus required checkpoint confirmations.
	checkpointConfirmations := int32(blockchain.CheckpointConfirmations)
	requiredHeight := latestCheckpoint.Height + checkpointConfirmations
	if block.Height() < requiredHeight {
		return false, fmt.Errorf("the block database is only at height "+
			"%d which is less than the latest checkpoint height "+
			"of %d plus required confirmations of %d",
			block.Height(), latestCheckpoint.Height,
			checkpointConfirmations)
	}

	// For the first checkpoint, the required height is any block after the
	// genesis block, so long as the chain has at least the required number
	// of confirmations (which is enforced above).
	if len(activeNetParams.Checkpoints) == 0 {
		requiredHeight = 1
	}

	// Indeterminate progress setup.
	fmt.Print("Checking for candidates")
	// Determine if this block is a checkpoint candidate.
	isCandidate, err := chain.IsCheckpointCandidateAbe(block)
	if err != nil {
		return false, err
	}

	return isCandidate, nil
}

// showCandidate display a checkpoint candidate using and output format
// determined by the configuration parameters.  The Go syntax output
// uses the format the chain code expects for checkpoints added to the list.
func showCandidate(candidateNum int, checkpoint *chaincfg.Checkpoint) {
	if cfg.UseGoOutput {
		fmt.Printf("Candidate %d -- {%d, newShaHashFromStr(\"%v\")},\n",
			candidateNum, checkpoint.Height, checkpoint.Hash)
		return
	}

	fmt.Printf("Candidate %d -- Height: %d, Hash: %v\n", candidateNum,
		checkpoint.Height, checkpoint.Hash)

}

func main() {
	// Load configuration and parse command line.
	tcfg, _, err := loadConfig()
	if err != nil {
		return
	}
	cfg = tcfg

	// Load the block database.
	db, err := loadBlockDB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to load database:", err)
		return
	}
	defer db.Close()

	// Setup chain.  Ignore notifications since they aren't needed for this
	// util.
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: activeNetParams,
		TimeSource:  blockchain.NewMedianTime(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize chain: %v\n", err)
		return
	}

	if len(cfg.Heights) != 0 {
		for i := 0; i < len(cfg.Heights); i++ {
			isCandidate, err := CheckCandidates(chain, cfg.Heights[i])
			if err != nil {
				panic(err)
			}
			fmt.Printf("height = %d, %t\n", cfg.Heights[i], isCandidate)
		}
		return
	}

	// Get the latest block hash and height from the database and report
	// status.
	best := chain.BestSnapshot()
	fmt.Printf("Block database loaded with block height %d\n", best.Height)

	// Find checkpoint candidates.
	candidates, err := findCandidates(chain, &best.Hash)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to identify candidates:", err)
		return
	}

	// No candidates.
	if len(candidates) == 0 {
		fmt.Println("No candidates found.")
		return
	}

	// Show the candidates.
	for i, checkpoint := range candidates {
		showCandidate(i+1, checkpoint)
	}
}
