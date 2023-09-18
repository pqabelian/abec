package witnessmgr

import (
	"errors"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/wire"
	"sync"
)

const (
	// deleteInterval is the number of blocks between each delete operation.
	deleteInterval = 100
)

// Config is a configuration struct used to initialize a new WitnessManager.
type Config struct {
	NodeType           wire.NodeType
	MaxReservedWitness uint32
	Chain              *blockchain.BlockChain
}

// WitnessManager is used to control the storage of witness.
// It will automatically prune the witness file if the node
// is not a full node.
type WitnessManager struct {
	nodeType           wire.NodeType
	maxReservedWitness uint32
	chain              *blockchain.BlockChain
	deleteLock         sync.Mutex
}

// New constructs a new WitnessManager.
func New(config *Config) (*WitnessManager, error) {
	wm := WitnessManager{
		nodeType:           config.NodeType,
		maxReservedWitness: config.MaxReservedWitness,
		chain:              config.Chain,
	}

	if wm.nodeType == wire.NormalNode {
		currentHeight := config.Chain.BestSnapshot().Height
		witnessKeptStartHeight := currentHeight - int32(wm.maxReservedWitness)
		if witnessKeptStartHeight > 0 {
			log.Infof("Start pruning witness data before height %v, please do not shut down abec", witnessKeptStartHeight)
			err := wm.pruneWitnessBeforeHeight(witnessKeptStartHeight)
			if err != nil {
				log.Errorf("Fail to prune witness data: %v", err)
			}
		}
		wm.chain.Subscribe(wm.handleBlockchainNotification)
	}

	if wm.nodeType == wire.SemifullNode {
		lastCheckpoint := wm.chain.LatestCheckpoint()
		if lastCheckpoint != nil {
			log.Infof("Start pruning witness data before height %v, please do not shut down abec", lastCheckpoint.Height)
			err := wm.pruneWitnessBeforeHeight(lastCheckpoint.Height)
			if err != nil {
				return nil, err
			}
		}
	}

	return &wm, nil
}

// handleBlockchainNotification handles notifications from blockchain.
func (wm *WitnessManager) handleBlockchainNotification(notification *blockchain.Notification) {
	switch notification.Type {

	// A block has been connected to the main blockchain.
	case blockchain.NTBlockConnected:
		block, ok := notification.Data.(*abeutil.BlockAbe)
		if !ok {
			log.Warnf("Chain connected notification is not a block.")
			break
		}

		currentHeight := block.Height()
		if currentHeight%deleteInterval == 0 {
			witnessKeptStartHeight := currentHeight - int32(wm.maxReservedWitness)
			if witnessKeptStartHeight <= 0 {
				return
			}
			log.Infof("Start pruning witness data before height %v, please do not shut down abec", witnessKeptStartHeight)
			err := wm.pruneWitnessBeforeHeight(witnessKeptStartHeight)
			if err != nil {
				log.Errorf("Fail to prune witness data: %v", err)
			}
		}
	}
}

// pruneWitnessBeforeHeight keep the witness file after certain height (include)
// and prune other witness file.
func (wm *WitnessManager) pruneWitnessBeforeHeight(height int32) error {
	if !wm.deleteLock.TryLock() {
		log.Infof("Witness deleting process is ongoing, skip")
		return nil
	}
	defer wm.deleteLock.Unlock()

	if height <= 0 {
		return nil
	}

	bestState := wm.chain.BestSnapshot()
	if bestState == nil {
		return errors.New("unable to fetch best state")
	}
	bestHeight := bestState.Height

	// Calculate the file number that stores the witness of block between height and bestHeight,
	// which should be reserved.
	fileNumReserved, err := wm.chain.FileNumBetweenHeight(uint32(height), uint32(bestHeight))
	if err != nil {
		return err
	}

	if len(fileNumReserved) == 0 {
		log.Infof("No witness file should be reserved, skip")
		return nil
	}
	log.Infof("Reserved witness files between height %v and %v: %v", height, bestHeight, fileNumReserved)

	// Calculate prune range, starting from min existing witness file num.
	fileNumPruned := make([]uint32, 0)
	minExistingWitnessFileNum, err := wm.chain.FetchMinExistingWitnessFileNum()
	if err != nil {
		return err
	}
	var currentNum uint32 = minExistingWitnessFileNum
	for _, num := range fileNumReserved {
		var i uint32
		for i = currentNum; i != num; i++ {
			fileNumPruned = append(fileNumPruned, i)
		}
		currentNum = i + 1
	}
	if len(fileNumPruned) == 0 {
		log.Infof("No witness file can be pruned, skip")
		return nil
	}
	log.Infof("No longer needed witness files between height %v and %v: %v", height, bestHeight, fileNumPruned)

	// Fetch witness file info, this process will also filter some files that do not exist.
	fileInfo, err := wm.chain.FetchWitnessFileInfo(fileNumPruned)
	if err != nil {
		return err
	}
	if len(fileInfo) == 0 {
		log.Infof("No witness file can be pruned")
		return nil
	}
	realFileNumPruned := make([]uint32, 0)
	for num, _ := range fileInfo {
		realFileNumPruned = append(realFileNumPruned, num)
	}

	// Save delete info to database, including file size and delete time,
	// these information may be useful in the future.
	err = wm.chain.StoreDeleteHistory(fileInfo)
	if err != nil {
		return err
	}

	// Update min consecutive witness file num first in case the delete process
	// is interrupted. Even if the delete process is interrupted accidentally later,
	// the witness file scan process when abec is launched can still work fine.
	minConsecutiveWitnessFileNum := fileNumReserved[len(fileNumReserved)-1]
	for i := len(fileNumReserved) - 2; i >= 0; i-- {
		if fileNumReserved[i]+1 != minConsecutiveWitnessFileNum {
			break
		}
		minConsecutiveWitnessFileNum = fileNumReserved[i]
	}
	err = wm.chain.UpdateMinConsecutiveWitnessFileNum(minConsecutiveWitnessFileNum)
	if err != nil {
		return err
	}

	// Store witnessServiceHeight before pruning witness in case the pruning process fails.
	err = wm.chain.StoreWitnessServiceHeight(uint32(height))
	if err != nil {
		return err
	}

	// Prune witness files, this may take a while.
	_, err = wm.chain.PruneWitnessFile(realFileNumPruned)
	if err != nil {
		return err
	}

	// Update min existing witness file.
	err = wm.chain.UpdateMinExistingWitnessFileNum()
	return err
}
