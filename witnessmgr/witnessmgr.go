package witnessmgr

import (
	"errors"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/wire"
)

const (
	// deleteInterval is the number of blocks between each delete operation.
	deleteInterval = 100
)

// Config is a configuration struct used to initialize a new WitnessManager.
type Config struct {
	NodeType   wire.NodeType
	TrustLevel wire.TrustLevel
	Chain      *blockchain.BlockChain
}

// WitnessManager is used to control the storage of witness.
// It will automatically prune the witness file if the node
// is not a full node.
type WitnessManager struct {
	nodeType   wire.NodeType
	trustLevel wire.TrustLevel
	chain      *blockchain.BlockChain
}

// New constructs a new WitnessManager.
func New(config *Config) (*WitnessManager, error) {
	wm := WitnessManager{
		nodeType:   config.NodeType,
		trustLevel: config.TrustLevel,
		chain:      config.Chain,
	}

	if wm.nodeType == wire.NormalNode {
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
			witnessKeptStartHeight := currentHeight - wire.MaxReservedWitness
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
	if height <= 0 {
		return nil
	}

	bestState := wm.chain.BestSnapshot()
	if bestState == nil {
		return errors.New("unable to fetch best state")
	}
	bestHeight := bestState.Height

	fileNumReserved, err := wm.chain.FileNumBetweenHeight(uint32(height), uint32(bestHeight))
	if err != nil {
		return err
	}

	if len(fileNumReserved) == 0 {
		return nil
	}
	log.Debugf("Reserving witness files between height %v and %v: %v", height, bestHeight, fileNumReserved)

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
		log.Infof("No witness file can be pruned")
		return nil
	}
	log.Debugf("Pruned witness files between height %v and %v: %v", height, bestHeight, fileNumPruned)

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

	// Save delete info to database, including file size and delete time.
	err = wm.chain.StoreDeleteHistory(fileInfo)
	if err != nil {
		return err
	}

	// Update min consecutive witness file num first in case the delete process
	// is interrupted. Even if the delete process is interrupted accidentally later,
	// the witness file scan process when abec is launched can still work fine.
	minWitnessFileNum := fileNumReserved[len(fileNumReserved)-1]
	for i := len(fileNumReserved) - 2; i >= 0; i-- {
		if fileNumReserved[i]+1 != minWitnessFileNum {
			break
		}
		minWitnessFileNum = fileNumReserved[i]
	}
	err = wm.chain.UpdateMinConsecutiveWitnessFileNum(minWitnessFileNum)
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
