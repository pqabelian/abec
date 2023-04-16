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

	fileNum, err := wm.chain.FileNumBetweenHeight(uint32(height), uint32(bestHeight))
	if err != nil {
		return err
	}

	if len(fileNum) == 0 {
		return nil
	}

	// Calculate prune range.
	fileNumPruned := make([]uint32, 0)
	var currentNum uint32 = 0
	for _, num := range fileNum {
		var i uint32
		for i = currentNum; i != num; i++ {
			fileNumPruned = append(fileNumPruned, i)
		}
		currentNum = i + 1
	}

	// todo: prune file

	return nil
}
