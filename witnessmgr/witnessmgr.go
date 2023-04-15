package witnessmgr

import (
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
// It will automatically delete the witness file if the node
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
			wm.startDeleteOperation()
		}

	}
}

// todo
func (wm *WitnessManager) startDeleteOperation() {

}
