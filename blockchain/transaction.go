package blockchain

import (
	"github.com/abesuite/abec/wire"
)

// RPC should provide the corresponding APIs.

// GetLatestTxVersion returns the latest TxVersion that the blockchain is supporting.
func (b *BlockChain) GetLatestTxVersion() (uint32, error) {
	// todo: may code depends on the chainParams
	return wire.TxVersion, nil
}

// GetSupportedTxVersions returns the TxVersion list that the blockchain is supporting.
func (b *BlockChain) GetSupportedTxVersions() ([]uint32, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// todo: may code depends on the chainParams
	return b.getSupportedTxVersionsByHeight(b.bestChain.Height())
}

// getSupportedTxVersionsByHeight returns the TxVersion list that the blockchain is supporting with respect to the given height.
func (b *BlockChain) getSupportedTxVersionsByHeight(height int32) ([]uint32, error) {

	versions := make([]uint32, 0, 2)

	if height >= b.chainParams.BlockHeightAconcaguaCommit {
		versions = append(versions, wire.TxVersion_Height_464000_Aconcagua)

	} else if height >= b.chainParams.BlockHeightAconcagua {
		versions = append(versions, wire.TxVersion_Height_464000_Aconcagua)
		versions = append(versions, wire.TxVersion_Height_MLPAUT_300000)

	} else if height >= b.chainParams.BlockHeightMLPAUTCOMMIT {
		versions = append(versions, wire.TxVersion_Height_MLPAUT_300000)

	} else if height >= b.chainParams.BlockHeightMLPAUT {
		versions = append(versions, wire.TxVersion_Height_MLPAUT_300000)
		versions = append(versions, wire.TxVersion_Height_0)

	} else {
		versions = append(versions, wire.TxVersion_Height_0)
	}

	return versions, nil
}
