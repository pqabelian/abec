package blockchain

import (
	ctautwire "github.com/pqabelian/abec/ctaut/wire"
)

// RPC should provide the corresponding APIs.

// GetLatestAutScriptVersion returns the latest AutScriptVersion that the blockchain is supporting.
func (b *BlockChain) GetLatestAutScriptVersion() (uint32, error) {
	// todo: may code depends on the chainParams
	return ctautwire.AutScriptVersion, nil
}

// GetSupportedAutScriptVersions returns the AutScriptVersion list that the blockchain is supporting.
func (b *BlockChain) GetSupportedAutScriptVersions() ([]uint32, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// todo: may code depends on the chainParams
	return b.getSupportedTxVersionsByHeight(b.bestChain.Height())
}

// getSupportedAutScriptVersionsByHeight returns the AutScriptVersion list that the blockchain is supporting with respect to the given height.
func (b *BlockChain) getSupportedAutScriptVersionsByHeight(height int32) ([]uint32, error) {

	versions := make([]uint32, 0, 2)

	if height >= b.chainParams.BlockHeightAconcagua {
		versions = append(versions, ctautwire.AutScriptVersion_1)
	}

	return versions, nil
}
