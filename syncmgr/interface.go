package syncmgr

import (
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/consensus/ethash"
	"github.com/abesuite/abec/mempool"
	"github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
)

// PeerNotifier exposes methods to notify peers of status changes to
// transactions, blocks, etc. Currently server (in the main package) implements
// this interface.
type PeerNotifier interface {
	AnnounceNewTransactions(newTxs []*mempool.TxDescAbe)

	UpdatePeerHeights(latestBlkHash *chainhash.Hash, latestHeight int32, updateSource *peer.Peer)

	RelayInventory(invVect *wire.InvVect, data interface{})

	TransactionConfirmed(tx *abeutil.TxAbe)
}

// Config is a configuration struct used to initialize a new SyncManager.
type Config struct {
	NodeType     wire.NodeType
	TrustLevel   wire.TrustLevel
	PeerNotifier PeerNotifier
	Chain        *blockchain.BlockChain
	TxMemPool    *mempool.TxPool
	Ethash       *ethash.Ethash // todo: (ethmining)
	ChainParams  *chaincfg.Params

	DisableCheckpoints bool
	MaxPeers           int

	FeeEstimator *mempool.FeeEstimator
}
