package syncmgr

import (
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/consensus/ethash"
	"github.com/pqabelian/abec/mempool"
	"github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/wire"
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
	PeerNotifier PeerNotifier
	Chain        *blockchain.BlockChain
	TxMemPool    *mempool.TxPool
	Ethash       *ethash.Ethash // todo: (ethmining)
	ChainParams  *chaincfg.Params

	DisableCheckpoints bool
	MaxPeers           int

	FeeEstimator *mempool.FeeEstimator
}
