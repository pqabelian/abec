package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/blockchain/indexers"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/connmgr"
	"github.com/pqabelian/abec/consensus/ethash"
	"github.com/pqabelian/abec/database"
	"github.com/pqabelian/abec/mempool"
	"github.com/pqabelian/abec/mempool/rotator"
	"github.com/pqabelian/abec/mining"
	"github.com/pqabelian/abec/mining/cpuminer"
	"github.com/pqabelian/abec/mining/externalminer"
	"github.com/pqabelian/abec/netaddrmgr"
	"github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/syncmgr"
	"github.com/pqabelian/abec/txscript"
	"github.com/pqabelian/abec/wire"
	"github.com/pqabelian/abec/witnessmgr"
	"github.com/shirou/gopsutil/v3/process"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// defaultServices describes the default services that are supported by the server.
	defaultServices = wire.SFNodeNetwork | wire.SFNodeWitness

	// defaultRequiredServices describes the default services that are
	// required to be supported by outbound peers.
	defaultRequiredServices = wire.SFNodeNetwork

	// defaultTargetOutbound is the default number of outbound peers to target.
	defaultTargetOutbound = 8

	// connectionRetryInterval is the base amount of time to wait in between
	// retries when connecting to persistent peers.  It is adjusted by the
	// number of retries such that there is a retry backoff.
	connectionRetryInterval = time.Second * 5
)

var (
	// userAgentName is the user agent name and is used to help identify
	// ourselves to other abec peers.
	userAgentName = "abec"

	// userAgentVersion is the user agent version and is used to help
	// identify ourselves to other abec peers.
	userAgentVersion = fmt.Sprintf("%d.%d.%d", appMajor, appMinor, appPatch)
)

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash chainhash.Hash

// onionAddr implements the net.Addr interface and represents a tor address.
type onionAddr struct {
	addr string
}

// String returns the onion address.
//
// This is part of the net.Addr interface.
func (oa *onionAddr) String() string {
	return oa.addr
}

// Network returns "onion".
//
// This is part of the net.Addr interface.
func (oa *onionAddr) Network() string {
	return "onion"
}

// Ensure onionAddr implements the net.Addr interface.
var _ net.Addr = (*onionAddr)(nil)

// simpleAddr implements the net.Addr interface with two struct fields
type simpleAddr struct {
	net, addr string
}

// String returns the address.
//
// This is part of the net.Addr interface.
func (a simpleAddr) String() string {
	return a.addr
}

// Network returns the network.
//
// This is part of the net.Addr interface.
func (a simpleAddr) Network() string {
	return a.net
}

// Ensure simpleAddr implements the net.Addr interface.
var _ net.Addr = simpleAddr{}

// broadcastMsg provides the ability to house an Abelian message to be broadcast
// to all connected peers except specified excluded peers.
type broadcastMsg struct {
	message      wire.Message
	excludePeers []*serverPeer
}

// broadcastInventoryAdd is a type used to declare that the InvVect it contains
// needs to be added to the rebroadcast map
type broadcastInventoryAdd relayMsg

// broadcastInventoryDel is a type used to declare that the InvVect it contains
// needs to be removed from the rebroadcast map
type broadcastInventoryDel *wire.InvVect

// relayMsg packages an inventory vector along with the newly discovered
// inventory so the relay has access to that information.
type relayMsg struct {
	invVect *wire.InvVect
	data    interface{}
}

// updatePeerHeightsMsg is a message sent from the blockmanager to the server
// after a new block has been accepted. The purpose of the message is to update
// the heights of peers that were known to announce the block before we
// connected it to the main chain or recognized it as an orphan. With these
// updates, peer heights will be kept up to date, allowing for fresh data when
// selecting sync peer candidacy.
type updatePeerHeightsMsg struct {
	newHash    *chainhash.Hash
	newHeight  int32
	originPeer *peer.Peer
}

// peerState maintains state of inbound, persistent, outbound peers as well
// as banned peers and outbound groups.
type peerState struct {
	inboundPeers    map[int32]*serverPeer
	outboundPeers   map[int32]*serverPeer
	persistentPeers map[int32]*serverPeer
	banned          map[string]time.Time
	outboundGroups  map[string]int
}

// Count returns the count of all known peers.
func (ps *peerState) Count() int {
	return len(ps.inboundPeers) + len(ps.outboundPeers) +
		len(ps.persistentPeers)
}

// forAllOutboundPeers is a helper function that runs closure on all outbound
// peers known to peerState.
func (ps *peerState) forAllOutboundPeers(closure func(sp *serverPeer)) {
	for _, e := range ps.outboundPeers {
		closure(e)
	}
	for _, e := range ps.persistentPeers {
		closure(e)
	}
}

// forAllPeers is a helper function that runs closure on all peers known to
// peerState.
func (ps *peerState) forAllPeers(closure func(sp *serverPeer)) {
	for _, e := range ps.inboundPeers {
		closure(e)
	}
	ps.forAllOutboundPeers(closure)
}

// server provides an Abelian server for handling communications to and from Abelian peers.
type server struct {
	// The following variables must only be used atomically.
	// Putting the uint64s first makes them 64-bit aligned for 32-bit systems.
	bytesReceived uint64 // Total bytes received from all peers since start.
	bytesSent     uint64 // Total bytes sent to all peers since start.
	started       int32
	shutdown      int32
	shutdownSched int32
	startupTime   int64

	chainParams *chaincfg.Params
	addrManager *netaddrmgr.NetAddrManager
	connManager *connmgr.ConnManager
	//	TODO:(Abelian) remove txScript, sigCache, and hashCache
	sigCache             *txscript.SigCache
	hashCache            *txscript.HashCache
	witnessCache         *txscript.WitnessCache
	rpcServer            *rpcServer
	rpcServerGetWork     *rpcServer
	syncManager          *syncmgr.SyncManager
	witnessManager       *witnessmgr.WitnessManager
	chain                *blockchain.BlockChain
	txMemPool            *mempool.TxPool
	ethash               *ethash.Ethash // todo: (ethmining)
	cpuMiner             *cpuminer.CPUMiner
	externalMiner        *externalminer.ExternalMiner
	modifyRebroadcastInv chan interface{}
	newPeers             chan *serverPeer
	donePeers            chan *serverPeer
	banPeers             chan *serverPeer
	query                chan interface{}
	relayInv             chan relayMsg
	broadcast            chan broadcastMsg
	peerHeightsUpdate    chan updatePeerHeightsMsg
	wg                   sync.WaitGroup
	quit                 chan struct{}
	nat                  NAT
	db                   database.DB
	timeSource           blockchain.MedianTimeSource
	services             wire.ServiceFlag

	communicationCache sync.Map

	// The following fields are used for optional indexes.  They will be nil
	// if the associated index is not enabled.  These fields are set during
	// initial creation of the server and never changed afterwards, so they
	// do not need to be protected for concurrent access.
	txIndex *indexers.TxIndex

	// The fee estimator keeps track of how long transactions are left in
	// the mempool before they are mined into blocks.
	feeEstimator *mempool.FeeEstimator

	// agentBlacklist is a list of blacklisted substrings by which to filter
	// user agents.
	agentBlacklist []string

	// agentWhitelist is a list of whitelisted user agent substrings, no
	// whitelisting will be applied if the list is empty or nil.
	agentWhitelist []string

	// txCacheRotator is one of the logging outputs.  It should be closed on
	// application shutdown.
	txCacheRotator *rotator.Rotator
}

// serverPeer extends the peer to maintain state shared by the server and
// the blockmanager.
type serverPeer struct {
	// The following variables must only be used atomically
	feeFilter int64

	*peer.Peer

	connReq        *connmgr.ConnReq
	server         *server
	persistent     bool
	continueHash   *chainhash.Hash
	relayMtx       sync.Mutex
	disableRelayTx bool
	sentAddrs      bool
	isWhitelisted  bool
	addressesMtx   sync.RWMutex
	knownAddresses map[string]struct{}
	banScore       connmgr.DynamicBanScore
	quit           chan struct{}
	// The following chans are used to sync blockmanager and server.
	txProcessed    chan struct{}
	blockProcessed chan struct{}
	//nsProcessed    chan struct{}
}

// newServerPeer returns a new serverPeer instance. The peer needs to be set by
// the caller.
func newServerPeer(s *server, isPersistent bool) *serverPeer {
	return &serverPeer{
		server:         s,
		persistent:     isPersistent,
		knownAddresses: make(map[string]struct{}),
		quit:           make(chan struct{}),
		txProcessed:    make(chan struct{}, 1),
		blockProcessed: make(chan struct{}, 1),
	}
}

// newestBlock returns the current best block hash and height using the format
// required by the configuration for the peer package.
func (sp *serverPeer) newestBlock() (*chainhash.Hash, int32, error) {
	best := sp.server.chain.BestSnapshot()
	return &best.Hash, best.Height, nil
}

// addKnownAddresses adds the given addresses to the set of known addresses to
// the peer to prevent sending duplicate addresses.
func (sp *serverPeer) addKnownAddresses(addresses []*wire.NetAddress) {
	sp.addressesMtx.Lock()
	for _, na := range addresses {
		sp.knownAddresses[netaddrmgr.NetAddressKey(na)] = struct{}{}
	}
	sp.addressesMtx.Unlock()
}

// addressKnown true if the given address is already known to the peer.
func (sp *serverPeer) addressKnown(na *wire.NetAddress) bool {
	sp.addressesMtx.RLock()
	_, exists := sp.knownAddresses[netaddrmgr.NetAddressKey(na)]
	sp.addressesMtx.RUnlock()
	return exists
}

// setDisableRelayTx toggles relaying of transactions for the given peer.
// It is safe for concurrent access.
func (sp *serverPeer) setDisableRelayTx(disable bool) {
	sp.relayMtx.Lock()
	sp.disableRelayTx = disable
	sp.relayMtx.Unlock()
}

// relayTxDisabled returns whether or not relaying of transactions for the given
// peer is disabled.
// It is safe for concurrent access.
func (sp *serverPeer) relayTxDisabled() bool {
	sp.relayMtx.Lock()
	isDisabled := sp.disableRelayTx
	sp.relayMtx.Unlock()

	return isDisabled
}

// pushAddrMsg sends an addr message to the connected peer using the provided
// addresses.
func (sp *serverPeer) pushAddrMsg(addresses []*wire.NetAddress) {
	// Filter addresses already known to the peer.
	addrs := make([]*wire.NetAddress, 0, len(addresses))
	for _, addr := range addresses {
		if !sp.addressKnown(addr) {
			addrs = append(addrs, addr)
		}
	}
	known, err := sp.PushAddrMsg(addrs)
	if err != nil {
		peerLog.Errorf("Can't push address message to %s: %v", sp.Peer, err)
		sp.Disconnect()
		return
	}
	sp.addKnownAddresses(known)
}

// addBanScore increases the persistent and decaying ban score fields by the
// values passed as parameters. If the resulting score exceeds half of the ban
// threshold, a warning is logged including the reason provided. Further, if
// the score is above the ban threshold, the peer will be banned and
// disconnected.
func (sp *serverPeer) addBanScore(persistent, transient uint32, reason string) bool {
	// No warning is logged and no score is calculated if banning is disabled.
	if cfg.DisableBanning {
		return false
	}
	if sp.isWhitelisted {
		peerLog.Debugf("Misbehaving whitelisted peer %s: %s", sp, reason)
		return false
	}

	warnThreshold := cfg.BanThreshold >> 1
	if transient == 0 && persistent == 0 {
		// The score is not being increased, but a warning message is still
		// logged if the score is above the warn threshold.
		score := sp.banScore.Int()
		if score > warnThreshold {
			peerLog.Warnf("Misbehaving peer %s: %s -- ban score is %d, "+
				"it was not increased this time", sp, reason, score)
		}
		return false
	}
	score := sp.banScore.Increase(persistent, transient)
	if score > warnThreshold {
		peerLog.Warnf("Misbehaving peer %s: %s -- ban score increased to %d",
			sp, reason, score)
		if score > cfg.BanThreshold {
			peerLog.Warnf("Misbehaving peer %s -- banning and disconnecting",
				sp)
			sp.server.BanPeer(sp)
			sp.Disconnect()
			return true
		}
	}
	return false
}

// hasServices returns whether or not the provided advertised service flags have
// all of the provided desired service flags set.
func hasServices(advertised, desired wire.ServiceFlag) bool {
	return advertised&desired == desired
}

// OnVersion is invoked when a peer receives a version Abelian message
// and is used to negotiate the protocol version details as well as kick start
// the communications.
func (sp *serverPeer) OnVersion(_ *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
	// Update the address manager with the advertised services for outbound
	// connections in case they have changed.  This is not done for inbound
	// connections to help prevent malicious behavior and is skipped when
	// running on the simulation test network since it is only intended to
	// connect to specified peers and actively avoids advertising and
	// connecting to discovered peers.
	//
	// NOTE: This is done before rejecting peers that are too old to ensure
	// it is updated regardless in the case a new minimum protocol version is
	// enforced and the remote node has not upgraded yet.
	isInbound := sp.Inbound()
	remoteAddr := sp.NA()
	addrManager := sp.server.addrManager
	if !cfg.SimNet && !isInbound {
		addrManager.SetServices(remoteAddr, msg.Services)
	}

	// Ignore peers that have a protocol version that is too old.  The peer
	// negotiation logic will disconnect it after this callback returns.
	if msg.ProtocolVersion < int32(peer.MinAcceptableProtocolVersion) {
		return nil
	}

	// Reject outbound peers that are not full nodes.
	wantServices := wire.SFNodeNetwork
	if !isInbound && !hasServices(msg.Services, wantServices) {
		missingServices := wantServices & ^msg.Services
		srvrLog.Debugf("Rejecting peer %s with services %v due to not "+
			"providing desired services %v", sp.Peer, msg.Services,
			missingServices)
		reason := fmt.Sprintf("required services %#x not offered",
			uint64(missingServices))
		return wire.NewMsgReject(msg.Command(), wire.RejectNonstandard, reason)
	}

	// Add the remote peer time as a sample for creating an offset against
	// the local clock to keep the network time in sync.
	sp.server.timeSource.AddTimeSample(sp.Addr(), msg.Timestamp)

	// Choose whether or not to relay transactions before a filter command
	// is received.
	sp.setDisableRelayTx(msg.DisableRelayTx)

	return nil
}

// OnVerAck is invoked when a peer receives a verack message and is used
// to kick start communication with them.
func (sp *serverPeer) OnVerAck(_ *peer.Peer, _ *wire.MsgVerAck) {
	sp.server.AddPeer(sp)
}

// OnTx is invoked when a peer receives a tx message.  It blocks
// until the transaction has been fully processed.  Unlock the block
// handler this does not serialize all transactions through a single thread
// transactions don't rely on the previous one in a linear fashion like blocks.
func (sp *serverPeer) OnTx(_ *peer.Peer, msg *wire.MsgTxAbe) {
	if cfg.BlocksOnly {
		peerLog.Tracef("Ignoring tx %v from %v - blocksonly enabled",
			msg.TxHash(), sp)
		return
	}

	// Add the transaction to the known inventory for the peer.
	// Convert the raw MsgTx to a abeutil.Tx which provides some convenience
	// methods and things such as hash caching.
	tx := abeutil.NewTxAbe(msg)
	iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
	sp.AddKnownInventory(iv)

	// Queue the transaction up to be handled by the sync manager and
	// intentionally block further receives until the transaction is fully
	// processed and known good or bad.  This helps prevent a malicious peer
	// from queuing up a bunch of bad transactions before disconnecting (or
	// being disconnected) and wasting memory.
	sp.server.syncManager.QueueTxAbe(tx, sp.Peer, sp.txProcessed)
	<-sp.txProcessed
}

// OnBlock is invoked when a peer receives a block message.  It
// blocks until the block has been fully processed.
func (sp *serverPeer) OnBlock(p *peer.Peer, msg *wire.MsgBlockAbe, buf []byte) {
	// peerLog.Debugf("Receive block %s containing %v transactions from peer %s", msg.BlockHash().String(), len(msg.Transactions), p)
	// Convert the raw MsgBlock to a abeutil.Block which provides some
	// convenience methods and things such as hash caching.
	block := abeutil.NewBlockFromBlockAndBytesAbe(msg, buf) // TODO(abe): the height of block is unknown

	// Add the block to the known inventory for the peer.
	inv := wire.InvTypeBlock
	if block.MsgBlock().HasWitness() {
		inv = wire.InvTypeWitnessBlock
	}
	iv := wire.NewInvVect(inv, block.Hash())
	sp.AddKnownInventory(iv)

	// Queue the block up to be handled by the block
	// manager and intentionally block further receives
	// until the block is fully processed and known
	// good or bad.  This helps prevent a malicious peer
	// from queuing up a bunch of bad blocks before
	// disconnecting (or being disconnected) and wasting
	// memory.  Additionally, this behavior is depended on
	// by at least the block acceptance test tool as the
	// reference implementation processes blocks in the same
	// thread and therefore blocks further messages until
	// the block has been fully processed.
	sp.server.syncManager.QueueBlockAbe(block, sp.Peer, sp.blockProcessed)
	<-sp.blockProcessed
}

func (sp *serverPeer) OnPrunedBlock(p *peer.Peer, msg *wire.MsgPrunedBlock, buf []byte) {
	// peerLog.Debugf("Receive pruned block %s containing %v transactions from peer %s", msg.BlockHash().String(), len(msg.TransactionHashes), p)
	// Convert the raw MsgBlock to a abeutil.Block which provides some
	// convenience methods and things such as hash caching.
	//block := abeutil.NewBlockFromBlockAndBytesAbe(msg, buf) // TODO(abe): the height of block is unknown
	prunedBlock := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, buf)
	blockHash := msg.BlockHash()
	// Add the block to the known inventory for the peer.
	iv := wire.NewInvVect(wire.InvTypePrunedBlock, &blockHash)
	sp.AddKnownInventory(iv)

	// Queue the block up to be handled by the block
	// manager and intentionally block further receives
	// until the block is fully processed and known
	// good or bad.  This helps prevent a malicious peer
	// from queuing up a bunch of bad blocks before
	// disconnecting (or being disconnected) and wasting
	// memory.  Additionally, this behavior is depended on
	// by at least the block acceptance test tool as the
	// reference implementation processes blocks in the same
	// thread and therefore blocks further messages until
	// the block has been fully processed.
	sp.server.syncManager.QueuePrunedBlock(prunedBlock, sp.Peer, nil)
}

func (sp *serverPeer) OnNeedSet(_ *peer.Peer, msg *wire.MsgNeedSet, buf []byte) {
	// Convert the raw MsgBlock to a abeutil.Block which provides some
	// convenience methods and things such as hash caching.
	err := sp.server.pushNeedSetResultMsg(sp, msg.BlockHash, msg.Hashes, wire.WitnessEncoding)
	if err != nil {
		// do nothing
	}
}

func (sp *serverPeer) OnNeedSetResult(p *peer.Peer, msg *wire.MsgNeedSetResult, buf []byte) {
	peerExist, reqExist := sp.server.syncManager.ExistRequestedNeedSetInPeerStates(p, msg.BlockHash)
	if !peerExist {
		peerLog.Warnf("Received pruned block message from unknown peer %s", p)
		return
	}

	// If we didn't ask for this needset then the peer is misbehaving.
	if !reqExist {
		// Disconnect with the misbehaving peer
		peerLog.Warnf("Got unrequested needset %v from %s -- "+
			"disconnecting", msg.BlockHash, p.Addr())
		p.Disconnect()
		return
	}

	defer func() {
		p.StoreNeedSetResult(msg)
		sp.server.syncManager.RemoveRequestedNeedSetInPeerStates(p, msg.BlockHash)
	}()

	// check witness in response
	for i := 0; i < len(msg.Txs); i++ {
		if !msg.Txs[i].HasWitness() {
			peerLog.Warnf("Got needset %v from %s, but some transaction in response does not has witness -- "+
				"disconnecting", msg.BlockHash, p.Addr())
			p.Disconnect()
			p.StoreNeedSetResult(nil)
			return
		}
	}

}

// OnInv is invoked when a peer receives an inv message and is
// used to examine the inventory being advertised by the remote peer and react
// accordingly.  We pass the message down to blockmanager which will call
// QueueMessage with any appropriate responses.
func (sp *serverPeer) OnInv(p *peer.Peer, msg *wire.MsgInv) {
	//if len(msg.InvList) == 0 {
	//	peerLog.Debugf("Receive inv message with empty InvList from peer %s", p)
	//} else {
	//	peerLog.Debugf("Receive inv message with length %v, type %s from peer %s", len(msg.InvList), msg.InvList[0].Type.String(), p)
	//}

	if !cfg.BlocksOnly {
		if len(msg.InvList) > 0 {
			sp.server.syncManager.QueueInv(msg, sp.Peer)
		}
		return
	}

	// when enable block only, transaction should not be received from any peer
	// so filter the inventory
	newInv := wire.NewMsgInvSizeHint(uint(len(msg.InvList)))
	for _, invVect := range msg.InvList {
		if invVect.Type == wire.InvTypeTx || invVect.Type == wire.InvTypeWitnessTx {
			peerLog.Tracef("Ignoring tx %v in inv from %v -- "+
				"blocksonly enabled", invVect.Hash, sp)
			//	BIP0037 is implemented.
			peerLog.Infof("Peer %v is announcing "+
				"transactions -- disconnecting", sp)
			sp.Disconnect()
			return
		}
		err := newInv.AddInvVect(invVect)
		if err != nil {
			peerLog.Errorf("Failed to add inventory vector: %v", err)
			break
		}
	}

	if len(newInv.InvList) > 0 {
		sp.server.syncManager.QueueInv(newInv, sp.Peer)
	}
}

// OnHeaders is invoked when a peer receives a headers
// message.  The message is passed down to the sync manager.
func (sp *serverPeer) OnHeaders(_ *peer.Peer, msg *wire.MsgHeaders) {
	sp.server.syncManager.QueueHeaders(msg, sp.Peer)
}

// OnGetData is invoked when a peer receives a getdata message and
// is used to deliver block and transaction information.
func (sp *serverPeer) OnGetData(_ *peer.Peer, msg *wire.MsgGetData) {
	numAdded := 0
	notFound := wire.NewMsgNotFound()

	length := len(msg.InvList)
	// A decaying ban score increase is applied to prevent exhausting resources
	// with unusually large inventory queries.
	// Requesting more than the maximum inventory vector length within a short
	// period of time yields a score above the default ban threshold. Sustained
	// bursts of small requests are not penalized as that would potentially ban
	// peers performing IBD.
	// This incremental score decays each minute to half of its value.
	if sp.addBanScore(0, uint32(length)*99/wire.MaxInvPerMsg, "getdata") {
		return
	}

	// We wait on this wait channel periodically to prevent queuing
	// far more data than we can send in a reasonable time, wasting memory.
	// The waiting occurs after the database fetch for the next one to
	// provide a little pipelining.
	var waitChan chan struct{}
	doneChan := make(chan struct{}, 1)

	for i, iv := range msg.InvList {
		var c chan struct{}
		// If this will be the last message we send.
		if i == length-1 && len(notFound.InvList) == 0 {
			c = doneChan
		} else if (i+1)%3 == 0 {
			// Buffered so as to not make the send goroutine block.
			c = make(chan struct{}, 1)
		}
		var err error
		switch iv.Type {
		case wire.InvTypeWitnessTx:
			err = sp.server.pushTxMsg(sp, &iv.Hash, c, waitChan, wire.WitnessEncoding)
		case wire.InvTypeTx:
			err = sp.server.pushTxMsg(sp, &iv.Hash, c, waitChan, wire.BaseEncoding)
		case wire.InvTypeWitnessBlock:
			err = sp.server.pushBlockMsgAbe(sp, &iv.Hash, c, waitChan, wire.WitnessEncoding)
		case wire.InvTypeBlock:
			err = sp.server.pushBlockMsgAbe(sp, &iv.Hash, c, waitChan, wire.BaseEncoding)
		case wire.InvTypePrunedBlock:
			err = sp.server.pushPrunedBlockMsg(sp, &iv.Hash, c, waitChan, wire.WitnessEncoding)
		default:
			peerLog.Warnf("Unknown type in inventory request %d",
				iv.Type)
			continue
		}
		if err != nil {
			notFound.AddInvVect(iv)
			// deny all subsequent requests
			if iv.Type == wire.InvTypeWitnessBlock {
				for j := i + 1; j < len(msg.InvList); j++ {
					notFound.AddInvVect(msg.InvList[j])
				}
				break
			}

			// When there is a failure fetching the final entry
			// and the done channel was sent in due to there
			// being no outstanding not found inventory, consume
			// it here because there is now not found inventory
			// that will use the channel momentarily.
			if i == len(msg.InvList)-1 && c != nil {
				<-c
			}
		}
		numAdded++
		waitChan = c
	}
	if len(notFound.InvList) != 0 {
		sp.QueueMessage(notFound, doneChan)
	}

	// Wait for messages to be sent. We can send quite a lot of data at this
	// point and this will keep the peer busy for a decent amount of time.
	// We don't process anything else by them in this time so that we
	// have an idea of when we should hear back from them - else the idle
	// timeout could fire when we were only half done sending the blocks.
	if numAdded > 0 {
		<-doneChan
	}
}

// OnGetBlocks is invoked when a peer receives a getblocks
// message.
func (sp *serverPeer) OnGetBlocks(_ *peer.Peer, msg *wire.MsgGetBlocks) {
	// Find the most recent known block in the best chain based on the block
	// locator and fetch all of the block hashes after it until either
	// wire.MaxBlocksPerMsg have been fetched or the provided stop hash is
	// encountered.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	//
	// This mirrors the behavior in the reference implementation.
	chain := sp.server.chain
	hashList, heights := chain.LocateBlocks(msg.BlockLocatorHashes, &msg.HashStop,
		wire.MaxBlocksPerMsg) // from the start node to hash stop node or max blockhash
	witnessServiceHeight := int32(0)
	if sp.server.witnessManager.NodeType() != wire.FullNode {
		witnessServiceHeight = sp.server.witnessManager.WitnessServiceHeight()
	}

	// Generate inventory message.
	invMsg := wire.NewMsgInv()
	for i := range hashList {
		inv := wire.InvTypeBlock
		if heights[i] >= witnessServiceHeight {
			inv = wire.InvTypeWitnessBlock
		}
		iv := wire.NewInvVect(inv, &hashList[i])
		invMsg.AddInvVect(iv)
	}

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

// OnGetHeaders is invoked when a peer receives a getheaders
// message.
func (sp *serverPeer) OnGetHeaders(_ *peer.Peer, msg *wire.MsgGetHeaders) {
	// Ignore getheaders requests if not in sync.
	if !sp.server.syncManager.IsCurrent() {
		//	todo (ABE) :check whether we are current, if we are not current, it means that we are busing in syning from other peers,
		//	todo (ABE) : and will not answer this GetHeader request with data.
		return
	}

	// Find the most recent known block in the best chain based on the block
	// locator and fetch all of the headers after it until either
	// wire.MaxBlockHeadersPerMsg have been fetched or the provided stop
	// hash is encountered.
	//
	// Use the block after the genesis block if no other blocks in the
	// provided locator are known.  This does mean the client will start
	// over with the genesis block if unknown block locators are provided.
	//
	// This mirrors the behavior in the reference implementation.
	chain := sp.server.chain
	headers := chain.LocateHeaders(msg.BlockLocatorHashes, &msg.HashStop)

	// Send found headers to the requesting peer.
	blockHeaders := make([]*wire.BlockHeader, len(headers))
	for i := range headers {
		blockHeaders[i] = &headers[i]
	}
	sp.QueueMessage(&wire.MsgHeaders{Headers: blockHeaders}, nil)
}

// OnFeeFilter is invoked when a peer receives a feefilter message and
// is used by remote peers to request that no transactions which have a fee rate
// lower than provided value are inventoried to them.  The peer will be
// disconnected if an invalid fee filter value is provided.
func (sp *serverPeer) OnFeeFilter(_ *peer.Peer, msg *wire.MsgFeeFilter) {
	// Check that the passed minimum fee is a valid amount.
	if msg.MinFee < 0 || msg.MinFee > int64(abeutil.MaxNeutrino) {
		peerLog.Debugf("Peer %v sent an invalid feefilter '%v' -- "+
			"disconnecting", sp, abeutil.Amount(msg.MinFee))
		sp.Disconnect()
		return
	}

	atomic.StoreInt64(&sp.feeFilter, msg.MinFee)
}

// OnGetAddr is invoked when a peer receives a getaddr Abelian message
// and is used to provide the peer with known addresses from the address
// manager.
func (sp *serverPeer) OnGetAddr(_ *peer.Peer, msg *wire.MsgGetAddr) {
	// Don't return any addresses when running on the simulation test
	// network.  This helps prevent the network from becoming another
	// public test network since it will not be able to learn about other
	// peers that have not specifically been provided.
	if cfg.SimNet {
		return
	}

	// Do not accept getaddr requests from outbound peers.  This reduces
	// fingerprinting attacks.
	if !sp.Inbound() {
		peerLog.Debugf("Ignoring getaddr request from outbound peer "+
			"%v", sp)
		return
	}

	// Only allow one getaddr request per connection to discourage
	// address stamping of inv announcements.
	if sp.sentAddrs {
		peerLog.Debugf("Ignoring repeated getaddr request from peer "+
			"%v", sp)
		return
	}
	sp.sentAddrs = true

	// Get the current known addresses from the address manager.
	addrCache := sp.server.addrManager.NetAddressCache()

	// Push the addresses.
	sp.pushAddrMsg(addrCache)
}

// OnAddr is invoked when a peer receives an addr Abelian message and is
// used to notify the server about advertised addresses.
func (sp *serverPeer) OnAddr(_ *peer.Peer, msg *wire.MsgAddr) {
	// Ignore addresses when running on the simulation test network.  This
	// helps prevent the network from becoming another public test network
	// since it will not be able to learn about other peers that have not
	// specifically been provided.
	if cfg.SimNet {
		return
	}

	// A message that has no addresses is invalid.
	if len(msg.AddrList) == 0 {
		peerLog.Errorf("Command [%s] from %s does not contain any addresses",
			msg.Command(), sp.Peer)
		sp.Disconnect()
		return
	}

	for _, na := range msg.AddrList {
		// Don't add more address if we're disconnecting.
		if !sp.Connected() {
			return
		}

		// Set the timestamp to 5 days ago if it's more than 24 hours
		// in the future so this address is one of the first to be
		// removed when space is needed.
		now := time.Now()
		if na.Timestamp.After(now.Add(time.Minute * 10)) {
			na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
		}

		// Add address to known addresses for this peer.
		sp.addKnownAddresses([]*wire.NetAddress{na})
	}

	// Add addresses to server address manager.  The address manager handles
	// the details of things such as preventing duplicate addresses, max
	// addresses, and last seen updates.
	// XXX bitcoind gives a 2 hour time penalty here, do we want to do the
	// same?
	sp.server.addrManager.AddAddresses(msg.AddrList, sp.NA())
}

// OnRead is invoked when a peer receives a message and it is used to update
// the bytes received by the server.
func (sp *serverPeer) OnRead(_ *peer.Peer, bytesRead int, msg wire.Message, err error) {
	sp.server.AddBytesReceived(uint64(bytesRead))
}

// OnWrite is invoked when a peer sends a message and it is used to update
// the bytes sent by the server.
func (sp *serverPeer) OnWrite(_ *peer.Peer, bytesWritten int, msg wire.Message, err error) {
	sp.server.AddBytesSent(uint64(bytesWritten))
}

// OnNotFound is invoked when a peer sends a notfound message.
func (sp *serverPeer) OnNotFound(p *peer.Peer, msg *wire.MsgNotFound) {
	if !sp.Connected() {
		return
	}

	var numBlocks, numTxns uint32
	for _, inv := range msg.InvList {
		switch inv.Type {
		case wire.InvTypeBlock:
			numBlocks++
		case wire.InvTypeWitnessBlock:
			numBlocks++
			peerLog.Debugf("Witness block %s notfound message from %s, disconnecting...", inv.Hash.String(), sp)
			sp.Disconnect()
			return
		case wire.InvTypeTx:
			numTxns++
		case wire.InvTypeWitnessTx:
			numTxns++
		default:
			peerLog.Debugf("Invalid inv type '%d' in notfound message from %s",
				inv.Type, sp)
			sp.Disconnect()
			return
		}
	}
	if numBlocks > 0 {
		blockStr := pickNoun(uint64(numBlocks), "block", "blocks")
		reason := fmt.Sprintf("%d %v not found", numBlocks, blockStr)
		if sp.addBanScore(20*numBlocks, 0, reason) {
			return
		}
	}
	if numTxns > 0 {
		txStr := pickNoun(uint64(numTxns), "transaction", "transactions")
		reason := fmt.Sprintf("%d %v not found", numBlocks, txStr)
		if sp.addBanScore(0, 10*numTxns, reason) {
			return
		}
	}

	sp.server.syncManager.QueueNotFound(msg, p)
}

// randomUint16Number returns a random uint16 in a specified input range.  Note
// that the range is in zeroth ordering; if you pass it 1800, you will get
// values from 0 to 1800.
func randomUint16Number(max uint16) uint16 {
	// In order to avoid modulo bias and ensure every possible outcome in
	// [0, max) has equal probability, the random number must be sampled
	// from a random source that has a range limited to a multiple of the
	// modulus.
	var randomNumber uint16
	var limitRange = (math.MaxUint16 / max) * max
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &randomNumber)
		if randomNumber < limitRange {
			return (randomNumber % max)
		}
	}
}

// AddRebroadcastInventory adds 'iv' to the list of inventories to be
// rebroadcasted at random intervals until they show up in a block.
func (s *server) AddRebroadcastInventory(iv *wire.InvVect, data interface{}) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryAdd{invVect: iv, data: data}
}

// RemoveRebroadcastInventory removes 'iv' from the list of items to be
// rebroadcasted if present.
func (s *server) RemoveRebroadcastInventory(iv *wire.InvVect) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}

	s.modifyRebroadcastInv <- broadcastInventoryDel(iv)
}

// relayTransactions generates and relays inventory vectors for all of the
// passed transactions to all connected peers.
func (s *server) relayTransactions(txns []*mempool.TxDescAbe) {
	for _, txD := range txns {
		iv := wire.NewInvVect(txD.Tx.InvType(), txD.Tx.Hash())
		s.RelayInventory(iv, txD)
	}
}

// AnnounceNewTransactions generates and relays inventory vectors and notifies
// both websocket and getblocktemplate long poll clients of the passed
// transactions.  This function should be called whenever new transactions
// are added to the mempool.
//
//	todo(ABE):
func (s *server) AnnounceNewTransactions(txns []*mempool.TxDescAbe) {
	// Generate and relay inventory vectors for all newly accepted
	// transactions.
	s.relayTransactions(txns)

	// Notify both websocket and getblocktemplate long poll clients of all
	// newly accepted transactions.
	if s.rpcServer != nil {
		s.rpcServer.NotifyNewTransactionsAbe(txns)
	}
	if s.rpcServerGetWork != nil {
		s.rpcServerGetWork.NotifyNewTransactionsAbe(txns)
	}
}

// Transaction has one confirmation on the main chain. Now we can mark it as no
// longer needing rebroadcasting.
//
//	todo(ABE):
func (s *server) TransactionConfirmed(tx *abeutil.TxAbe) {
	// Rebroadcasting is only necessary when the RPC server is active.
	if s.rpcServer == nil {
		return
	}

	iv := wire.NewInvVect(tx.InvType(), tx.Hash())
	s.RemoveRebroadcastInventory(iv)
}

// pushTxMsg sends a tx message for the provided transaction hash to the
// connected peer.  An error is returned if the transaction hash is not known.
func (s *server) pushTxMsg(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{},
	waitChan <-chan struct{}, encoding wire.MessageEncoding) error {

	var msg wire.Message
	msgCacheKey := fmt.Sprintf("tx_%s_%d", hash, encoding)
	value, ok := s.communicationCache.Load(msgCacheKey)
	if wrappedMessage, hit := value.(*wire.WrappedMessage); ok && hit {
		wrappedMessage.Use()
		msg = wrappedMessage
	} else {
		// Attempt to fetch the requested transaction from the pool.  A
		// call could be made to check for existence first, but simply trying
		// to fetch a missing transaction results in the same behavior.
		tx, err := s.txMemPool.FetchTransaction(hash)
		if err != nil {
			peerLog.Tracef("Unable to fetch tx %v from transaction "+
				"pool: %v", hash, err)

			if doneChan != nil {
				doneChan <- struct{}{}
			}
			return err
		}
		if encoding == wire.WitnessEncoding && !tx.HasWitness() {
			peerLog.Warnf("Transaction %v fetch successful but it do not has witness: %v", hash, err)

			if doneChan != nil {
				doneChan <- struct{}{}
			}
			return err
		}

		wrappedTxMsg := wire.WrapMessage(tx.MsgTx(), encoding)
		s.communicationCache.Store(msgCacheKey, wrappedTxMsg)
		wrappedTxMsg.Use()
		msg = wrappedTxMsg
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	sp.QueueMessageWithEncoding(msg, doneChan, encoding)

	return nil
}

func (s *server) pushNeedSetResultMsg(sp *serverPeer, blockHash chainhash.Hash,
	txHashes []chainhash.Hash, encoding wire.MessageEncoding) error {

	block, err := sp.server.chain.BlockByHashAbe(&blockHash)
	if err != nil {
		sp.PushRejectMsg(wire.CmdNeedSet, wire.RejectInvalid, "invalid block hash", &blockHash, false)
		return err
	}
	originTxs := block.Transactions()
	txhashMap := make(map[chainhash.Hash]*abeutil.TxAbe)
	for i := 0; i < len(originTxs); i++ {
		txhash := originTxs[i].Hash()
		txhashMap[*txhash] = originTxs[i]
	}
	rtxs := make([]*wire.MsgTxAbe, len(txHashes))
	for i, txhash := range txHashes {
		rtxs[i] = txhashMap[txhash].MsgTx()
	}
	resMsg := wire.NewMsgNeedSetResult(blockHash, rtxs)

	sp.QueueMessageWithEncoding(resMsg, nil, encoding)
	//sp.QueueMessageWithEncoding(block.MsgBlock(), doneChan, encoding)
	//sp.PushRejectMsg(wire.CmdNeedSet, wire.RejectInvalid, "invalid block hash", &blockHash, false)

	return nil
}

// pushBlockMsg sends a block message for the provided block hash to the
// connected peer.  An error is returned if the block hash is not known.
//
//	todo(ABE):
func (s *server) pushBlockMsg(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{},
	waitChan <-chan struct{}, encoding wire.MessageEncoding) error {

	// Fetch the raw block bytes from the database.
	var blockBytes []byte
	err := sp.server.db.View(func(dbTx database.Tx) error {
		var err error
		blockBytes, err = dbTx.FetchBlock(hash)
		return err
	})
	if err != nil {
		peerLog.Tracef("Unable to fetch requested block hash %v: %v",
			hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Deserialize the block.
	var msgBlock wire.MsgBlockAbe
	err = msgBlock.Deserialize(bytes.NewReader(blockBytes))
	if err != nil {
		peerLog.Tracef("Unable to deserialize requested block hash "+
			"%v: %v", hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// We only send the channel for this message if we aren't sending
	// an inv straight after.
	//	todo(ABE): ?
	//  answer: the block may be sent in batches, use this variable to record the location of the next tranfer
	//         beacuse last Inv message just contain the last batches, so next batches will send a inv message
	var dc chan<- struct{}
	continueHash := sp.continueHash // the last hash
	// if it is nil or cur hash do not equal the continue hash, the sendInv will be false
	sendInv := continueHash != nil && continueHash.IsEqual(hash)
	if !sendInv { // if the sendInv is false, the the dc is doneChan else dc is nil
		dc = doneChan // and the dc is nil means that do not finish the request
	}
	//	todo (ABE): as the block is fetched from database, the witness may not be included. If so, regardless of encoding, no witness is provided.
	sp.QueueMessageWithEncoding(&msgBlock, dc, encoding)

	// When the peer requests the final block that was advertised in
	// response to a getblocks message which requested more blocks than
	// would fit into a single message, send it a new inventory message
	// to trigger it to issue another getblocks message for the next
	// batch of inventory.
	if sendInv { // if the sendInv is true, update the continueHash
		best := sp.server.chain.BestSnapshot()
		invMsg := wire.NewMsgInvSizeHint(1)
		iv := wire.NewInvVect(wire.InvTypeBlock, &best.Hash) // best block hash
		invMsg.AddInvVect(iv)                                //just contain a message
		sp.QueueMessage(invMsg, doneChan)
		sp.continueHash = nil
	}
	return nil
}

// server.cache wire.Message + []byte
func (s *server) pushBlockMsgAbe(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{},
	waitChan <-chan struct{}, encoding wire.MessageEncoding) error {
	var msg wire.Message
	msgCacheKey := fmt.Sprintf("block_%s_%d", hash, encoding)
	value, ok := s.communicationCache.Load(msgCacheKey)
	if wrappedMessage, hit := value.(*wire.WrappedMessage); ok && hit {
		wrappedMessage.Use()
		msg = wrappedMessage
	} else {
		// Fetch the raw block bytes from the database.
		var blockBytes []byte
		var witnesses [][]byte
		err := sp.server.db.View(func(dbTx database.Tx) error {
			var err error
			if encoding == wire.BaseEncoding {
				blockBytes, err = dbTx.FetchBlockWithoutWitness(hash)
			} else {
				blockBytes, witnesses, err = dbTx.FetchBlockAbe(hash)
			}
			return err
		})
		if err != nil {
			peerLog.Tracef("Unable to fetch requested block hash %v: %v",
				hash, err)

			if doneChan != nil {
				doneChan <- struct{}{}
			}
			return err
		}

		var msgBlock wire.MsgBlockAbe
		// Deserialize the block.
		err = msgBlock.DeserializeNoWitness(bytes.NewReader(blockBytes))
		if err != nil {
			peerLog.Tracef("Unable to deserialize requested block hash "+
				"%v: %v", hash, err)

			if doneChan != nil {
				doneChan <- struct{}{}
			}
			return err
		}

		if len(witnesses) != 0 {
			txs := msgBlock.Transactions
			for i := 0; i < len(txs); i++ {
				txs[i].TxWitness = witnesses[i][chainhash.HashSize:]
			}
		}

		if encoding == wire.WitnessEncoding && !msgBlock.HasWitness() {
			peerLog.Debugf("Peer %v request witness block %v but we do not have witness", sp, hash.String())
			// Once we have fetched data wait for any previous operation to finish.
			if waitChan != nil {
				<-waitChan
			}
			return errors.New("witness block not found")
		}

		wrappedBlockMsg := wire.WrapMessage(&msgBlock, encoding)
		s.communicationCache.Store(msgCacheKey, wrappedBlockMsg)
		wrappedBlockMsg.Use()
		msg = wrappedBlockMsg
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// We only send the channel for this message if we aren't sending
	// an inv straight after.
	//	todo(ABE): ?
	//  answer: the block may be sent in batches, use this variable to record the location of the next tranfer
	//         beacuse last Inv message just contain the last batches, so next batches will send a inv message
	var dc chan<- struct{}
	continueHash := sp.continueHash // the last hash
	// if it is nil or cur hash do not equal the continue hash, the sendInv will be false
	sendInv := continueHash != nil && continueHash.IsEqual(hash)
	if !sendInv { // if the sendInv is false, the the dc is doneChan else dc is nil
		dc = doneChan // and the dc is nil means that do not finish the request
	}

	sp.QueueMessageWithEncoding(msg, dc, encoding)

	// When the peer requests the final block that was advertised in
	// response to a getblocks message which requested more blocks than
	// would fit into a single message, send it a new inventory message
	// to trigger it to issue another getblocks message for the next
	// batch of inventory.
	if sendInv { // if the sendInv is true, update the continueHash
		best := sp.server.chain.BestSnapshot()
		invMsg := wire.NewMsgInvSizeHint(1)
		iv := wire.NewInvVect(wire.InvTypeWitnessBlock, &best.Hash) // best block hash
		invMsg.AddInvVect(iv)                                       //just contain a message
		sp.QueueMessage(invMsg, doneChan)
		sp.continueHash = nil
	}
	return nil
}

func (s *server) pushPrunedBlockMsg(sp *serverPeer, hash *chainhash.Hash, doneChan chan<- struct{},
	waitChan <-chan struct{}, encoding wire.MessageEncoding) error {

	// Fetch the raw block bytes from the database.
	var blockBytes []byte
	var witnessBytes [][]byte
	err := sp.server.db.View(func(dbTx database.Tx) error {
		var err error
		blockBytes, witnessBytes, err = dbTx.FetchBlockAbe(hash)
		return err
	})
	if err != nil {
		peerLog.Tracef("Unable to fetch requested block hash %v: %v",
			hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Deserialize the block.
	var msgBlock wire.MsgBlockAbe
	err = msgBlock.DeserializeNoWitness(bytes.NewReader(blockBytes))
	if err != nil {
		peerLog.Tracef("Unable to deserialize requested block hash "+
			"%v: %v", hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	if witnessBytes != nil {
		txs := msgBlock.Transactions
		for i := 0; i < len(txs); i++ {
			txs[i].TxWitness = witnessBytes[i][chainhash.HashSize:]
		}
	}

	msgPrunedBlock, err := wire.NewMsgBlockPrunedFromMsgBlockAbe(&msgBlock)
	if err != nil {
		peerLog.Tracef("Unable to deserialize requested block hash "+
			"%v: %v", hash, err)

		if doneChan != nil {
			doneChan <- struct{}{}
		}
		return err
	}

	// Once we have fetched data wait for any previous operation to finish.
	if waitChan != nil {
		<-waitChan
	}

	// We only send the channel for this message if we aren't sending
	// an inv straight after.
	//	todo(ABE): ?
	//  answer: the block may be sent in batches, use this variable to record the location of the next tranfer
	//         beacuse last Inv message just contain the last batches, so next batches will send a inv message
	var dc chan<- struct{}
	continueHash := sp.continueHash // the last hash
	// if it is nil or cur hash do not equal the continue hash, the sendInv will be false
	sendInv := continueHash != nil && continueHash.IsEqual(hash)
	if !sendInv { // if the sendInv is false, the the dc is doneChan else dc is nil
		dc = doneChan // and the dc is nil means that do not finish the request
	}
	//	todo (ABE): as the block is fetched from database, the witness may not be included. If so, regardless of encoding, no witness is provided.
	sp.QueueMessageWithEncoding(msgPrunedBlock, dc, encoding)

	return nil
}

// handleUpdatePeerHeight updates the heights of all peers who were known to
// announce a block we recently accepted.
func (s *server) handleUpdatePeerHeights(state *peerState, umsg updatePeerHeightsMsg) {
	state.forAllPeers(func(sp *serverPeer) {
		// The origin peer should already have the updated height.
		if sp.Peer == umsg.originPeer {
			return
		}

		// This is a pointer to the underlying memory which doesn't
		// change.
		latestBlkHash := sp.LastAnnouncedBlock()

		// Skip this peer if it hasn't recently announced any new blocks.
		if latestBlkHash == nil {
			return
		}

		// If the peer has recently announced a block, and this block
		// matches our newly accepted block, then update their block
		// height.
		if *latestBlkHash == *umsg.newHash {
			sp.UpdateLastBlockHeight(umsg.newHeight)
			sp.UpdateLastAnnouncedBlock(nil)
			if umsg.newHeight > sp.AnnouncedHeight() {
				sp.UpdateAnnouncedHeight(umsg.newHeight)
			}
		}
	})
}

// handleAddPeerMsg deals with adding new peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleAddPeerMsg(state *peerState, sp *serverPeer) bool {
	if sp == nil || !sp.Connected() {
		return false
	}

	// Disconnect peers with unwanted user agents.
	if sp.HasUndesiredUserAgent(s.agentBlacklist, s.agentWhitelist) {
		sp.Disconnect()
		return false
	}

	// Ignore new peers if we're shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		srvrLog.Infof("New peer %s ignored - server is shutting down", sp)
		sp.Disconnect()
		return false
	}

	// Disconnect banned peers.
	host, _, err := net.SplitHostPort(sp.Addr())
	if err != nil {
		srvrLog.Debugf("can't split hostport %v", err)
		sp.Disconnect()
		return false
	}
	if banEnd, ok := state.banned[host]; ok {
		if time.Now().Before(banEnd) {
			srvrLog.Debugf("Peer %s is banned for another %v - disconnecting",
				host, time.Until(banEnd))
			sp.Disconnect()
			return false
		}

		srvrLog.Infof("Peer %s is no longer banned", host)
		delete(state.banned, host)
	}

	// TODO: Check for max peers from a single IP.

	// Limit max number of total peers.
	if state.Count() >= cfg.MaxPeers {
		srvrLog.Infof("Max peers reached [%d] - disconnecting peer %s",
			cfg.MaxPeers, sp)
		sp.Disconnect()
		// TODO: how to handle permanent peers here?
		// they should be rescheduled.
		return false
	}

	// Add the new peer and start it.
	srvrLog.Debugf("New peer %s (Last block height: %v, Witness Service Height: %v)", sp, sp.LastBlock(),
		sp.WitnessServiceHeight())
	if sp.Inbound() {
		state.inboundPeers[sp.ID()] = sp
	} else {
		state.outboundGroups[netaddrmgr.GroupKey(sp.NA())]++
		if sp.persistent {
			state.persistentPeers[sp.ID()] = sp
		} else {
			state.outboundPeers[sp.ID()] = sp
		}
	}

	// Update the address' last seen time if the peer has acknowledged
	// our version and has sent us its version as well.
	if sp.VerAckReceived() && sp.VersionKnown() && sp.NA() != nil {
		s.addrManager.Connected(sp.NA())
	}

	// Signal the sync manager this peer is a new sync candidate.
	s.syncManager.NewPeer(sp.Peer)

	// Update the address manager and request known addresses from the
	// remote peer for outbound connections. This is skipped when running on
	// the simulation test network since it is only intended to connect to
	// specified peers and actively avoids advertising and connecting to
	// discovered peers.
	if !cfg.SimNet && !sp.Inbound() {
		// Advertise the local address when the server accepts incoming
		// connections and it believes itself to be close to the best
		// known tip.
		if !cfg.DisableListen && s.syncManager.IsCurrent() {
			// Get address that best matches.
			lna := s.addrManager.GetBestLocalAddress(sp.NA())
			if netaddrmgr.IsRoutable(lna) {
				// Filter addresses the peer already knows about.
				addresses := []*wire.NetAddress{lna}
				sp.pushAddrMsg(addresses)
			}
		}

		// Request known addresses if the server address manager needs more.
		if s.addrManager.NeedMoreNetAddresses() {
			sp.QueueMessage(wire.NewMsgGetAddr(), nil)
		}

		// Mark the address as a known good address.
		s.addrManager.Good(sp.NA())

	}

	return true
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It is
// invoked from the peerHandler goroutine.
func (s *server) handleDonePeerMsg(state *peerState, sp *serverPeer) {
	var list map[int32]*serverPeer
	if sp.persistent {
		list = state.persistentPeers
	} else if sp.Inbound() {
		list = state.inboundPeers
	} else {
		list = state.outboundPeers
	}

	// Regardless of whether the peer was found in our list, we'll inform
	// our connection manager about the disconnection. This can happen if we
	// process a peer's `done` message before its `add`.
	if !sp.Inbound() {
		if sp.persistent {
			s.connManager.Disconnect(sp.connReq.ID())
		} else {
			s.connManager.Remove(sp.connReq.ID())
			go s.connManager.NewConnReq()
		}
	}

	if _, ok := list[sp.ID()]; ok {
		if !sp.Inbound() && sp.VersionKnown() {
			state.outboundGroups[netaddrmgr.GroupKey(sp.NA())]--
		}
		delete(list, sp.ID())
		srvrLog.Debugf("Removed peer %s", sp)
		return
	}
}

// handleBanPeerMsg deals with banning peers.  It is invoked from the
// peerHandler goroutine.
func (s *server) handleBanPeerMsg(state *peerState, sp *serverPeer) {
	host, _, err := net.SplitHostPort(sp.Addr())
	if err != nil {
		srvrLog.Debugf("can't split ban peer %s %v", sp.Addr(), err)
		return
	}
	direction := directionString(sp.Inbound())
	srvrLog.Infof("Banned peer %s (%s) for %v", host, direction,
		cfg.BanDuration)
	state.banned[host] = time.Now().Add(cfg.BanDuration)
}

// handleRelayInvMsg deals with relaying inventory to peers that are not already
// known to have it.  It is invoked from the peerHandler goroutine.
func (s *server) handleRelayInvMsg(state *peerState, msg relayMsg) {
	state.forAllPeers(func(sp *serverPeer) {
		if !sp.Connected() {
			return // Why the message can not pass there?
		}

		// If the inventory is a block and the peer prefers headers,
		// generate and send a headers message instead of an inventory
		// message.
		if sp.WantsHeaders() && (msg.invVect.Type == wire.InvTypeBlock ||
			msg.invVect.Type == wire.InvTypePrunedBlock ||
			msg.invVect.Type == wire.InvTypeWitnessBlock) {
			blockHeader, ok := msg.data.(wire.BlockHeader)
			if !ok {
				peerLog.Warnf("Underlying data for headers" +
					" is not a block header")
				return
			}
			msgHeaders := wire.NewMsgHeaders()
			if err := msgHeaders.AddBlockHeader(&blockHeader); err != nil {
				peerLog.Errorf("Failed to add block"+
					" header: %v", err)
				return
			}
			sp.QueueMessage(msgHeaders, nil)
			return
		}

		if msg.invVect.Type == wire.InvTypeTx || msg.invVect.Type == wire.InvTypeWitnessTx {
			// Don't relay the transaction to the peer when it has
			// transaction relaying disabled.
			if sp.relayTxDisabled() {
				return
			}

			txD, ok := msg.data.(*mempool.TxDescAbe) //the type must right
			if !ok {
				peerLog.Warnf("Underlying data for tx inv "+
					"relay is not a *mempool.TxDescAbe: %T",
					msg.data)
				return
			}

			// Don't relay the transaction if the transaction fee-per-kb
			// is less than the peer's feefilter.
			feeFilter := atomic.LoadInt64(&sp.feeFilter)
			if feeFilter > 0 && txD.FeePerKB < uint64(feeFilter) {
				peerLog.Warnf("Transaction fee-per-kb is less than peer's feefilter so that it is not relayed: %T",
					msg.data)
				return
			}

		}

		// Queue the inventory to be relayed with the next batch.
		// It will be ignored if the peer is already known to
		// have the inventory.
		// peerLog.Debugf("Send inv message type %s, hash %s to peer %s", msg.invVect.Type.String(), msg.invVect.Hash.String(), sp)
		sp.QueueInventory(msg.invVect)
	})
}

// handleBroadcastMsg deals with broadcasting messages to peers.  It is invoked
// from the peerHandler goroutine.
func (s *server) handleBroadcastMsg(state *peerState, bmsg *broadcastMsg) {
	state.forAllPeers(func(sp *serverPeer) {
		if !sp.Connected() {
			return
		}

		for _, ep := range bmsg.excludePeers {
			if sp == ep {
				return
			}
		}

		sp.QueueMessage(bmsg.message, nil)
	})
}

type getConnCountMsg struct {
	reply chan int32
}

type getPeersMsg struct {
	reply chan []*serverPeer
}

type getOutboundGroup struct {
	key   string
	reply chan int
}

type getAddedNodesMsg struct {
	reply chan []*serverPeer
}

type disconnectNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

type connectNodeMsg struct {
	addr      string
	permanent bool
	reply     chan error
}

type removeNodeMsg struct {
	cmp   func(*serverPeer) bool
	reply chan error
}

// handleQuery is the central handler for all queries and commands from other
// goroutines related to peer state.
func (s *server) handleQuery(state *peerState, querymsg interface{}) {
	switch msg := querymsg.(type) {
	case getConnCountMsg:
		nconnected := int32(0)
		state.forAllPeers(func(sp *serverPeer) {
			if sp.Connected() {
				nconnected++
			}
		})
		msg.reply <- nconnected

	case getPeersMsg:
		peers := make([]*serverPeer, 0, state.Count())
		state.forAllPeers(func(sp *serverPeer) {
			if !sp.Connected() {
				return
			}
			peers = append(peers, sp)
		})
		msg.reply <- peers

	case connectNodeMsg:
		// TODO: duplicate oneshots?
		// Limit max number of total peers.
		if state.Count() >= cfg.MaxPeers {
			msg.reply <- errors.New("max peers reached")
			return
		}
		for _, peer := range state.persistentPeers {
			if peer.Addr() == msg.addr {
				if msg.permanent {
					msg.reply <- errors.New("peer already connected")
				} else {
					msg.reply <- errors.New("peer exists as a permanent peer")
				}
				return
			}
		}

		netAddr, err := addrStringToNetAddr(msg.addr)
		if err != nil {
			msg.reply <- err
			return
		}

		// TODO: if too many, nuke a non-perm peer.
		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      netAddr,
			Permanent: msg.permanent,
		})
		msg.reply <- nil
	case removeNodeMsg:
		found := disconnectPeer(state.persistentPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[netaddrmgr.GroupKey(sp.NA())]--
		})

		if found {
			msg.reply <- nil
		} else {
			msg.reply <- errors.New("peer not found")
		}
	case getOutboundGroup:
		count, ok := state.outboundGroups[msg.key]
		if ok {
			msg.reply <- count
		} else {
			msg.reply <- 0
		}
	// Request a list of the persistent (added) peers.
	case getAddedNodesMsg:
		// Respond with a slice of the relevant peers.
		peers := make([]*serverPeer, 0, len(state.persistentPeers))
		for _, sp := range state.persistentPeers {
			peers = append(peers, sp)
		}
		msg.reply <- peers
	case disconnectNodeMsg:
		// Check inbound peers. We pass a nil callback since we don't
		// require any additional actions on disconnect for inbound peers.
		found := disconnectPeer(state.inboundPeers, msg.cmp, nil)
		if found {
			msg.reply <- nil
			return
		}

		// Check outbound peers.
		found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
			// Keep group counts ok since we remove from
			// the list now.
			state.outboundGroups[netaddrmgr.GroupKey(sp.NA())]--
		})
		if found {
			// If there are multiple outbound connections to the same
			// ip:port, continue disconnecting them all until no such
			// peers are found.
			for found {
				found = disconnectPeer(state.outboundPeers, msg.cmp, func(sp *serverPeer) {
					state.outboundGroups[netaddrmgr.GroupKey(sp.NA())]--
				})
			}
			msg.reply <- nil
			return
		}

		msg.reply <- errors.New("peer not found")
	}
}

// disconnectPeer attempts to drop the connection of a targeted peer in the
// passed peer list. Targets are identified via usage of the passed
// `compareFunc`, which should return `true` if the passed peer is the target
// peer. This function returns true on success and false if the peer is unable
// to be located. If the peer is found, and the passed callback: `whenFound'
// isn't nil, we call it with the peer as the argument before it is removed
// from the peerList, and is disconnected from the server.
func disconnectPeer(peerList map[int32]*serverPeer, compareFunc func(*serverPeer) bool, whenFound func(*serverPeer)) bool {
	for addr, peer := range peerList {
		if compareFunc(peer) {
			if whenFound != nil {
				whenFound(peer)
			}

			// This is ok because we are not continuing
			// to iterate so won't corrupt the loop.
			delete(peerList, addr)
			peer.Disconnect()
			return true
		}
	}
	return false
}

// newPeerConfig returns the configuration for the given serverPeer.
func newPeerConfig(sp *serverPeer) *peer.Config {
	return &peer.Config{
		Listeners: peer.MessageListeners{
			OnVersion:       sp.OnVersion,
			OnVerAck:        sp.OnVerAck,
			OnTx:            sp.OnTx,
			OnBlock:         sp.OnBlock,
			OnPrunedBlock:   sp.OnPrunedBlock,
			OnNeedSet:       sp.OnNeedSet,
			OnNeedSetResult: sp.OnNeedSetResult,
			OnInv:           sp.OnInv,
			OnHeaders:       sp.OnHeaders,
			OnGetData:       sp.OnGetData,
			OnGetBlocks:     sp.OnGetBlocks,
			OnGetHeaders:    sp.OnGetHeaders,
			OnFeeFilter:     sp.OnFeeFilter,
			OnGetAddr:       sp.OnGetAddr,
			OnAddr:          sp.OnAddr,
			OnRead:          sp.OnRead,
			OnWrite:         sp.OnWrite,
			OnNotFound:      sp.OnNotFound,

			// Note: The reference client currently bans peers that send alerts
			// not signed with its key.  We could verify against their key, but
			// since the reference client is currently unwilling to support
			// other implementations' alert messages, we will not relay theirs.
			OnAlert: nil,
		},
		NewestBlock:        sp.newestBlock,
		HostToNetAddress:   sp.server.addrManager.HostToNetAddress,
		Proxy:              cfg.Proxy,
		UserAgentName:      userAgentName,
		UserAgentVersion:   userAgentVersion,
		UserAgentComments:  cfg.UserAgentComments,
		ChainParams:        sp.server.chainParams,
		Services:           sp.server.services,
		DisableRelayTx:     cfg.BlocksOnly,
		ProtocolVersion:    peer.MaxProtocolVersion,
		TrickleInterval:    cfg.TrickleInterval,
		Chain:              sp.server.chain,
		CommunicationCache: &sp.server.communicationCache,
	}
}

// inboundPeerConnected is invoked by the connection manager when a new inbound
// connection is established.  It initializes a new inbound server peer
// instance, associates it with the connection, and starts a goroutine to wait
// for disconnection.
func (s *server) inboundPeerConnected(conn net.Conn) {
	sp := newServerPeer(s, false)
	sp.isWhitelisted = isWhitelisted(conn.RemoteAddr())
	sp.Peer = peer.NewInboundPeer(newPeerConfig(sp))
	sp.AssociateConnection(conn)
	go s.peerDoneHandler(sp)
}

// outboundPeerConnected is invoked by the connection manager when a new
// outbound connection is established.  It initializes a new outbound server
// peer instance, associates it with the relevant state such as the connection
// request instance and the connection itself, and finally notifies the address
// manager of the attempt.
func (s *server) outboundPeerConnected(c *connmgr.ConnReq, conn net.Conn) {
	// create a serverPeer containing Peer
	sp := newServerPeer(s, c.Permanent)
	p, err := peer.NewOutboundPeer(newPeerConfig(sp), c.Addr.String())
	if err != nil {
		srvrLog.Debugf("Cannot create outbound peer %s: %v", c.Addr, err)
		if c.Permanent {
			s.connManager.Disconnect(c.ID())
		} else {
			s.connManager.Remove(c.ID())
			go s.connManager.NewConnReq()
		}
		return
	}
	sp.Peer = p
	sp.connReq = c // binding the conn and sp
	sp.isWhitelisted = isWhitelisted(conn.RemoteAddr())
	sp.AssociateConnection(conn)
	go s.peerDoneHandler(sp) //send or receive some signs when peer disconnect
}

// peerDoneHandler handles peer disconnects by notifiying the server that it's
// done along with other performing other desirable cleanup.
func (s *server) peerDoneHandler(sp *serverPeer) {
	sp.WaitForDisconnect() // wait for signs meaning peer disconnect
	s.donePeers <- sp      // the other endpoint of this channel is server.peerHandler

	// Only tell sync manager we are gone if we ever told it we existed.
	if sp.VerAckReceived() { // utility the "true" of readremoteVersionMsg
		s.syncManager.DonePeer(sp.Peer) // send a sign to syncManager to stop the sync process

		// Evict any remaining orphans that were sent by the peer.
		numEvicted := s.txMemPool.RemoveOrphansByTag(mempool.Tag(sp.ID()))
		if numEvicted > 0 {
			txmpLog.Debugf("Evicted %d %s from peer %v (id %d)",
				numEvicted, pickNoun(numEvicted, "orphan",
					"orphans"), sp, sp.ID())
		}
	}
	close(sp.quit) // send a sign to server, the other endpoint of this channel is server.peerHandler
}

// peerHandler is used to handle peer operations such as adding and removing
// peers to and from the server, banning peers, and broadcasting messages to
// peers.  It must be run in a goroutine.
func (s *server) peerHandler() {
	// Start the address manager and sync manager, both of which are needed
	// by peers.  This is done here since their lifecycle is closely tied
	// to this handler and rather than adding more channels to synchronize
	// things, it's easier and slightly faster to simply start and stop them
	// in this handler.
	s.addrManager.Start() // address manager, not containing transports
	s.syncManager.Start() // data sync between peers

	srvrLog.Tracef("Starting peer handler")

	state := &peerState{
		inboundPeers:    make(map[int32]*serverPeer),
		persistentPeers: make(map[int32]*serverPeer),
		outboundPeers:   make(map[int32]*serverPeer),
		banned:          make(map[string]time.Time),
		outboundGroups:  make(map[string]int),
	}

	if !cfg.DisableDNSSeed {
		// Add peers discovered through DNS to the address manager.
		connmgr.SeedFromDNS(activeNetParams.Params, defaultRequiredServices,
			abecLookup, func(addrs []*wire.NetAddress) {
				//	todo (ABE): 20210731
				// Bitcoind uses a lookup of the dns seeder here. This
				// is rather strange since the values looked up by the
				// DNS seed lookups will vary quite a lot.
				// to replicate this behaviour we put all addresses as
				// having come from the first one.
				s.addrManager.AddAddresses(addrs, addrs[0])
			})
	}

	// todo(ABE): why here is "go s.connManager.Start()" rather than "s.connManager.Start()"
	// osy: When the node is closed, need to handle the network source,
	// if the conn manager also close, the source will be can not control
	go s.connManager.Start() // connect manager depending the peeraddress

out:
	for {
		select {
		// New peers connected to the server.
		case p := <-s.newPeers:
			s.handleAddPeerMsg(state, p)

		// Disconnected peers.
		case p := <-s.donePeers:
			s.handleDonePeerMsg(state, p)

		// Block accepted in mainchain or orphan, update peer height.
		case umsg := <-s.peerHeightsUpdate:
			s.handleUpdatePeerHeights(state, umsg)

		// Peer to ban.
		case p := <-s.banPeers:
			s.handleBanPeerMsg(state, p)

		// New inventory to potentially be relayed to other peers.
		case invMsg := <-s.relayInv: //relay to other peers
			s.handleRelayInvMsg(state, invMsg)

		// Message to broadcast to all connected peers except those
		// which are excluded by the message.
		case bmsg := <-s.broadcast:
			s.handleBroadcastMsg(state, &bmsg)

		case qmsg := <-s.query:
			s.handleQuery(state, qmsg)

		case <-s.quit:
			// Disconnect all peers on server shutdown.
			state.forAllPeers(func(sp *serverPeer) {
				srvrLog.Tracef("Shutdown peer %s", sp)
				sp.Disconnect()
			})
			break out
		}
	}

	s.connManager.Stop()
	s.syncManager.Stop()
	s.addrManager.Stop()

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.newPeers:
		case <-s.donePeers:
		case <-s.peerHeightsUpdate:
		case <-s.relayInv:
		case <-s.broadcast:
		case <-s.query:
		default:
			break cleanup
		}
	}
	s.wg.Done()
	srvrLog.Tracef("Peer handler done")
}

// AddPeer adds a new peer that has already been connected to the server.
func (s *server) AddPeer(sp *serverPeer) {
	s.newPeers <- sp
}

// BanPeer bans a peer that has already been connected to the server by ip.
func (s *server) BanPeer(sp *serverPeer) {
	s.banPeers <- sp
}

// RelayInventory relays the passed inventory vector to all connected peers
// that are not already known to have it.
func (s *server) RelayInventory(invVect *wire.InvVect, data interface{}) {
	//if invVect.Type==wire.InvTypeTx || invVect.Type==wire.InvTypeWitnessTx{
	//	fmt.Printf("relay a transaction with hash : %v\n",invVect.Hash)
	//	fmt.Printf("And the value is : %v\n",data)
	//}
	s.relayInv <- relayMsg{invVect: invVect, data: data}
}

// BroadcastMessage sends msg to all peers currently connected to the server
// except those in the passed peers to exclude.
func (s *server) BroadcastMessage(msg wire.Message, exclPeers ...*serverPeer) {
	// XXX: Need to determine if this is an alert that has already been
	// broadcast and refrain from broadcasting again.
	bmsg := broadcastMsg{message: msg, excludePeers: exclPeers}
	s.broadcast <- bmsg
}

// ConnectedCount returns the number of currently connected peers.
func (s *server) ConnectedCount() int32 {
	replyChan := make(chan int32)

	s.query <- getConnCountMsg{reply: replyChan}

	return <-replyChan
}

// OutboundGroupCount returns the number of peers connected to the given
// outbound group key.
func (s *server) OutboundGroupCount(key string) int {
	replyChan := make(chan int)
	s.query <- getOutboundGroup{key: key, reply: replyChan}
	return <-replyChan
}

// AddBytesSent adds the passed number of bytes to the total bytes sent counter
// for the server.  It is safe for concurrent access.
func (s *server) AddBytesSent(bytesSent uint64) {
	atomic.AddUint64(&s.bytesSent, bytesSent)
}

// AddBytesReceived adds the passed number of bytes to the total bytes received
// counter for the server.  It is safe for concurrent access.
func (s *server) AddBytesReceived(bytesReceived uint64) {
	atomic.AddUint64(&s.bytesReceived, bytesReceived)
}

// NetTotals returns the sum of all bytes received and sent across the network
// for all peers.  It is safe for concurrent access.
func (s *server) NetTotals() (uint64, uint64) {
	return atomic.LoadUint64(&s.bytesReceived),
		atomic.LoadUint64(&s.bytesSent)
}

// UpdatePeerHeights updates the heights of all peers who have have announced
// the latest connected main chain block, or a recognized orphan. These height
// updates allow us to dynamically refresh peer heights, ensuring sync peer
// selection has access to the latest block heights for each peer.
func (s *server) UpdatePeerHeights(latestBlkHash *chainhash.Hash, latestHeight int32, updateSource *peer.Peer) {
	s.peerHeightsUpdate <- updatePeerHeightsMsg{
		newHash:    latestBlkHash,
		newHeight:  latestHeight,
		originPeer: updateSource,
	}
}

// rebroadcastHandler keeps track of user submitted inventories that we have
// sent out but have not yet made it into a block. We periodically rebroadcast
// them in case our peers restarted or otherwise lost track of them.
func (s *server) rebroadcastHandler() {
	// Wait 5 min before first tx rebroadcast.
	timer := time.NewTimer(5 * time.Minute) //5 minute
	pendingInvs := make(map[wire.InvVect]interface{})

out:
	for {
		select {
		case riv := <-s.modifyRebroadcastInv:
			switch msg := riv.(type) {
			// Incoming InvVects are added to our map of RPC txs.
			case broadcastInventoryAdd:
				pendingInvs[*msg.invVect] = msg.data

			// When an InvVect has been added to a block, we can
			// now remove it, if it was present.
			case broadcastInventoryDel:
				delete(pendingInvs, *msg)
			}

		case <-timer.C:
			// Any inventory we have has not made it into a block
			// yet. We periodically resubmit them until they have.
			for iv, data := range pendingInvs {
				ivCopy := iv
				s.RelayInventory(&ivCopy, data)
			}

			// Process at a random time up to 30mins (in seconds)
			// in the future.
			timer.Reset(time.Second *
				time.Duration(randomUint16Number(1800)))

		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	// Drain channels before exiting so nothing is left waiting around
	// to send.
cleanup:
	for {
		select {
		case <-s.modifyRebroadcastInv:
		default:
			break cleanup
		}
	}
	s.wg.Done()
}

// Start begins accepting connections from peers.
func (s *server) Start() {
	// Already started?
	if atomic.AddInt32(&s.started, 1) != 1 {
		return
	}

	srvrLog.Trace("Starting server")

	// Server startup time. Used for the uptime command for uptime calculation.
	s.startupTime = time.Now().Unix()

	// Start the peer handler which in turn starts the address and block
	// managers.
	s.wg.Add(1)
	go s.peerHandler() //about three key start :peer addrManager syncManager connManager

	if s.nat != nil {
		s.wg.Add(1)
		go s.upnpUpdateThread()
	}

	if !cfg.DisableRPC {
		s.wg.Add(1)

		// Start the rebroadcastHandler, which ensures user tx received by
		// the RPC server are rebroadcast until being included in a block.
		go s.rebroadcastHandler()

		s.rpcServer.Start()
	}

	if cfg.EnableGetWorkRPC {
		s.rpcServerGetWork.Start()
	}

	// Start the CPU miner if generation is enabled.
	if cfg.Generate {
		s.cpuMiner.Start() //if the config contains mining flag, then start mining
	}

	//	Start the external miner is external generation is enabled.
	if cfg.ExternalGenerate {
		s.externalMiner.Start()
	}

	s.wg.Add(1)
	go s.memUsage()
}

// Stop gracefully shuts down the server by stopping and disconnecting all
// peers and the main listener.
func (s *server) Stop() error {
	// Make sure this only happens once.
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		srvrLog.Infof("Server is already in the process of shutting down")
		return nil
	}

	srvrLog.Warnf("Server shutting down")

	// Stop the CPU miner if needed
	s.cpuMiner.Stop()

	// Stop the external mining if needed
	s.externalMiner.Stop()

	// Shutdown the RPC server if it's not disabled.
	if !cfg.DisableRPC {
		s.rpcServer.Stop()
	}
	if cfg.EnableGetWorkRPC {
		s.rpcServerGetWork.Stop()
	}

	// Save fee estimator state in the database.
	s.db.Update(func(tx database.Tx) error {
		metadata := tx.Metadata()
		metadata.Put(mempool.EstimateFeeDatabaseKey, s.feeEstimator.Save())

		return nil
	})

	// Signal the remaining goroutines to quit.
	close(s.quit)
	return nil
}

// WaitForShutdown blocks until the main listener and peer handlers are stopped.
func (s *server) WaitForShutdown() {
	s.wg.Wait()
}

// ScheduleShutdown schedules a server shutdown after the specified duration.
// It also dynamically adjusts how often to warn the server is going down based
// on remaining duration.
func (s *server) ScheduleShutdown(duration time.Duration) {
	// Don't schedule shutdown more than once.
	if atomic.AddInt32(&s.shutdownSched, 1) != 1 {
		return
	}
	srvrLog.Warnf("Server shutdown in %v", duration)
	go func() {
		remaining := duration
		tickDuration := dynamicTickDuration(remaining)
		done := time.After(remaining)
		ticker := time.NewTicker(tickDuration)
	out:
		for {
			select {
			case <-done:
				ticker.Stop()
				s.Stop()
				break out
			case <-ticker.C:
				remaining = remaining - tickDuration
				if remaining < time.Second {
					continue
				}

				// Change tick duration dynamically based on remaining time.
				newDuration := dynamicTickDuration(remaining)
				if tickDuration != newDuration {
					tickDuration = newDuration
					ticker.Stop()
					ticker = time.NewTicker(tickDuration)
				}
				srvrLog.Warnf("Server shutdown in %v", remaining)
			}
		}
	}()
}

// parseListeners determines whether each listen address is IPv4 and IPv6 and
// returns a slice of appropriate net.Addrs to listen on with TCP. It also
// properly detects addresses which apply to "all interfaces" and adds the
// address as both IPv4 and IPv6.
func parseListeners(addrs []string) ([]net.Addr, error) {
	netAddrs := make([]net.Addr, 0, len(addrs)*2)
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp4", addr: addr})
			netAddrs = append(netAddrs, simpleAddr{net: "tcp6", addr: addr})
			continue
		}

		// Strip IPv6 zone id if present since net.ParseIP does not
		// handle it.
		zoneIndex := strings.LastIndex(host, "%")
		if zoneIndex > 0 {
			host = host[:zoneIndex]
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("'%s' is not a valid IP address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp6", addr: addr})
		} else {
			netAddrs = append(netAddrs, simpleAddr{net: "tcp4", addr: addr})
		}
	}
	return netAddrs, nil
}

func (s *server) upnpUpdateThread() {
	// Go off immediately to prevent code duplication, thereafter we renew
	// lease every 15 minutes.
	timer := time.NewTimer(0 * time.Second)
	lport, _ := strconv.ParseInt(activeNetParams.DefaultPort, 10, 16)
	first := true
out:
	for {
		select {
		case <-timer.C:
			// TODO: pick external port  more cleverly
			// TODO: know which ports we are listening to on an external net.
			// TODO: if specific listen port doesn't work then ask for wildcard
			// listen port?
			// XXX this assumes timeout is in seconds.
			listenPort, err := s.nat.AddPortMapping("tcp", int(lport), int(lport),
				"abec listen port", 20*60)
			if err != nil {
				srvrLog.Warnf("can't add UPnP port mapping: %v", err)
			}
			if first && err == nil {
				// TODO: look this up periodically to see if upnp domain changed
				// and so did ip.
				externalip, err := s.nat.GetExternalAddress()
				if err != nil {
					srvrLog.Warnf("UPnP can't get external address: %v", err)
					continue out
				}
				na := wire.NewNetAddressIPPort(externalip, uint16(listenPort),
					s.services)
				err = s.addrManager.AddLocalNetAddress(na, netaddrmgr.UpnpPrio)
				if err != nil {
					// XXX DeletePortMapping?
				}
				srvrLog.Warnf("Successfully bound via UPnP to %s", netaddrmgr.NetAddressKey(na))
				first = false
			}
			timer.Reset(time.Minute * 15)
		case <-s.quit:
			break out
		}
	}

	timer.Stop()

	if err := s.nat.DeletePortMapping("tcp", int(lport), int(lport)); err != nil {
		srvrLog.Warnf("unable to remove UPnP port mapping: %v", err)
	} else {
		srvrLog.Debugf("successfully disestablished UPnP port mapping")
	}

	s.wg.Done()
}

func (s *server) memUsage() {
	defer s.wg.Done()
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
out:
	for {
		select {
		case <-ticker.C:
			p, _ := process.NewProcess(int32(os.Getpid()))
			memoryInfo, _ := p.MemoryInfo()
			srvrLog.Infof("Memory usage:rss %.2fG vms %.2fG", float64(memoryInfo.RSS)/1024/1024/1024, float64(memoryInfo.VMS)/1024/1024/1024)
		case <-s.quit:
			break out
		}
	}
}

// setupRPCListeners returns a slice of listeners that are configured for use
// with the RPC server depending on the configuration settings for listen
// addresses and TLS.
func setupRPCListeners() ([]net.Listener, error) {
	// Setup TLS if not disabled.
	listenFunc := net.Listen
	if !cfg.DisableTLS {
		// Generate the TLS cert and key file if both don't already
		// exist.
		if !fileExists(cfg.RPCKey) && !fileExists(cfg.RPCCert) {
			err := genCertPair(cfg.RPCCert, cfg.RPCKey)
			if err != nil {
				return nil, err
			}
		}
		keypair, err := tls.LoadX509KeyPair(cfg.RPCCert, cfg.RPCKey)
		if err != nil {
			return nil, err
		}

		tlsConfig := tls.Config{
			Certificates: []tls.Certificate{keypair},
			MinVersion:   tls.VersionTLS12,
		}

		// Change the standard net.Listen function to the tls one.
		listenFunc = func(net string, laddr string) (net.Listener, error) {
			return tls.Listen(net, laddr, &tlsConfig)
		}
	}

	netAddrs, err := parseListeners(cfg.RPCListeners)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		listener, err := listenFunc(addr.Network(), addr.String())
		if err != nil {
			rpcsLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// setupRPCListenersGetWork returns a slice of listeners that are configured for use
// with the RPC server for getwork depending on the configuration settings for listen
// addresses.
func setupRPCListenersGetWork() ([]net.Listener, error) {
	listenFunc := net.Listen
	netAddrs, err := parseListeners(cfg.RPCListenersGetWork)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		listener, err := listenFunc(addr.Network(), addr.String())
		if err != nil {
			rpcsLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// newServer returns a new abec server configured to listen on addr for the
// abe network type specified by chainParams.  Use start to begin accepting
// connections from peers.
func newServer(listenAddrs, agentBlacklist, agentWhitelist []string,
	db database.DB, chainParams *chaincfg.Params,
	interrupt <-chan struct{}) (*server, error) {

	services := cfg.serviceFlag

	amgr := netaddrmgr.New(cfg.DataDir, abecLookup)

	var listeners []net.Listener
	var nat NAT
	if !cfg.DisableListen {
		var err error
		listeners, nat, err = initListeners(amgr, listenAddrs, services)
		if err != nil {
			return nil, err
		}
		if len(listeners) == 0 {
			return nil, errors.New("no valid listen address")
		}
	}

	if len(agentBlacklist) > 0 {
		srvrLog.Infof("User-agent blacklist %s", agentBlacklist)
	}
	if len(agentWhitelist) > 0 {
		srvrLog.Infof("User-agent whitelist %s", agentWhitelist)
	}

	s := server{
		chainParams:          chainParams,
		addrManager:          amgr,
		newPeers:             make(chan *serverPeer, cfg.MaxPeers),
		donePeers:            make(chan *serverPeer, cfg.MaxPeers),
		banPeers:             make(chan *serverPeer, cfg.MaxPeers),
		query:                make(chan interface{}),
		relayInv:             make(chan relayMsg, cfg.MaxPeers),
		broadcast:            make(chan broadcastMsg, cfg.MaxPeers),
		quit:                 make(chan struct{}),
		modifyRebroadcastInv: make(chan interface{}),
		peerHeightsUpdate:    make(chan updatePeerHeightsMsg),
		nat:                  nat,
		db:                   db,
		timeSource:           blockchain.NewMedianTime(),
		services:             services,
		sigCache:             txscript.NewSigCache(cfg.SigCacheMaxSize),
		hashCache:            txscript.NewHashCache(cfg.SigCacheMaxSize),
		witnessCache:         txscript.NewWitnessCache(cfg.WitnessCacheMaxSize),
		agentBlacklist:       agentBlacklist,
		agentWhitelist:       agentWhitelist,
		communicationCache:   sync.Map{},
	}

	// Create the transaction index if needed.
	// todo (abe): indexers should be finished later.
	var indexes []indexers.Indexer
	if cfg.TxIndex {
		indxLog.Info("Transaction index is still under construction.")
		// When txIndex is finished, uncomment the following code.
		//indxLog.Info("Transaction index is enabled")
		//
		s.txIndex = indexers.NewTxIndex(db)
		indexes = append(indexes, s.txIndex)
	}

	// Create an index manager if any of the optional indexes are enabled.
	var indexManager blockchain.IndexManager
	if len(indexes) > 0 {
		indexManager = indexers.NewManager(db, indexes)
	}

	// Merge given checkpoints with the default ones unless they are disabled.
	var checkpoints []chaincfg.Checkpoint
	if !cfg.DisableCheckpoints {
		checkpoints = mergeCheckpoints(s.chainParams.Checkpoints, cfg.addCheckpoints)
	}

	var nodeType wire.NodeType
	err := db.View(func(dbTx database.Tx) error {
		var err error
		nodeType, err = dbTx.FetchNodeType()
		return err
	})
	if err != nil {
		return nil, err
	}

	// Create a new block chain instance with the appropriate configuration.
	s.chain, err = blockchain.New(&blockchain.Config{
		NodeType:            nodeType,
		DB:                  s.db,
		Interrupt:           interrupt,
		ChainParams:         s.chainParams,
		Checkpoints:         checkpoints,
		FakePowHeightScopes: cfg.addFakePowHeightScopes,
		TimeSource:          s.timeSource,
		SigCache:            s.sigCache,
		WitnessCache:        s.witnessCache,
		IndexManager:        indexManager,
		HashCache:           s.hashCache,
	})
	if err != nil {
		return nil, err
	}

	// Search for a FeeEstimator state in the database. If none can be found
	// or if it cannot be loaded, create a new one.
	db.Update(func(tx database.Tx) error {
		metadata := tx.Metadata()
		feeEstimationData := metadata.Get(mempool.EstimateFeeDatabaseKey)
		if feeEstimationData != nil {
			// delete it from the database so that we don't try to restore the
			// same thing again somehow.
			metadata.Delete(mempool.EstimateFeeDatabaseKey)

			// If there is an error, log it and make a new fee estimator.
			var err error
			s.feeEstimator, err = mempool.RestoreFeeEstimator(feeEstimationData)

			if err != nil {
				peerLog.Errorf("Failed to restore fee estimator %v", err)
			}
		}

		return nil
	})

	// If no feeEstimator has been found, or if the one that has been found
	// is behind somehow, create a new one and start over.
	if s.feeEstimator == nil || s.feeEstimator.LastKnownHeight() != s.chain.BestSnapshot().Height {
		s.feeEstimator = mempool.NewFeeEstimator(
			mempool.DefaultEstimateFeeMaxRollback,
			mempool.DefaultEstimateFeeMinRegisteredBlocks)
	}

	if cfg.AllowDiskCacheTx {
		cacheTxFileName := filepath.Join(cfg.CacheTxDir, defaultCacheTxFilename)
		logDir, _ := filepath.Split(cacheTxFileName)

		// clean dirty data if shut down unexpectedly
		os.RemoveAll(cfg.CacheTxDir)
		err := os.MkdirAll(logDir, 0700)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create transaction cache directory: %v\n", err)
			os.Exit(1)
		}
		r, err := rotator.New(cacheTxFileName, 0, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create file rotator: %v\n", err)
			os.Exit(1)
		}

		s.txCacheRotator = r
	}
	txC := mempool.Config{
		Policy: mempool.Policy{
			DisableRelayPriority: cfg.NoRelayPriority,
			AcceptNonStd:         cfg.RelayNonStd,
			FreeTxRelayLimit:     cfg.FreeTxRelayLimit,
			MaxOrphanTxs:         cfg.MaxOrphanTxs,
			MaxOrphanTxSize:      defaultMaxOrphanTxSize,
			MaxSigOpCostPerTx:    blockchain.MaxBlockSigOpsCost / 4,
			MinRelayTxFee:        cfg.minRelayTxFee,
			MaxTxVersion:         int32(wire.TxVersion),
			RejectReplacement:    cfg.RejectReplacement,
		},
		ChainParams: chainParams,
		//	todo(ABE):
		FetchUtxoView:     s.chain.FetchUtxoView,
		FetchUtxoRingView: s.chain.FetchUtxoRingView,
		FetchAUTView:      s.chain.FetchAUTView,
		BestHeight:        func() int32 { return s.chain.BestSnapshot().Height },
		MedianTimePast:    func() time.Time { return s.chain.BestSnapshot().MedianTime },
		CalcSequenceLock: func(tx *abeutil.Tx, view *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error) {
			return s.chain.CalcSequenceLock(tx, view, true)
		},
		IsDeploymentActive: s.chain.IsDeploymentActive,
		SigCache:           s.sigCache,
		HashCache:          s.hashCache,
		WitnessCache:       s.witnessCache,
		FeeEstimator:       s.feeEstimator,
		AllowDiskCacheTx:   cfg.AllowDiskCacheTx,
		TxCacheRotator:     s.txCacheRotator,
		CacheTxFileName:    filepath.Join(cfg.CacheTxDir, defaultCacheTxFilename),
	}
	s.txMemPool = mempool.New(&txC)
	//	todo: (EthashPoW)
	cfg.EthashConfig.BlockHeightStart = s.chainParams.BlockHeightEthashPoW
	cfg.EthashConfig.EpochLength = s.chainParams.EthashEpochLength
	s.ethash = ethash.New(cfg.EthashConfig)

	s.syncManager, err = syncmgr.New(&syncmgr.Config{
		NodeType:           cfg.nodeType,
		PeerNotifier:       &s, // serve
		Chain:              s.chain,
		TxMemPool:          s.txMemPool,
		Ethash:             s.ethash, // todo: (EthashPoW)
		ChainParams:        s.chainParams,
		DisableCheckpoints: cfg.DisableCheckpoints,
		MaxPeers:           cfg.MaxPeers,
		FeeEstimator:       s.feeEstimator,
	})
	if err != nil {
		return nil, err
	}

	witnessMgrMaxReservedWitness := cfg.maxReservedWitness
	if os.Getenv("ABEC_MAX_RESERVED_WITNESS") != "" {
		envWitnessMgrMaxReservedWitness, err := strconv.ParseInt(os.Getenv("ABEC_MAX_RESERVED_WITNESS"), 10, 32)
		if err != nil {
			panic(err)
		}
		witnessMgrMaxReservedWitness = uint32(envWitnessMgrMaxReservedWitness)
	}
	s.witnessManager, err = witnessmgr.New(&witnessmgr.Config{
		NodeType:             cfg.nodeType,
		MaxReservedWitness:   witnessMgrMaxReservedWitness,
		Chain:                s.chain,
		WitnessServiceHeight: cfg.witnessServiceHeight,
		TLogFilename:         cfg.tLogFilename,
	})
	if err != nil {
		return nil, err
	}

	// Create the mining policy and block template generator based on the
	// configuration options.
	//
	// NOTE: The CPU miner relies on the mempool, so the mempool has to be
	// created before calling the function to create the CPU miner.
	policy := mining.Policy{
		BlockMinWeight:         cfg.BlockMinWeight,
		BlockMaxWeight:         cfg.BlockMaxWeight,
		BlockMinSize:           cfg.BlockMinSize,
		BlockMaxSize:           cfg.BlockMaxSize,
		BlockSizeMinMLPAUT:     cfg.BlockSizeMinMLPAUT,
		BlockSizeMaxMLPAUT:     cfg.BlockSizeMaxMLPAUT,
		BlockFullSizeMinMLPAUT: cfg.BlockFullSizeMinMLPAUT,
		BlockFullSizeMaxMLPAUT: cfg.BlockFullSizeMaxMLPAUT,
		BlockPrioritySize:      cfg.BlockPrioritySize,
		TxMinFreeFee:           cfg.minRelayTxFee,
	}
	blockTemplateGenerator := mining.NewBlkTmplGenerator(&policy,
		s.chainParams, s.txMemPool, s.chain, s.timeSource,
		s.sigCache, s.hashCache, s.witnessCache)
	if s.chain.BestSnapshot().Height+1 < s.chainParams.BlockHeightMLPAUT {
		// Check address, disallow higher address with crypto scheme
		for i := 0; i < len(cfg.miningAddrs); i++ {
			if cfg.miningAddrs[i].CryptoScheme() != abecryptoxparam.CryptoSchemePQRingCT {
				return nil, fmt.Errorf("address with crypto scheme other than %d address is disallow until height %d", abecryptoxparam.CryptoSchemePQRingCT, s.chainParams.BlockHeightMLPAUT)
			}
		}
	}

	s.cpuMiner = cpuminer.New(&cpuminer.Config{
		ChainParams:            chainParams,
		Ethash:                 s.ethash, // todo: (EthashPoW)
		FakePowHeightScope:     s.chain.FakePoWHeightScopes(),
		BlockTemplateGenerator: blockTemplateGenerator,
		MiningAddrs:            cfg.miningAddrs,
		HashRateWatermark:      cfg.HashRateWatermark,
		ProcessBlock:           s.syncManager.ProcessBlock,
		ConnectedCount:         s.ConnectedCount,
		IsCurrent:              s.syncManager.IsCurrent,
	})

	s.externalMiner = externalminer.New(&externalminer.Config{
		ChainParams:            chainParams,
		Ethash:                 s.ethash,
		BlockTemplateGenerator: blockTemplateGenerator,
		MiningAddrs:            cfg.miningAddrs,
		ProcessBlock:           s.syncManager.ProcessBlock,
		ConnectedCount:         s.ConnectedCount,
		IsCurrent:              s.syncManager.IsCurrent,
	})

	// Only setup a function to return new addresses to connect to when
	// not running in connect-only mode.  The simulation network is always
	// in connect-only mode since it is only intended to connect to
	// specified peers and actively avoid advertising and connecting to
	// discovered peers in order to prevent it from becoming a public test
	// network.
	var newAddressFunc func() (net.Addr, error)
	if !cfg.SimNet && len(cfg.ConnectPeers) == 0 {
		newAddressFunc = func() (net.Addr, error) {
			for tries := 0; tries < 100; tries++ {
				addr := s.addrManager.GetNetAddress() // to get the address of peer which can be connected
				if addr == nil {
					break
				}

				// Address will not be invalid, local or unroutable
				// because addrmanager rejects those on addition.
				// Just check that we don't already have an address
				// in the same group so that we are not connecting
				// to the same network segment at the expense of
				// others.
				key := netaddrmgr.GroupKey(addr.NetAddress())
				if s.OutboundGroupCount(key) != 0 {
					continue
				}

				// only allow recent nodes (10mins) after we failed 30
				// times
				if tries < 30 && time.Since(addr.LastAttempt()) < 10*time.Minute {
					continue
				}

				// allow nondefault ports after 50 failed tries.
				if tries < 50 && fmt.Sprintf("%d", addr.NetAddress().Port) !=
					activeNetParams.DefaultPort {
					continue
				}

				// Mark an attempt for the valid address.
				s.addrManager.Attempt(addr.NetAddress())

				addrString := netaddrmgr.NetAddressKey(addr.NetAddress())
				return addrStringToNetAddr(addrString)
			}

			return nil, errors.New("no valid connect address")
		}
	}

	// Create a connection manager.
	targetOutbound := defaultTargetOutbound
	if cfg.MaxPeers < targetOutbound {
		targetOutbound = cfg.MaxPeers
	}
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      listeners,
		OnAccept:       s.inboundPeerConnected,
		RetryDuration:  connectionRetryInterval,
		TargetOutbound: uint32(targetOutbound),
		Dial:           abecDial,
		OnConnection:   s.outboundPeerConnected, //handle with the process of connected
		GetNewAddress:  newAddressFunc,          // get the address of peer
	})
	if err != nil {
		return nil, err
	}
	s.connManager = cmgr

	// Start up persistent peers.
	permanentPeers := cfg.ConnectPeers
	if len(permanentPeers) == 0 {
		permanentPeers = cfg.AddPeers
	}
	for _, addr := range permanentPeers {
		netAddr, err := addrStringToNetAddr(addr)
		if err != nil {
			srvrLog.Warnf("warning critical: can not parse %s to network address: %v",
				addr, err)
			continue
		}

		go s.connManager.Connect(&connmgr.ConnReq{
			Addr:      netAddr,
			Permanent: true,
		})
	}

	if !cfg.DisableRPC {
		// Setup listeners for the configured RPC listen addresses and
		// TLS settings.
		rpcListeners, err := setupRPCListeners()
		if err != nil {
			return nil, err
		}
		if len(rpcListeners) == 0 {
			return nil, errors.New("RPCS: No valid listen address")
		}

		s.rpcServer, err = newRPCServer(&rpcserverConfig{
			Listeners:   rpcListeners,
			StartupTime: s.startupTime,
			ConnMgr:     &rpcConnManager{&s},
			SyncMgr:     &rpcSyncMgr{&s, s.syncManager},
			TimeSource:  s.timeSource,
			Chain:       s.chain,
			ChainParams: chainParams,
			DB:          db,
			TxMemPool:   s.txMemPool,
			// todo: (EthashPoW) 202207
			Ethash:    s.ethash,
			Generator: blockTemplateGenerator,
			CPUMiner:  s.cpuMiner,
			// todo: 2023.05.11 At this moment, the ExternalMiner here is not used,
			// since we use rpcServerGetWork to respond the requests of getwork.
			ExternalMiner: s.externalMiner,
			TxIndex:       s.txIndex,
			FeeEstimator:  s.feeEstimator,
		})
		if err != nil {
			return nil, err
		}

		// Signal process shutdown when the RPC server requests it.
		go func() {
			<-s.rpcServer.RequestedProcessShutdown()
			shutdownRequestChannel <- struct{}{}
		}()
	}

	if cfg.EnableGetWorkRPC {
		// Setup listeners for the configured RPC listen addresses.
		rpcListeners, err := setupRPCListenersGetWork()
		if err != nil {
			return nil, err
		}
		if len(rpcListeners) == 0 {
			return nil, errors.New("RPCS: No valid listen address for getwork")
		}

		s.rpcServerGetWork, err = newRPCServer(&rpcserverConfig{
			Listeners:   rpcListeners,
			StartupTime: s.startupTime,
			ConnMgr:     &rpcConnManager{&s},
			SyncMgr:     &rpcSyncMgr{&s, s.syncManager},
			TimeSource:  s.timeSource,
			Chain:       s.chain,
			ChainParams: chainParams,
			DB:          db,
			TxMemPool:   s.txMemPool,
			// todo: (EthashPoW) 202207
			Ethash:        s.ethash,
			Generator:     blockTemplateGenerator,
			CPUMiner:      s.cpuMiner,
			ExternalMiner: s.externalMiner,
			TxIndex:       s.txIndex,
			FeeEstimator:  s.feeEstimator,
			Alias:         "getwork",
		})
		if err != nil {
			return nil, err
		}

		// Signal process shutdown when the RPC server requests it.
		go func() {
			<-s.rpcServerGetWork.RequestedProcessShutdown()
			shutdownRequestChannel <- struct{}{}
		}()
	}

	return &s, nil
}

// initListeners initializes the configured net listeners and adds any bound
// addresses to the address manager. Returns the listeners and a NAT interface,
// which is non-nil if UPnP is in use.
func initListeners(amgr *netaddrmgr.NetAddrManager, listenAddrs []string, services wire.ServiceFlag) ([]net.Listener, NAT, error) {
	// Listen for TCP connections at the configured addresses
	netAddrs, err := parseListeners(listenAddrs)
	if err != nil {
		return nil, nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		listener, err := net.Listen(addr.Network(), addr.String())
		if err != nil {
			srvrLog.Warnf("Can't listen on %s: %v", addr, err)
			continue
		}
		listeners = append(listeners, listener)
	}

	var nat NAT
	if len(cfg.ExternalIPs) != 0 {
		defaultPort, err := strconv.ParseUint(activeNetParams.DefaultPort, 10, 16)
		if err != nil {
			srvrLog.Errorf("Can not parse default port %s for active chain: %v",
				activeNetParams.DefaultPort, err)
			return nil, nil, err
		}

		for _, sip := range cfg.ExternalIPs {
			eport := uint16(defaultPort)
			host, portstr, err := net.SplitHostPort(sip)
			if err != nil {
				// no port, use default.
				// todo: 20220427. if no port, then use a random port
				host = sip
			} else {
				port, err := strconv.ParseUint(portstr, 10, 16)
				if err != nil {
					srvrLog.Warnf("Can not parse port from %s for "+
						"externalip: %v", sip, err)
					continue
				}
				eport = uint16(port)
			}
			na, err := amgr.HostToNetAddress(host, eport, services)
			if err != nil {
				srvrLog.Warnf("Not adding %s as externalip: %v", sip, err)
				continue
			}

			err = amgr.AddLocalNetAddress(na, netaddrmgr.ManualPrio)
			if err != nil {
				amgrLog.Warnf("Skipping specified external IP: %v", err)
			}
		}
	} else {
		if cfg.Upnp {
			var err error
			nat, err = Discover()
			if err != nil {
				srvrLog.Warnf("Can't discover upnp: %v", err)
			}
			// nil nat here is fine, just means no upnp on network.
		}

		// Add bound addresses to address manager to be advertised to peers.
		for _, listener := range listeners {
			addr := listener.Addr().String()
			err := addLocalAddress(amgr, addr, services)
			if err != nil {
				amgrLog.Warnf("Skipping bound address %s: %v", addr, err)
			}
		}
	}

	return listeners, nat, nil
}

// addrStringToNetAddr takes an address in the form of 'host:port' and returns
// a net.Addr which maps to the original address with any host names resolved
// to IP addresses.  It also handles tor addresses properly by returning a
// net.Addr that encapsulates the address.
func addrStringToNetAddr(addr string) (net.Addr, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	// Skip if host is already an IP address.
	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}, nil
	}

	// Tor addresses cannot be resolved to an IP, so just return an onion
	// address instead.
	if strings.HasSuffix(host, ".onion") {
		if cfg.NoOnion {
			return nil, errors.New("tor has been disabled")
		}

		return &onionAddr{addr: addr}, nil
	}

	// Attempt to look up an IP address associated with the parsed host.
	ips, err := abecLookup(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	return &net.TCPAddr{
		IP:   ips[0],
		Port: port,
	}, nil
}

// addLocalAddress adds an address that this node is listening on to the
// address manager so that it may be relayed to peers.
func addLocalAddress(addrMgr *netaddrmgr.NetAddrManager, addr string, services wire.ServiceFlag) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return err
	}

	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		// If bound to unspecified address, advertise all local interfaces
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}

		for _, addr := range addrs {
			ifaceIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// If bound to 0.0.0.0, do not add IPv6 interfaces and if bound to
			// ::, do not add IPv4 interfaces.
			if (ip.To4() == nil) != (ifaceIP.To4() == nil) {
				continue
			}

			netAddr := wire.NewNetAddressIPPort(ifaceIP, uint16(port), services)
			addrMgr.AddLocalNetAddress(netAddr, netaddrmgr.BoundPrio)
		}
	} else {
		netAddr, err := addrMgr.HostToNetAddress(host, uint16(port), services)
		if err != nil {
			return err
		}

		addrMgr.AddLocalNetAddress(netAddr, netaddrmgr.BoundPrio)
	}

	return nil
}

// dynamicTickDuration is a convenience function used to dynamically choose a
// tick duration based on remaining time.  It is primarily used during
// server shutdown to make shutdown warnings more frequent as the shutdown time
// approaches.
func dynamicTickDuration(remaining time.Duration) time.Duration {
	switch {
	case remaining <= time.Second*5:
		return time.Second
	case remaining <= time.Second*15:
		return time.Second * 5
	case remaining <= time.Minute:
		return time.Second * 15
	case remaining <= time.Minute*5:
		return time.Minute
	case remaining <= time.Minute*15:
		return time.Minute * 5
	case remaining <= time.Hour:
		return time.Minute * 15
	}
	return time.Hour
}

// isWhitelisted returns whether the IP address is included in the whitelisted
// networks and IPs.
func isWhitelisted(addr net.Addr) bool {
	if len(cfg.whitelists) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		srvrLog.Warnf("Unable to SplitHostPort on '%s': %v", addr, err)
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		srvrLog.Warnf("Unable to parse IP '%s'", addr)
		return false
	}

	for _, ipnet := range cfg.whitelists {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// checkpointSorter implements sort.Interface to allow a slice of checkpoints to
// be sorted.
type checkpointSorter []chaincfg.Checkpoint

// Len returns the number of checkpoints in the slice.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Len() int {
	return len(s)
}

// Swap swaps the checkpoints at the passed indices.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less returns whether the checkpoint with index i should sort before the
// checkpoint with index j.  It is part of the sort.Interface implementation.
func (s checkpointSorter) Less(i, j int) bool {
	return s[i].Height < s[j].Height
}

// mergeCheckpoints returns two slices of checkpoints merged into one slice
// such that the checkpoints are sorted by height.  In the case the additional
// checkpoints contain a checkpoint with the same height as a checkpoint in the
// default checkpoints, the additional checkpoint will take precedence and
// overwrite the default one.
func mergeCheckpoints(defaultCheckpoints, additional []chaincfg.Checkpoint) []chaincfg.Checkpoint {
	// Create a map of the additional checkpoints to remove duplicates while
	// leaving the most recently-specified checkpoint.
	extra := make(map[int32]chaincfg.Checkpoint)
	for _, checkpoint := range additional {
		extra[checkpoint.Height] = checkpoint
	}

	// Add all default checkpoints that do not have an override in the
	// additional checkpoints.
	numDefault := len(defaultCheckpoints)
	checkpoints := make([]chaincfg.Checkpoint, 0, numDefault+len(extra))
	for _, checkpoint := range defaultCheckpoints {
		if _, exists := extra[checkpoint.Height]; !exists {
			checkpoints = append(checkpoints, checkpoint)
		}
	}

	// Append the additional checkpoints and return the sorted results.
	for _, checkpoint := range extra {
		checkpoints = append(checkpoints, checkpoint)
	}
	sort.Sort(checkpointSorter(checkpoints))
	return checkpoints
}

// HasUndesiredUserAgent determines whether the server should continue to pursue
// a connection with this peer based on its advertised user agent. It performs
// the following steps:
// 1) Reject the peer if it contains a blacklisted agent.
// 2) If no whitelist is provided, accept all user agents.
// 3) Accept the peer if it contains a whitelisted agent.
// 4) Reject all other peers.
func (sp *serverPeer) HasUndesiredUserAgent(blacklistedAgents,
	whitelistedAgents []string) bool {

	agent := sp.UserAgent()

	// First, if peer's user agent contains any blacklisted substring, we
	// will ignore the connection request.
	for _, blacklistedAgent := range blacklistedAgents {
		if strings.Contains(agent, blacklistedAgent) {
			srvrLog.Debugf("Ignoring peer %s, user agent "+
				"contains blacklisted user agent: %s", sp,
				agent)
			return true
		}
	}

	// If no whitelist is provided, we will accept all user agents.
	if len(whitelistedAgents) == 0 {
		return false
	}

	// Peer's user agent passed blacklist. Now check to see if it contains
	// one of our whitelisted user agents, if so accept.
	for _, whitelistedAgent := range whitelistedAgents {
		if strings.Contains(agent, whitelistedAgent) {
			return false
		}
	}

	// Otherwise, the peer's user agent was not included in our whitelist.
	// Ignore just in case it could stall the initial block download.
	srvrLog.Debugf("Ignoring peer %s, user agent: %s not found in "+
		"whitelist", sp, agent)

	return true
}
