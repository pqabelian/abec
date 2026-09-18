package wire

import (
	"sync"
	"time"

	"github.com/pqabelian/abec/chainhash"
)

// requestedResponse records the response identity. A needset response is tied
// to its block; reconstruction owns transaction-set and witness validation.
type requestedResponse struct {
	hash       chainhash.Hash
	txHash     chainhash.Hash
	admittedAt time.Time
}

// MessageRequests tracks responses expected from one peer. Its methods are safe
// for concurrent use. The zero value tracks requests without a global limit.
type MessageRequests struct {
	mu            sync.Mutex
	pending       map[string][]requestedResponse
	counter       *RequestCounter
	reading       int
	completedData uint64 // Matched getdata responses, excluding direct tx relay.
	closed        bool
}

func NewMessageRequests(counter *RequestCounter) *MessageRequests {
	return &MessageRequests{counter: counter}
}

// Add registers a complete request before it is written. False means no credit
// was added: the peer is closed or the shared counter cannot admit the request.
func (r *MessageRequests) Add(msg Message) bool {
	pending := make(map[string][]requestedResponse)
	switch msg := msg.(type) {
	case *MsgGetData:
		for _, iv := range msg.InvList {
			if responsePayloadLimit(iv.Type.String()) != 0 {
				key := iv.Type.String()
				pending[key] = append(pending[key], requestedResponse{hash: iv.Hash})
			}
		}
	case *MsgGetHeaders:
		pending[CmdGetHeaders] = []requestedResponse{{}}
	case *MsgGetBlockTx:
		pending[CmdGetBlockTx] = []requestedResponse{{hash: msg.BlockHash, txHash: msg.TxHash}}
	case *MsgNeedSet:
		pending[CmdNeedSet] = []requestedResponse{{hash: msg.BlockHash}}
	}
	var count, payloadBytes uint64
	for key, requests := range pending {
		count += uint64(len(requests))
		payloadBytes += uint64(len(requests)) * responsePayloadLimit(key)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.counter.reserve(count, payloadBytes) {
		return false
	}
	if r.pending == nil {
		r.pending = make(map[string][]requestedResponse)
	}
	now := time.Now()
	for key, requests := range pending {
		for i := range requests {
			requests[i].admittedAt = now
		}
		r.pending[key] = append(r.pending[key], requests...)
	}
	return true
}

// ReserveNext admits as much of a getdata batch as fits. Other requests are
// atomic. It returns the message to send and an optional unsent remainder.
// A nil first result means capacity is unavailable; no request was registered.
func (r *MessageRequests) ReserveNext(msg Message) (Message, Message) {
	gd, ok := msg.(*MsgGetData)
	if !ok || len(gd.InvList) == 0 {
		if r.Add(msg) {
			return msg, nil
		}
		return nil, msg
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, msg
	}
	if r.pending == nil {
		r.pending = make(map[string][]requestedResponse)
	}
	now := time.Now()
	n := 0
	for _, iv := range gd.InvList {
		key := iv.Type.String()
		payloadLimit := responsePayloadLimit(key)
		if payloadLimit != 0 {
			if !r.counter.reserve(1, payloadLimit) {
				break
			}
			r.pending[key] = append(r.pending[key], requestedResponse{hash: iv.Hash, admittedAt: now})
		}
		n++
	}
	if n == 0 {
		return nil, msg
	}
	if n == len(gd.InvList) {
		return msg, nil
	}
	return &MsgGetData{InvList: gd.InvList[:n]}, &MsgGetData{InvList: gd.InvList[n:]}
}

func responseRequestKeys(command string) []string {
	switch command {
	case CmdHeaders:
		return []string{CmdGetHeaders}
	case CmdBlock:
		return []string{InvTypeBlock.String(), InvTypeWitnessBlock.String()}
	case CmdTx:
		return []string{InvTypeWitnessTx.String(), InvTypeTx.String()}
	case CmdPrunedBlock:
		return []string{InvTypePrunedBlock.String()}
	case CmdBlockTx:
		return []string{CmdGetBlockTx}
	case CmdNeedSetResult:
		return []string{CmdNeedSet}
	}
	return nil
}

// begin validates the message type before allocation without consuming an
// unidentified request. The peer has one reader; Close waits for it to finish.
func (r *MessageRequests) begin(command string) (uint64, error) {
	if r == nil {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, messageError("ReadMessage", "request tracker closed")
	}
	keys := responseRequestKeys(command)
	allowed := len(keys) == 0
	for _, key := range keys {
		allowed = allowed || len(r.pending[key]) > 0
	}
	var relayLimit uint64
	if !allowed && command == CmdTx {
		// Direct transaction relay is supported. Without an expected tx
		// response to cover the read, acquire a temporary protocol-max charge.
		relayLimit = responsePayloadLimit(InvTypeTx.String())
		if !r.counter.reserve(1, relayLimit) {
			return 0, ErrResponseLimit
		}
		allowed = true
	}
	if !allowed {
		return 0, messageError("ReadMessage", "unexpected message "+command)
	}
	r.reading++
	return relayLimit, nil
}

// complete returns credit only for an exact decoded response identity.
func (r *MessageRequests) complete(msg Message) error {
	if r == nil {
		return nil
	}
	var hash, txHash chainhash.Hash
	switch msg := msg.(type) {
	case *MsgHeaders:
		// Headers carry no request ID; retain the existing count-based match.
	case *MsgBlockAbe:
		hash = msg.BlockHash()
	case *MsgTxAbe:
		hash = msg.TxHash()
	case *MsgPrunedBlock:
		hash = msg.BlockHash()
	case *MsgBlockTx:
		hash, txHash = msg.BlockHash, msg.Tx.TxHash()
	case *MsgNeedSetResult:
		hash = msg.BlockHash
	case *MsgNotFound:
		return r.notFound(msg)
	default:
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if key, i := r.oldestMatch(responseRequestKeys(msg.Command()), hash, txHash); i >= 0 {
		r.remove(key, i)
		return nil
	}
	if msg.Command() == CmdTx {
		// An independently relayed transaction cannot spend another hash's
		// credit, but still follows the normal transaction validation path.
		return nil
	}
	return messageError("ReadMessage", "unrequested response "+msg.Command())
}

// oldestMatch requires r.mu. Identical or base/witness-equivalent responses
// complete the oldest matching request so duplicates cannot cause early expiry.
func (r *MessageRequests) oldestMatch(keys []string, hash, txHash chainhash.Hash) (string, int) {
	// ponytail: scan the admitted window; use a hash index if large configured
	// windows make matching costly. The default admits at most 16 tx requests.
	var matchedKey string
	index := -1
	var oldest time.Time
	for _, key := range keys {
		for i, request := range r.pending[key] {
			if request.hash == hash && request.txHash == txHash &&
				(index < 0 || request.admittedAt.Before(oldest)) {
				matchedKey, index, oldest = key, i, request.admittedAt
			}
		}
	}
	return matchedKey, index
}

// remove requires r.mu. Order is irrelevant, including repeated requests for
// the same inventory: each response completes only one outstanding request.
func (r *MessageRequests) remove(key string, i int) {
	requests := r.pending[key]
	last := len(requests) - 1
	requests[i] = requests[last]
	requests[last] = requestedResponse{}
	if last == 0 {
		delete(r.pending, key)
	} else {
		r.pending[key] = requests[:last]
	}
	r.counter.release(1, responsePayloadLimit(key))
	if isGetDataRequest(key) {
		r.completedData++
	}
}

func isGetDataRequest(key string) bool {
	switch key {
	case InvTypeBlock.String(), InvTypeWitnessBlock.String(), InvTypePrunedBlock.String(),
		InvTypeTx.String(), InvTypeWitnessTx.String():
		return true
	}
	return false
}

// GetDataStatus reports outstanding inventory entries and matched completions.
// Peers use it to distinguish real download progress from unsolicited messages.
func (r *MessageRequests) GetDataStatus() (pending int, completed uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, requests := range r.pending {
		if isGetDataRequest(key) {
			pending += len(requests)
		}
	}
	return pending, r.completedData
}

// Expired reports whether any admitted request has reached the age cutoff.
// Other responses and requests still waiting for credit cannot change its age.
func (r *MessageRequests) Expired(cutoff time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, requests := range r.pending {
		for _, request := range requests {
			if !request.admittedAt.After(cutoff) {
				return true
			}
		}
	}
	return false
}

func (r *MessageRequests) notFound(msg *MsgNotFound) error {
	// Filtering unknown hashes must not hide invalid types from the server's
	// existing rejection policy. Validate the entire message before updating it.
	for _, iv := range msg.InvList {
		if !isGetDataRequest(iv.Type.String()) {
			return messageError("ReadMessage", "invalid notfound inventory type "+iv.Type.String())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Only matched entries may reach callers. SyncManager also tracks requests
	// still waiting in the peer queue, which an unsolicited notfound must not
	// cancel. A nil tracker leaves the stateless reader's message unchanged.
	matched := msg.InvList[:0]
	for _, iv := range msg.InvList {
		if key, i := r.oldestMatch([]string{iv.Type.String()}, iv.Hash, chainhash.Hash{}); i >= 0 {
			r.remove(key, i)
			matched = append(matched, iv)
		}
	}
	clear(msg.InvList[len(matched):])
	msg.InvList = matched
	return nil
}

func (r *MessageRequests) end(relayLimit uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if relayLimit != 0 {
		r.counter.release(1, relayLimit)
	}
	r.reading--
	if r.closed && r.reading == 0 {
		r.releaseAll()
	}
}

// Close returns unanswered requests once any active read has exited. Read
// failures leave identities intact until the connection owner calls Close.
func (r *MessageRequests) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.reading == 0 {
		r.releaseAll()
	}
}

// releaseAll requires r.mu.
func (r *MessageRequests) releaseAll() {
	var count, payloadBytes uint64
	for key, requests := range r.pending {
		count += uint64(len(requests))
		payloadBytes += uint64(len(requests)) * responsePayloadLimit(key)
	}
	clear(r.pending)
	r.counter.release(count, payloadBytes)
}
