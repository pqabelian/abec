package wire

import (
	"sync"
	"time"

	"github.com/abesuite/abec/chainhash"
)

// requestedResponse records the response identity. A needset response is tied
// to its block; reconstruction owns transaction-set and witness validation.
type requestedResponse struct {
	hash   chainhash.Hash
	txHash chainhash.Hash
	sentAt time.Time
}

// MessageRequests tracks responses to local requests sent to one peer. It does
// not govern requests received from that peer. Its zero value is ready to use,
// and its methods are safe for concurrent use.
type MessageRequests struct {
	mu            sync.Mutex
	pending       map[string][]requestedResponse
	completedData uint64 // Matched getdata responses, excluding direct tx relay.
	closed        bool
}

func NewMessageRequests() *MessageRequests {
	return &MessageRequests{}
}

// Add registers a local request before it is written. Outgoing responses and
// other messages create no pending request. False means the tracker is closed.
func (r *MessageRequests) Add(msg Message) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	pending := make(map[string][]requestedResponse)
	switch msg := msg.(type) {
	case *MsgGetData:
		for _, iv := range msg.InvList {
			if isGetDataRequest(iv.Type.String()) {
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
	if len(pending) == 0 {
		return true
	}
	if r.pending == nil {
		r.pending = make(map[string][]requestedResponse)
	}
	now := time.Now()
	for key, requests := range pending {
		for i := range requests {
			requests[i].sentAt = now
		}
		r.pending[key] = append(r.pending[key], requests...)
	}
	return true
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

// begin checks that an incoming response has a pending local request before
// reading its payload. Incoming requests and direct transaction relay are not
// responses to local requests and do not require a pending entry.
func (r *MessageRequests) begin(command string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return messageError("ReadMessage", "request tracker closed")
	}
	keys := responseRequestKeys(command)
	if len(keys) == 0 || command == CmdTx {
		return nil
	}
	for _, key := range keys {
		if len(r.pending[key]) > 0 {
			return nil
		}
	}
	return messageError("ReadMessage", "unexpected message "+command)
}

// complete removes a pending request only for an exact decoded response identity.
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
		// An independently relayed transaction cannot complete another hash's
		// request, but still follows the normal transaction validation path.
		return nil
	}
	return messageError("ReadMessage", "unrequested response "+msg.Command())
}

// oldestMatch requires r.mu. Identical or base/witness-equivalent responses
// complete the oldest matching request so duplicates cannot cause early expiry.
func (r *MessageRequests) oldestMatch(keys []string, hash, txHash chainhash.Hash) (string, int) {
	// Match the oldest request across equivalent base/witness response types.
	var matchedKey string
	index := -1
	var oldest time.Time
	for _, key := range keys {
		for i, request := range r.pending[key] {
			if request.hash == hash && request.txHash == txHash &&
				(index < 0 || request.sentAt.Before(oldest)) {
				matchedKey, index, oldest = key, i, request.sentAt
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

// Expired reports whether any sent request has reached the age cutoff.
// Other responses cannot change its age.
func (r *MessageRequests) Expired(cutoff time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, requests := range r.pending {
		for _, request := range requests {
			if !request.sentAt.After(cutoff) {
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

// Close discards unanswered requests and prevents further registration.
func (r *MessageRequests) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	clear(r.pending)
}
