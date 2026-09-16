package wire

import "sync"

// MessageRequests tracks responses expected from one peer. Its methods are safe
// for concurrent use. The zero value tracks requests without a global limit.
type MessageRequests struct {
	mu      sync.Mutex
	pending map[string]int
	counter *RequestCounter
	closed  bool
}

func NewMessageRequests(counter *RequestCounter) *MessageRequests {
	return &MessageRequests{counter: counter}
}

// Add registers a complete request before it is written. False means no credit
// was added: the peer is closed or the shared counter cannot admit the request.
func (r *MessageRequests) Add(msg Message) bool {
	counts := make(map[string]int)
	switch msg := msg.(type) {
	case *MsgGetData:
		for _, iv := range msg.InvList {
			if responsePayloadLimit(iv.Type.String()) != 0 {
				counts[iv.Type.String()]++
			}
		}
	case *MsgGetHeaders, *MsgNeedSet, *MsgGetBlockTx:
		counts[msg.Command()]++
	}
	var count, payloadBytes uint64
	for key, n := range counts {
		count += uint64(n)
		payloadBytes += uint64(n) * responsePayloadLimit(key)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.counter.reserve(count, payloadBytes) {
		return false
	}
	if r.pending == nil {
		r.pending = make(map[string]int)
	}
	for key, n := range counts {
		r.pending[key] += n
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
		r.pending = make(map[string]int)
	}
	n := 0
	for _, iv := range gd.InvList {
		key := iv.Type.String()
		payloadLimit := responsePayloadLimit(key)
		if payloadLimit != 0 {
			if !r.counter.reserve(1, payloadLimit) {
				break
			}
			r.pending[key]++
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

// consume validates a response header before allocating its payload. The
// returned payload limit stays counted until the reader finishes or fails.
func (r *MessageRequests) consume(command string) (uint64, error) {
	if r == nil {
		return 0, nil
	}
	var keys []string
	switch command {
	case CmdHeaders:
		keys = []string{CmdGetHeaders}
	case CmdBlock:
		keys = []string{InvTypeBlock.String(), InvTypeWitnessBlock.String()}
	case CmdTx:
		keys = []string{InvTypeWitnessTx.String(), InvTypeTx.String()}
	case CmdPrunedBlock:
		keys = []string{InvTypePrunedBlock.String()}
	case CmdBlockTx:
		keys = []string{CmdGetBlockTx}
	case CmdNeedSetResult:
		keys = []string{CmdNeedSet}
	default:
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range keys {
		if r.pending[key] > 0 {
			r.pending[key]--
			return responsePayloadLimit(key), nil
		}
	}
	return 0, messageError("ReadMessage", "unexpected message "+command)
}

func (r *MessageRequests) notFound(msg *MsgNotFound) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, iv := range msg.InvList {
		key := iv.Type.String()
		if r.pending[key] > 0 {
			r.pending[key]--
			r.counter.release(1, responsePayloadLimit(key))
		}
	}
}

// Close returns unanswered requests. A response already being read is released
// separately by the reader, so concurrent disconnects cannot double-decrement.
func (r *MessageRequests) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	var count, payloadBytes uint64
	for key, n := range r.pending {
		count += uint64(n)
		payloadBytes += uint64(n) * responsePayloadLimit(key)
	}
	clear(r.pending)
	r.counter.release(count, payloadBytes)
}
