package wire

import "sync"

// RequestCounter limits outstanding data requests across all server connections.
// Admission uses count by response type multiplied by its protocol payload
// maximum. It does not track actual payload sizes or downstream processing.
type RequestCounter struct {
	mu           sync.Mutex
	limit        uint64 // Sum of protocol payload maxima for outstanding responses.
	requests     uint64
	payloadBytes uint64
	changed      chan struct{}
}

func NewRequestCounter(limit uint64) *RequestCounter {
	return &RequestCounter{limit: limit, changed: make(chan struct{})}
}

func (c *RequestCounter) reserve(count, payloadBytes uint64) bool {
	if c == nil || count == 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if payloadBytes > c.limit-c.payloadBytes {
		return false
	}
	c.requests += count
	c.payloadBytes += payloadBytes
	return true
}

func (c *RequestCounter) release(count, payloadBytes uint64) {
	if c == nil || count == 0 {
		return
	}
	c.mu.Lock()
	c.requests -= count
	c.payloadBytes -= payloadBytes
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
}

// Changed is closed when requests finish. Fetch it before trying to register
// requests to avoid missing a concurrent release.
func (c *RequestCounter) Changed() <-chan struct{} {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed
}

// Usage returns outstanding request count and the sum of their response payload maxima.
func (c *RequestCounter) Usage() (requests, payloadBytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests, c.payloadBytes
}

// responsePayloadLimit uses the same protocol limit enforced by the decoder.
func responsePayloadLimit(key string) uint64 {
	switch key {
	case InvTypeBlock.String(), InvTypeWitnessBlock.String():
		return uint64((&MsgBlockAbe{}).MaxPayloadLength(ProtocolVersion))
	case InvTypePrunedBlock.String():
		return uint64((&MsgPrunedBlock{}).MaxPayloadLength(ProtocolVersion))
	case InvTypeTx.String(), InvTypeWitnessTx.String():
		return uint64((&MsgTxAbe{}).MaxPayloadLength(ProtocolVersion))
	case CmdGetBlockTx:
		return uint64((&MsgBlockTx{}).MaxPayloadLength(ProtocolVersion))
	case CmdNeedSet:
		return uint64((&MsgNeedSetResult{}).MaxPayloadLength(ProtocolVersion))
	case CmdGetHeaders:
		return uint64((&MsgHeaders{}).MaxPayloadLength(ProtocolVersion))
	}
	return 0
}
