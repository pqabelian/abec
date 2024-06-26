package wire

import (
	"bytes"
	"fmt"
	"sync"
)

type Entry interface {
	Message

	Use()
	Done()
	CanDelete() bool
	Cached() bool

	Cache(pver uint32, encoding MessageEncoding)
	Bytes() []byte
}

type WrappedMessage struct {
	Message
	encoding MessageEncoding
	//key     string
	//mapping *sync.Map
	mu      sync.RWMutex
	counter int

	cacheMu sync.RWMutex
	cached  bool
	buf     *bytes.Buffer
}

func (m *WrappedMessage) Encoding() MessageEncoding {
	return m.encoding
}

func (m *WrappedMessage) Use() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
}

func (m *WrappedMessage) Done() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter--
}

func (m *WrappedMessage) CanDelete() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counter == 0
}
func (m *WrappedMessage) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.counter
}

func (m *WrappedMessage) Cached() bool {
	return m.cached
}
func (m *WrappedMessage) Bytes() []byte {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return m.buf.Bytes()
}
func (m *WrappedMessage) Cache(pver uint32, encoding MessageEncoding) {
	if m.cached {
		return
	}

	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if m.cached {
		return
	}
	m.buf = &bytes.Buffer{}
	m.BtcEncode(m.buf, pver, encoding)
	m.cached = true
}

func WrapMessage(msg Message, encoding MessageEncoding) *WrappedMessage {
	return &WrappedMessage{
		Message:  msg,
		encoding: encoding,
		mu:       sync.RWMutex{},
		counter:  0,
	}
}
func WrapMsgKey(msg Message, encoding MessageEncoding) string {
	switch msg.Command() {
	case "block":
		blockMsg := msg.(*MsgBlockAbe)
		return fmt.Sprintf("block_%s_%d", blockMsg.BlockHash(), encoding)
	case "tx":
		txMsg := msg.(*MsgTxAbe)
		return fmt.Sprintf("tx_%s_%d", txMsg.TxHash(), encoding)
	default:
		return ""
	}
}
