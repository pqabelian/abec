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
	//key     string
	//mapping *sync.Map
	mu      sync.RWMutex
	counter int

	cacheMu sync.RWMutex
	cached  bool
	buf     *bytes.Buffer
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

func WrapMessage(msg Message) *WrappedMessage {
	return &WrappedMessage{
		Message: msg,
		mu:      sync.RWMutex{},
		counter: 0,
	}
}
func WrapMsgKey(msg Message) string {
	switch msg.Command() {
	case "block":
		blockMsg := msg.(*MsgBlockAbe)
		return fmt.Sprintf("block_%s", blockMsg.BlockHash())
	default:
		return ""
	}
}
