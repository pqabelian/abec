package wire

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pqabelian/abec/chainhash"
)

type encodeLimitMessage struct {
	Message
	limit  uint32
	encode func(io.Writer) error
}

type cappedMessage struct {
	Message
	limit uint32
}

func (m cappedMessage) MaxPayloadLength(uint32) uint32 { return m.limit }

func (m *encodeLimitMessage) Command() string                { return "test" }
func (m *encodeLimitMessage) MaxPayloadLength(uint32) uint32 { return m.limit }
func (m *encodeLimitMessage) BtcEncode(w io.Writer, _ uint32, _ MessageEncoding) error {
	return m.encode(w)
}

func TestOutboundEncodingStopsAtLimit(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		for _, ignoreError := range []bool{false, true} {
			accepted := 0
			m := &encodeLimitMessage{limit: 16, encode: func(w io.Writer) error {
				for i := 0; i < 4; i++ {
					n, err := io.WriteString(w, "12345678")
					accepted += n
					if err != nil && !ignoreError {
						return err
					}
				}
				return nil
			}}
			var msg Message = m
			if wrapped {
				msg = WrapMessage(m, BaseEncoding)
			}
			var output bytes.Buffer
			n, err := WriteMessageN(&output, msg, ProtocolVersion, MainNet)
			var sizeErr *MessageError
			if !errors.As(err, &sizeErr) || sizeErr.Func != "WriteMessage" || n != 0 || output.Len() != 0 || accepted != 16 {
				t.Fatalf("wrapped=%v ignoreError=%v: accepted=%d output=%d n=%d err=%v", wrapped, ignoreError, accepted, output.Len(), n, err)
			}
			if cached, ok := msg.(*WrappedMessage); ok && (cached.Cached() || len(cached.Bytes()) != 0) {
				t.Fatal("oversized payload was published in the cache")
			}
		}
	}
}

func TestOutboundEncodingErrors(t *testing.T) {
	encodeErr := errors.New("encoding failed")
	for _, wrapped := range []bool{false, true} {
		var msg Message = &encodeLimitMessage{limit: 16, encode: func(w io.Writer) error {
			w.Write([]byte{1})
			return encodeErr
		}}
		if wrapped {
			msg = WrapMessage(msg, BaseEncoding)
		}
		var output bytes.Buffer
		n, err := WriteMessageN(&output, msg, ProtocolVersion, MainNet)
		if err != encodeErr || n != 0 || output.Len() != 0 {
			t.Fatalf("wrapped=%v: n=%d output=%d err=%v", wrapped, n, output.Len(), err)
		}
		if cached, ok := msg.(*WrappedMessage); ok && (cached.Cached() || len(cached.Bytes()) != 0) {
			t.Fatal("failed encoding was published in the cache")
		}
	}
}

func TestOutboundEncodingBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 16} {
		data := bytes.Repeat([]byte{0x5a}, size)
		m := &encodeLimitMessage{limit: uint32(size), encode: func(w io.Writer) error {
			_, err := w.Write(data)
			return err
		}}
		for _, msg := range []Message{m, WrapMessage(m, BaseEncoding)} {
			var output bytes.Buffer
			n, err := WriteMessageN(&output, msg, ProtocolVersion, MainNet)
			if err != nil || n != MessageHeaderSize+size || !bytes.Equal(output.Bytes()[MessageHeaderSize:], data) {
				t.Fatalf("size=%d msg=%T n=%d err=%v", size, msg, n, err)
			}
		}
	}
}

func TestConcurrentWrappedMessageEncoding(t *testing.T) {
	var encodes atomic.Int32
	m := &encodeLimitMessage{limit: 16, encode: func(w io.Writer) error {
		encodes.Add(1)
		_, err := w.Write([]byte("payload"))
		return err
	}}
	wrapped := WrapMessage(m, BaseEncoding)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			var output bytes.Buffer
			n, err := WriteMessageN(&output, wrapped, ProtocolVersion, MainNet)
			if err != nil || n != MessageHeaderSize+7 || string(output.Bytes()[MessageHeaderSize:]) != "payload" {
				t.Errorf("n=%d err=%v", n, err)
			}
		})
	}
	wg.Wait()
	if encodes.Load() != 1 {
		t.Fatalf("shared message encoded %d times", encodes.Load())
	}
}

func TestNeedSetResultEncodingBound(t *testing.T) {
	tx := NewMsgTxAbe(TxVersion_Height_0)
	tx.TxWitness = make([]byte, 4096)
	result := NewMsgNeedSetResult(chainhash.Hash{}, make([]*MsgTxAbe, 1000))
	for i := range result.Txs {
		result.Txs[i] = tx
	}
	// Exercise the real supplemental-response encoder at a smaller limit so
	// the regression needs neither a large allocation nor a network peer.
	limited := cappedMessage{Message: result, limit: 64 * 1024}
	for _, msg := range []Message{limited, WrapMessage(limited, WitnessEncoding)} {
		var output bytes.Buffer
		n, err := WriteMessageWithEncodingN(&output, msg, ProtocolVersion, MainNet, WitnessEncoding)
		if err == nil || n != 0 || output.Len() != 0 {
			t.Fatalf("oversized result published: msg=%T n=%d err=%v", msg, n, err)
		}
	}
}

func TestCachedMessageWireCompatibility(t *testing.T) {
	tx := NewMsgTxAbe(TxVersion_Height_464000_Aconcagua)
	tx.TxMemo, tx.TxWitness, tx.AutWitness = []byte{1}, []byte{2}, []byte{3}
	for _, encoding := range []MessageEncoding{BaseEncoding, WitnessEncoding} {
		var expected bytes.Buffer
		if _, err := WriteMessageWithEncodingN(&expected, tx, ProtocolVersion, MainNet, encoding); err != nil {
			t.Fatal(err)
		}
		wrapped := WrapMessage(tx, encoding)
		for i := 0; i < 2; i++ {
			var got bytes.Buffer
			if _, err := WriteMessageWithEncodingN(&got, wrapped, ProtocolVersion, MainNet, encoding); err != nil || !bytes.Equal(got.Bytes(), expected.Bytes()) {
				t.Fatalf("cached encoding=%d changed: %v", encoding, err)
			}
		}
	}
}
