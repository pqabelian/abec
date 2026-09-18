package wire_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"testing"

	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func dataRequest(typ wire.InvType, count int) *wire.MsgGetData {
	msg := wire.NewMsgGetData()
	for i := 0; i < count; i++ {
		hash := chainhash.Hash{byte(i)}
		msg.AddInvVect(wire.NewInvVect(typ, &hash))
	}
	return msg
}

func TestSharedRequestCounterLifetime(t *testing.T) {
	const limit = 512 * 1024 * 1024
	counter := wire.NewRequestCounter(limit)
	a, b := wire.NewMessageRequests(counter), wire.NewMessageRequests(counter)
	blocks := dataRequest(wire.InvTypeWitnessBlock, 2)
	blocks.InvList[0].Hash = chaincfg.MainNetParams.GenesisBlock.BlockHash()
	if !a.Add(blocks) || b.Add(dataRequest(wire.InvTypeTx, 1)) {
		t.Fatal("connections did not share the global limit")
	}
	if count, size := counter.Usage(); count != 2 || size != limit {
		t.Fatalf("unexpected usage: %d requests, %d payload bytes", count, size)
	}
	changed := counter.Changed()
	data := encodedMessage(t, chaincfg.MainNetParams.GenesisBlock)
	if _, _, _, err := wire.ReadMessageWithRequestsN(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, a); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("received response did not wake waiting connections")
	}
	if count, size := counter.Usage(); count != 1 || size != wire.MaxBlockPayloadAbe {
		t.Fatalf("complete response did not release its protocol maximum: %d, %d", count, size)
	}
	if !b.Add(dataRequest(wire.InvTypeTx, 1)) {
		t.Fatal("freed capacity was not made available")
	}
	if count, size := counter.Usage(); count != 2 || size != wire.MaxBlockPayloadAbe+uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)) {
		t.Fatalf("mixed response types were not counted by their respective maxima: %d, %d", count, size)
	}
	a.Close()
	b.Close()
	a.Close()
	if a.Add(dataRequest(wire.InvTypeTx, 1)) {
		t.Fatal("closed connection registered more requests")
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("disconnect leaked or underflowed counts: %d, %d", count, size)
	}
}

func TestRequestCounterSplitsGetData(t *testing.T) {
	counter := wire.NewRequestCounter(512 * 1024 * 1024)
	requests := wire.NewMessageRequests(counter)
	msg := dataRequest(wire.InvTypeBlock, 5)
	if requests.Add(msg) {
		t.Fatal("oversized atomic request was admitted")
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatal("rejected atomic request acquired partial credits")
	}
	var remaining wire.Message = msg
	var hashes []chainhash.Hash
	for remaining != nil {
		part, rest := requests.ReserveNext(remaining)
		if part == nil {
			t.Fatal("a request that fits the counter was not admitted")
		}
		batch := part.(*wire.MsgGetData)
		if len(batch.InvList) > 2 {
			t.Fatal("fragment exceeds global capacity")
		}
		for _, iv := range batch.InvList {
			hashes = append(hashes, iv.Hash)
			nf := wire.NewMsgNotFound()
			nf.AddInvVect(iv)
			if _, _, _, err := wire.ReadMessageWithRequestsN(bytes.NewReader(encodedMessage(t, nf)), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, requests); err != nil {
				t.Fatal(err)
			}
		}
		remaining = rest
	}
	for i, hash := range hashes {
		if hash != msg.InvList[i].Hash {
			t.Fatal("fragmentation reordered inventory")
		}
	}
	if len(hashes) != len(msg.InvList) {
		t.Fatal("fragmentation lost inventory")
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("notfound leaked counts: %d, %d", count, size)
	}
}

func TestRequestsUseResponsePayloadLimits(t *testing.T) {
	cases := []struct{ request, response wire.Message }{
		{dataRequest(wire.InvTypeTx, 1), &wire.MsgTxAbe{}},
		{dataRequest(wire.InvTypeWitnessTx, 1), &wire.MsgTxAbe{}},
		{dataRequest(wire.InvTypeBlock, 1), &wire.MsgBlockAbe{}},
		{dataRequest(wire.InvTypeWitnessBlock, 1), &wire.MsgBlockAbe{}},
		{dataRequest(wire.InvTypePrunedBlock, 1), &wire.MsgPrunedBlock{}},
		{wire.NewMsgGetBlockTx(chainhash.Hash{}, chainhash.Hash{}), &wire.MsgBlockTx{}},
		{wire.NewMsgNeedSet(chainhash.Hash{}, nil), &wire.MsgNeedSetResult{}},
		{wire.NewMsgGetHeaders(), &wire.MsgHeaders{}},
	}
	for _, tc := range cases {
		t.Run(tc.request.Command(), func(t *testing.T) {
			limit := uint64(tc.response.MaxPayloadLength(wire.ProtocolVersion))
			counter := wire.NewRequestCounter(limit)
			r := wire.NewMessageRequests(counter)
			if !r.Add(tc.request) || r.Add(tc.request) {
				t.Fatal("one response maximum must admit exactly one request")
			}
			if count, size := counter.Usage(); count != 1 || size != limit {
				t.Fatalf("incorrect request count or protocol maximum: %d, %d", count, size)
			}
			r.Close()
		})
	}
}

func TestRequestCounterReadErrors(t *testing.T) {
	data := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	badChecksum := append([]byte(nil), data...)
	badChecksum[len(badChecksum)-1] ^= 1
	oversized := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(oversized[16:20], 32*1024*1024+1)
	for name, input := range map[string][]byte{"checksum": badChecksum, "truncated": data[:len(data)-1], "oversized": oversized} {
		t.Run(name, func(t *testing.T) {
			counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
			r := wire.NewMessageRequests(counter)
			r.Add(transactionRequest(wire.NewMsgTxAbe(wire.TxVersion_Height_0)))
			reader := bytes.NewReader(input)
			n, _, _, err := wire.ReadMessageWithRequestsN(reader, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
			if err == nil {
				t.Fatal("invalid response was accepted")
			}
			if name == "oversized" && n != wire.MessageHeaderSize {
				t.Fatal("oversized payload was read before rejection")
			}
			r.Close() // The connection owner closes the tracker after a read failure.
			if count, size := counter.Usage(); count != 0 || size != 0 {
				t.Fatalf("read error leaked counts: %d, %d", count, size)
			}
		})
	}
}

func transactionRequest(tx *wire.MsgTxAbe) *wire.MsgGetData {
	request := dataRequest(wire.InvTypeTx, 1)
	request.InvList[0].Hash = tx.TxHash()
	return request
}

func TestRequestCounterConcurrentConnections(t *testing.T) {
	limit := 16 * uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion))
	counter := wire.NewRequestCounter(limit)
	data := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := wire.NewMessageRequests(counter)
			defer r.Close()
			for j := 0; j < 50; j++ {
				if !r.Add(transactionRequest(wire.NewMsgTxAbe(wire.TxVersion_Height_0))) {
					t.Error("capacity for 16 simultaneous transactions was exceeded")
					return
				}
				_, _, _, err := wire.ReadMessageWithRequestsN(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
				if err != nil {
					t.Error(err)
					return
				}
				if count, size := counter.Usage(); count > 16 || size > limit {
					t.Error("concurrent peers exceeded the global cap")
				}
			}
		}()
	}
	wg.Wait()
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("concurrent connections leaked counts: %d, %d", count, size)
	}
}

type pausedPayload struct {
	io.Reader
	started chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (p *pausedPayload) Read(b []byte) (int, error) {
	p.once.Do(func() {
		close(p.started)
		<-p.resume
	})
	return p.Reader.Read(b)
}

func TestReadingResponseRemainsCountedAcrossDisconnect(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	r := wire.NewMessageRequests(counter)
	r.Add(transactionRequest(wire.NewMsgTxAbe(wire.TxVersion_Height_0)))
	data := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	payload := &pausedPayload{bytes.NewReader(data[wire.MessageHeaderSize:]), make(chan struct{}), make(chan struct{}), sync.Once{}}
	done := make(chan error, 1)
	go func() {
		_, _, _, err := wire.ReadMessageWithRequestsN(io.MultiReader(bytes.NewReader(data[:wire.MessageHeaderSize]), payload), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
		done <- err
	}()
	<-payload.started
	r.Close()
	r.Close()
	count, size := counter.Usage()
	close(payload.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if count != 1 || size != uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)) {
		t.Fatalf("header read or disconnect released an incomplete response: %d, %d", count, size)
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("reader completion leaked or underflowed counts: %d, %d", count, size)
	}
}

func TestUnsolicitedTxReadIsCounted(t *testing.T) {
	valid := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	badChecksum := append([]byte(nil), valid...)
	badChecksum[len(badChecksum)-1] ^= 1
	for name, data := range map[string][]byte{"valid": valid, "checksum": badChecksum, "truncated": valid[:len(valid)-1]} {
		t.Run(name, func(t *testing.T) {
			limit := uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion))
			counter := wire.NewRequestCounter(limit)
			r := wire.NewMessageRequests(counter)
			payload := &pausedPayload{bytes.NewReader(data[wire.MessageHeaderSize:]), make(chan struct{}), make(chan struct{}), sync.Once{}}
			done := make(chan error, 1)
			go func() {
				_, _, _, err := wire.ReadMessageWithRequestsN(io.MultiReader(bytes.NewReader(data[:wire.MessageHeaderSize]), payload), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
				done <- err
			}()
			<-payload.started
			r.Close()
			count, size := counter.Usage()
			close(payload.resume)
			err := <-done
			if (name == "valid") != (err == nil) {
				t.Fatalf("unexpected relay decode result: %v", err)
			}
			if count != 1 || size != limit {
				t.Fatalf("direct relay read was uncounted: %d, %d", count, size)
			}
			if count, size := counter.Usage(); count != 0 || size != 0 {
				t.Fatalf("direct relay read leaked credits: %d, %d", count, size)
			}
		})
	}
}

func TestUnsolicitedTxRespectsFullCounter(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	holder := wire.NewMessageRequests(counter)
	holder.Add(dataRequest(wire.InvTypeTx, 1))
	defer holder.Close()
	r := wire.NewMessageRequests(counter)
	defer r.Close()
	data := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	reader := bytes.NewReader(data)
	n, _, _, err := wire.ReadMessageWithRequestsN(reader, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
	if err != wire.ErrResponseLimit || n != wire.MessageHeaderSize || reader.Len() != len(data)-wire.MessageHeaderSize {
		t.Fatalf("full counter did not reject direct tx before payload allocation: n=%d err=%v", n, err)
	}
	if count, _ := counter.Usage(); count != 1 {
		t.Fatal("rejected relay changed another connection's count")
	}
}
