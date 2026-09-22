package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func TestLegacyNeedSetIsServeOnly(t *testing.T) {
	request := wire.NewMsgNeedSet(chainhash.Hash{1}, nil)
	response := wire.NewMsgNeedSetResult(request.BlockHash, nil)
	r := wire.NewMessageRequests()
	defer r.Close()
	if r.Add(request) || r.Expired(time.Now()) {
		t.Fatal("outgoing needset registered a pending request")
	}
	if !r.Add(response) || r.Expired(time.Now()) {
		t.Fatal("serving nsresult created a pending request")
	}
	// An incoming needset is a service request, not a response to local work.
	if _, msg, _, err := wire.ReadMessageWithRequestsN(bytes.NewReader(encodedMessage(t, request)), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r); err != nil || msg.Command() != wire.CmdNeedSet {
		t.Fatalf("legacy service request was rejected: %v", err)
	}
	// Other pending work must not authorize a legacy result for the same block.
	r.Add(wire.NewMsgGetBlockTx(request.BlockHash, chainhash.Hash{}))
	data := encodedMessage(t, response)
	reader := bytes.NewReader(data)
	n, msg, payload, err := wire.ReadMessageWithRequestsN(reader, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
	if !errors.Is(err, wire.ErrUnrequestedResponse) || n != wire.MessageHeaderSize ||
		reader.Len() != len(data)-wire.MessageHeaderSize || msg != nil || payload != nil || !r.Expired(time.Now()) {
		t.Fatalf("legacy response was accepted or changed unrelated work: n=%d err=%v", n, err)
	}
}

func TestNeedSetResultStopsBeforePayloadDiscard(t *testing.T) {
	for _, malformed := range []string{"wrong network", "oversized payload"} {
		t.Run(malformed, func(t *testing.T) {
			data := encodedMessage(t, wire.NewMsgNeedSetResult(chainhash.Hash{}, nil))
			if malformed == "wrong network" {
				binary.LittleEndian.PutUint32(data[:4], uint32(wire.TestNet))
			} else {
				binary.LittleEndian.PutUint32(data[16:20], wire.MaxMessagePayload+1)
			}
			reader := bytes.NewReader(data)
			n, decoded, payload, err := wire.ReadMessageWithRequestsN(reader, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, wire.NewMessageRequests())
			if !errors.Is(err, wire.ErrUnrequestedResponse) || n != wire.MessageHeaderSize ||
				reader.Len() != len(data)-wire.MessageHeaderSize || decoded != nil || payload != nil {
				t.Fatalf("legacy response did not stop at its header: n=%d remaining=%d err=%v", n, reader.Len(), err)
			}
		})
	}
}
