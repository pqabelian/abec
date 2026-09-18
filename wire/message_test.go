package wire_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func encodedMessage(t *testing.T, msg wire.Message) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := wire.WriteMessage(&b, msg, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestMessageRequestsRequirePendingResponse(t *testing.T) {
	cases := []struct {
		name    string
		invType wire.InvType
		msg     wire.Message
	}{
		{"headers", wire.InvTypeError, wire.NewMsgHeaders()},
		{"base-block", wire.InvTypeBlock, chaincfg.MainNetParams.GenesisBlock},
		{"witness-block", wire.InvTypeWitnessBlock, chaincfg.MainNetParams.GenesisBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := encodedMessage(t, tc.msg)
			var requests wire.MessageRequests
			var request wire.Message = wire.NewMsgGetHeaders()
			if tc.invType != wire.InvTypeError {
				getData := wire.NewMsgGetData()
				hash := chaincfg.MainNetParams.GenesisBlock.BlockHash()
				getData.AddInvVect(wire.NewInvVect(tc.invType, &hash))
				request = getData
			}
			// One request permits exactly one response, across repeated cycles.
			for i := 0; i < 2; i++ {
				requests.Add(request)
				if _, _, _, err := wire.ReadMessageWithRequestsN(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, &requests); err != nil {
					t.Fatal(err)
				}
				buf := bytes.NewReader(data)
				n, _, _, err := wire.ReadMessageWithRequestsN(buf, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, &requests)
				if err == nil || n != wire.MessageHeaderSize || buf.Len() != len(data)-wire.MessageHeaderSize {
					t.Fatalf("unsolicited response must be rejected before reading its payload: n=%d err=%v", n, err)
				}
			}
		})
	}
}

func TestReadMessageRoundTrip(t *testing.T) {
	// Both readers below pass a nil request tracker. Include notfound to cover
	// its request-accounting hook as well as ordinary response consumption.
	for _, msg := range []wire.Message{wire.NewMsgHeaders(), wire.NewMsgTxAbe(wire.TxVersion_Height_0), chaincfg.MainNetParams.GenesisBlock, wire.NewMsgNotFound()} {
		t.Run(msg.Command(), func(t *testing.T) {
			data := encodedMessage(t, msg)
			decoded, _, err := wire.ReadMessage(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet)
			if err != nil || decoded.Command() != msg.Command() {
				t.Fatalf("stateless message roundtrip failed: %v", err)
			}
			if _, _, _, err := wire.ReadMessageWithEncodingN(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding); err != nil {
				t.Fatal(err)
			}
			data[len(data)-1] ^= 1
			if _, _, err := wire.ReadMessage(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet); err == nil {
				t.Fatal("stateless reader accepted a corrupted checksum")
			}
		})
	}
}

// Observe the first payload read without supplying a potentially huge body.
type headerOnlyPayloadProbe struct {
	*bytes.Reader
	window int
}

func (r *headerOnlyPayloadProbe) Read(p []byte) (int, error) {
	if r.Reader.Len() != 0 {
		return r.Reader.Read(p)
	}
	r.window = len(p)
	return 0, io.EOF
}

func TestLargeDeclaredResponseDoesNotPreallocatePayload(t *testing.T) {
	requests := wire.NewMessageRequests()
	defer requests.Close()
	hash := chainhash.Hash{1}
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	requests.Add(wire.NewMsgGetBlockTx(hash, tx.TxHash()))
	data := encodedMessage(t, wire.NewMsgBlockTx(hash, tx))
	header := append([]byte(nil), data[:wire.MessageHeaderSize]...)
	binary.LittleEndian.PutUint32(header[16:20], (&wire.MsgBlockTx{}).MaxPayloadLength(wire.ProtocolVersion))
	r := &headerOnlyPayloadProbe{Reader: bytes.NewReader(header)}
	n, msg, payload, err := wire.ReadMessageWithRequestsN(r, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, requests)
	if err != io.EOF || n != wire.MessageHeaderSize || msg != nil || payload != nil {
		t.Fatalf("changed header-only read result: n=%d msg=%T payload=%d err=%v", n, msg, len(payload), err)
	}
	if r.window == 0 || r.window > 64*1024 {
		t.Fatalf("large payload allocated before its body arrived: read window=%d", r.window)
	}
	requests.Close()
}

func TestLargeMessageRoundTripAndNextFrame(t *testing.T) {
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = bytes.Repeat([]byte{1}, 256*1024)
	var frame bytes.Buffer
	if _, err := wire.WriteMessageWithEncodingN(&frame, tx, wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}
	for _, corrupt := range []bool{false, true} {
		data := append([]byte(nil), frame.Bytes()...)
		if corrupt {
			data[len(data)-1] ^= 1
		}
		data = append(data, encodedMessage(t, wire.NewMsgPing(7))...)
		r := bytes.NewReader(data)
		n, msg, raw, err := wire.ReadMessageWithEncodingN(r, wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding)
		if (err != nil) != corrupt || n != frame.Len() {
			t.Fatalf("incorrect checksum or byte count: corrupt=%v n=%d err=%v", corrupt, n, err)
		}
		if !corrupt && (msg.(*wire.MsgTxAbe).TxHash() != tx.TxHash() || !bytes.Equal(raw, frame.Bytes()[wire.MessageHeaderSize:])) {
			t.Fatal("large response changed decoded identity or raw payload")
		}
		next, _, err := wire.ReadMessage(r, wire.ProtocolVersion, wire.MainNet)
		if err != nil || next.(*wire.MsgPing).Nonce != 7 {
			t.Fatalf("read consumed the next frame: %v", err)
		}
	}
}
