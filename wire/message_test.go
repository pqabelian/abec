package wire_test

import (
	"bytes"
	"testing"

	"github.com/abesuite/abec/chaincfg"
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

func TestMessageRequestCredits(t *testing.T) {
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
