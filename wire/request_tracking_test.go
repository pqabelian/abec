package wire_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func dataRequest(typ wire.InvType, count int) *wire.MsgGetData {
	msg := wire.NewMsgGetData()
	for i := 0; i < count; i++ {
		hash := chainhash.Hash{byte(i)}
		msg.AddInvVect(wire.NewInvVect(typ, &hash))
	}
	return msg
}

func transactionRequest(tx *wire.MsgTxAbe) *wire.MsgGetData {
	request := dataRequest(wire.InvTypeTx, 1)
	request.InvList[0].Hash = tx.TxHash()
	return request
}

func TestReadErrorsPreservePendingRequests(t *testing.T) {
	data := encodedMessage(t, wire.NewMsgTxAbe(wire.TxVersion_Height_0))
	badChecksum := append([]byte(nil), data...)
	badChecksum[len(badChecksum)-1] ^= 1
	oversized := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(oversized[16:20], 32*1024*1024+1)
	for name, input := range map[string][]byte{"checksum": badChecksum, "truncated": data[:len(data)-1], "oversized": oversized} {
		t.Run(name, func(t *testing.T) {
			r := wire.NewMessageRequests()
			r.Add(transactionRequest(wire.NewMsgTxAbe(wire.TxVersion_Height_0)))
			reader := bytes.NewReader(input)
			n, _, _, err := wire.ReadMessageWithRequestsN(reader, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, r)
			if err == nil {
				t.Fatal("invalid response was accepted")
			}
			if name == "oversized" && n != wire.MessageHeaderSize {
				t.Fatal("oversized payload was read before rejection")
			}
			if !r.Expired(time.Now()) {
				t.Fatal("invalid response consumed the pending request")
			}
			r.Close() // The connection owner closes the tracker after a read failure.
			if r.Expired(time.Now()) {
				t.Fatal("closed tracker retained a request")
			}
		})
	}
}
