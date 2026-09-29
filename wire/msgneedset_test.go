package wire

import (
	"bytes"
	"testing"

	"github.com/pqabelian/abec/chainhash"
)

func TestNeedSetDuplicateHashes(t *testing.T) {
	for _, hashes := range [][]chainhash.Hash{
		nil, {{1}}, {{1}, {2}}, {{1}, {1}}, {{1}, {2}, {1}},
	} {
		duplicate := len(hashes) > 1 && hashes[0] == hashes[len(hashes)-1]
		msg := NewMsgNeedSet(chainhash.Hash{3}, hashes)
		// Build the input independently so the decoder is exercised even when
		// the encoder rejects duplicate requests.
		var body bytes.Buffer
		body.Write(msg.BlockHash[:])
		if err := WriteVarInt(&body, ProtocolVersion, uint64(len(hashes))); err != nil {
			t.Fatal(err)
		}
		for _, hash := range hashes {
			body.Write(hash[:])
		}
		var decoded MsgNeedSet
		err := decoded.BtcDecode(bytes.NewReader(body.Bytes()), ProtocolVersion, BaseEncoding)
		if (err != nil) != duplicate {
			t.Fatalf("duplicate=%v decode err=%v", duplicate, err)
		}
		// Check the actual receive boundary with a complete valid checksum.
		var frame bytes.Buffer
		var command [CommandSize]byte
		copy(command[:], CmdNeedSet)
		var checksum [4]byte
		copy(checksum[:], chainhash.DoubleHashB(body.Bytes()))
		if err := writeElements(&frame, MainNet, command, uint32(body.Len()), checksum); err != nil {
			t.Fatal(err)
		}
		frame.Write(body.Bytes())
		_, received, _, err := ReadMessageWithRequestsN(&frame, ProtocolVersion, MainNet, BaseEncoding, &MessageRequests{})
		if (err != nil) != duplicate || (received == nil) != duplicate {
			t.Fatalf("duplicate=%v receive boundary returned msg=%v err=%v", duplicate, received, err)
		}
		var output bytes.Buffer
		err = msg.BtcEncode(&output, ProtocolVersion, BaseEncoding)
		if (err != nil) != duplicate {
			t.Fatalf("duplicate=%v encode err=%v", duplicate, err)
		}
		if duplicate && output.Len() != 0 {
			t.Fatal("duplicate request wrote bytes before validation")
		}
		if !duplicate && !bytes.Equal(output.Bytes(), body.Bytes()) {
			t.Fatal("unique request encoding changed")
		}
	}
}
