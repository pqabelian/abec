package wire

import (
	"bytes"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/pqabelian/abec/chainhash"
)

func TestDecodeCollectionShortBody(t *testing.T) {
	var header, coinbase bytes.Buffer
	bh := BlockHeader{}
	if err := bh.WriteBlockHeader(&header, ProtocolVersion); err != nil {
		t.Fatal(err)
	}
	if err := NewMsgTxAbe(TxVersion_Height_0).BtcEncode(&coinbase, ProtocolVersion, WitnessEncoding); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		msg    Message
		prefix []byte
		field  string
		count  uint64
	}{
		{&MsgBlockAbe{}, header.Bytes(), "Transactions", 65536},
		{&MsgPrunedBlock{}, append(append([]byte{}, header.Bytes()...), coinbase.Bytes()...), "TransactionHashes", 65536},
		{&MsgNeedSet{}, make([]byte, chainhash.HashSize), "Hashes", 65536},
		{&MsgNeedSetResult{}, make([]byte, chainhash.HashSize), "Txs", 65536},
		{&MsgInv{}, nil, "InvList", MaxInvPerMsg},
		{&MsgGetData{}, nil, "InvList", MaxInvPerMsg},
		{&MsgNotFound{}, nil, "InvList", MaxInvPerMsg},
		{&MsgGetBlocks{}, make([]byte, 4), "BlockLocatorHashes", MaxBlockLocatorsPerMsg},
		{&MsgGetHeaders{}, make([]byte, 4), "BlockLocatorHashes", MaxBlockLocatorsPerMsg},
		{&MsgHeaders{}, nil, "Headers", MaxBlockHeadersPerMsg},
		{&MsgAddr{}, nil, "AddrList", MaxAddrPerMsg},
	} {
		t.Run(tc.msg.Command(), func(t *testing.T) {
			body := bytes.NewBuffer(append([]byte{}, tc.prefix...))
			if err := WriteVarInt(body, ProtocolVersion, tc.count); err != nil {
				t.Fatal(err)
			}
			if err := tc.msg.BtcDecode(body, ProtocolVersion, WitnessEncoding); err == nil {
				t.Fatal("accepted missing collection elements")
			}
			if capacity := reflect.ValueOf(tc.msg).Elem().FieldByName(tc.field).Cap(); capacity != 0 {
				t.Fatalf("allocated collection for missing elements: capacity=%d", capacity)
			}
		})
	}

	body := bytes.NewBuffer(append([]byte{}, header.Bytes()...))
	if err := WriteVarInt(body, ProtocolVersion, 65536); err != nil {
		t.Fatal(err)
	}
	var block MsgBlockAbe
	if _, err := block.DeserializeTxLoc(body); err == nil || cap(block.Transactions) != 0 {
		t.Fatalf("transaction-location decoder allocated missing transactions: %v", err)
	}
}

func TestDecodeVarFieldsShortBody(t *testing.T) {
	for _, read := range []struct {
		name string
		fn   func(io.Reader) error
	}{
		{"bytes", func(r io.Reader) error { _, err := ReadVarBytes(r, 0, MaxMessagePayload, "field"); return err }},
		{"string", func(r io.Reader) error { _, err := ReadVarString(r, 0); return err }},
	} {
		for _, newReader := range []struct {
			name string
			fn   func([]byte) io.Reader
		}{
			{"buffer", func(b []byte) io.Reader { return bytes.NewBuffer(b) }},
			{"bytes-reader", func(b []byte) io.Reader { return bytes.NewReader(b) }},
			{"string-reader", func(b []byte) io.Reader { return strings.NewReader(string(b)) }},
		} {
			t.Run(read.name+"/"+newReader.name, func(t *testing.T) {
				for _, supplied := range []int{0, 3} {
					var body bytes.Buffer
					if err := WriteVarInt(&body, 0, 4<<20); err != nil {
						t.Fatal(err)
					}
					body.Write(make([]byte, supplied))
					r := newReader.fn(body.Bytes())
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					err := read.fn(r)
					runtime.ReadMemStats(&after)
					want := io.EOF
					if supplied != 0 {
						want = io.ErrUnexpectedEOF
					}
					if err != want {
						t.Fatalf("error=%v, want %v", err, want)
					}
					if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
						t.Fatalf("short field allocated %d bytes", allocated)
					}
				}
			})
		}
	}
}

func TestDecodeVersionShortUserAgent(t *testing.T) {
	// A complete, checksum-valid version frame whose user-agent length exceeds
	// its actual body must not allocate the declared string length.
	var body bytes.Buffer
	if err := (&MsgVersion{UserAgent: ""}).BtcEncode(&body, ProtocolVersion, BaseEncoding); err != nil {
		t.Fatal(err)
	}
	// Version, services, timestamp, two addresses without timestamps, nonce.
	body.Truncate(4 + 8 + 8 + 26 + 26 + 8)
	if err := WriteVarInt(&body, ProtocolVersion, 4<<20); err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	var command [CommandSize]byte
	copy(command[:], CmdVersion)
	var checksum [4]byte
	copy(checksum[:], chainhash.DoubleHashB(body.Bytes()))
	if err := writeElements(&frame, MainNet, command, uint32(body.Len()), checksum); err != nil {
		t.Fatal(err)
	}
	frame.Write(body.Bytes())
	wantRead := frame.Len()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	n, msg, _, err := ReadMessageN(&frame, ProtocolVersion, MainNet)
	runtime.ReadMemStats(&after)
	if err != io.EOF || msg != nil || n != wantRead {
		t.Fatalf("short user agent: n=%d msg=%v err=%v", n, msg, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 1<<20 {
		t.Fatalf("short version frame allocated %d bytes", allocated)
	}
}

func TestDecodeVarFieldsRoundTrip(t *testing.T) {
	for _, value := range []string{"", "complete field"} {
		var body bytes.Buffer
		if err := WriteVarString(&body, 0, value); err != nil {
			t.Fatal(err)
		}
		data := append(body.Bytes(), 0xaa)
		for _, r := range []io.Reader{bytes.NewBuffer(data), bytes.NewReader(data), strings.NewReader(string(data)), struct{ io.Reader }{bytes.NewReader(data)}} {
			got, err := ReadVarString(r, 0)
			var next [1]byte
			_, nextErr := io.ReadFull(r, next[:])
			if err != nil || got != value || nextErr != nil || next[0] != 0xaa {
				t.Fatalf("field or next byte changed: value=%q reader=%T err=%v nextErr=%v", value, r, err, nextErr)
			}
		}
		for _, r := range []io.Reader{bytes.NewBuffer(data), bytes.NewReader(data), struct{ io.Reader }{bytes.NewReader(data)}} {
			got, err := ReadVarBytes(r, 0, uint32(len(value)), "field")
			if err != nil || string(got) != value {
				t.Fatalf("byte field changed: value=%q reader=%T err=%v", value, r, err)
			}
		}
	}
}

func TestDecodeCollectionRoundTrip(t *testing.T) {
	hash := chainhash.Hash{1}
	for _, version := range []uint32{TxVersion_Height_0, TxVersion_Height_464000_Aconcagua} {
		tx := NewMsgTxAbe(version)
		tx.TxWitness = []byte{1}
		for _, encoding := range []MessageEncoding{BaseEncoding, WitnessEncoding} {
			block := &MsgBlockAbe{}
			block.AddTransaction(tx)
			pruned := &MsgPrunedBlock{CoinbaseTx: tx}
			pruned.AddTransactionHash(tx)
			messages := []Message{
				block, pruned, &MsgNeedSet{Hashes: []chainhash.Hash{hash}},
				&MsgPrunedBlock{CoinbaseTx: tx}, &MsgNeedSet{}, &MsgNeedSetResult{},
				&MsgInv{}, &MsgGetData{}, &MsgNotFound{}, &MsgGetBlocks{}, &MsgGetHeaders{}, &MsgHeaders{}, &MsgAddr{},
				&MsgInv{InvList: []*InvVect{{Type: InvTypeTx, Hash: hash}}},
				&MsgGetData{InvList: []*InvVect{{Type: InvTypeTx, Hash: hash}}},
				&MsgNotFound{InvList: []*InvVect{{Type: InvTypeTx, Hash: hash}}},
				&MsgGetBlocks{BlockLocatorHashes: []*chainhash.Hash{&hash}},
				&MsgGetHeaders{BlockLocatorHashes: []*chainhash.Hash{&hash}},
				&MsgHeaders{Headers: []*BlockHeader{{}, {Version: int32(BlockVersionEthashPow)}, {Version: int32(BlockVersionAconcagua)}}},
				&MsgAddr{AddrList: []*NetAddress{{}}},
			}
			if encoding == BaseEncoding {
				messages = append(messages, &MsgBlockAbe{})
			}
			// Needset results always deserialize transactions with witnesses.
			if encoding == WitnessEncoding {
				messages = append(messages, &MsgNeedSetResult{Txs: []*MsgTxAbe{tx}})
			}
			for _, msg := range messages {
				var body bytes.Buffer
				if err := msg.BtcEncode(&body, ProtocolVersion, encoding); err != nil {
					t.Fatal(err)
				}
				data := append([]byte{}, body.Bytes()...)
				for _, r := range []io.Reader{bytes.NewBuffer(data), bytes.NewReader(data), struct{ io.Reader }{bytes.NewReader(data)}} {
					decoded, err := makeEmptyMessage(msg.Command())
					if err != nil {
						t.Fatal(err)
					}
					if err := decoded.BtcDecode(r, ProtocolVersion, encoding); err != nil {
						t.Fatalf("%s version=%d encoding=%d reader=%T: %v", msg.Command(), version, encoding, r, err)
					}
					var encoded bytes.Buffer
					if err := decoded.BtcEncode(&encoded, ProtocolVersion, encoding); err != nil || !bytes.Equal(encoded.Bytes(), data) {
						t.Fatalf("%s round trip changed data: %v", msg.Command(), err)
					}
				}
			}
		}
	}
}
