package wire_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func readTrackedResponse(t *testing.T, requests *wire.MessageRequests, msg wire.Message) error {
	t.Helper()
	var b bytes.Buffer
	if _, err := wire.WriteMessageWithEncodingN(&b, msg, wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := wire.ReadMessageWithRequestsN(&b, wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding, requests)
	return err
}

func TestNotFoundMatchesInventoryIdentity(t *testing.T) {
	txA, txB := wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	txA.TxMemo, txB.TxMemo = []byte{1}, []byte{2}
	a, b := txA.TxHash(), txB.TxHash()
	requests := wire.NewMessageRequests()
	defer requests.Close()
	gd := wire.NewMsgGetData()
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessTx, &a))
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessTx, &b))
	requests.Add(gd)

	for _, iv := range []*wire.InvVect{
		wire.NewInvVect(wire.InvTypeWitnessTx, &chainhash.Hash{99}),
		wire.NewInvVect(wire.InvTypeTx, &a), // Wrong inventory type.
	} {
		nf := wire.NewMsgNotFound()
		nf.AddInvVect(iv)
		if err := readTrackedResponse(t, requests, nf); err != nil {
			t.Fatal(err)
		}
		if count, _ := requests.GetDataStatus(); count != 2 {
			t.Fatal("unrequested notfound consumed another request")
		}
	}
	nf := wire.NewMsgNotFound()
	nf.AddInvVect(gd.InvList[0])
	nf.AddInvVect(gd.InvList[0])
	for i := 0; i < 2; i++ {
		if err := readTrackedResponse(t, requests, nf); err != nil {
			t.Fatal(err)
		}
		if count, _ := requests.GetDataStatus(); count != 1 {
			t.Fatal("duplicate notfound consumed B's request")
		}
	}
	if err := readTrackedResponse(t, requests, txB); err != nil {
		t.Fatalf("requested B was rejected after duplicate notfound(A): %v", err)
	}
	if count, _ := requests.GetDataStatus(); count != 0 {
		t.Fatalf("matched response left %d requests", count)
	}
}

func TestResponseMatchesRequestIdentity(t *testing.T) {
	txA, txB := wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	txA.TxMemo, txB.TxMemo = []byte{1}, []byte{2}
	txA.TxWitness, txB.TxWitness = []byte{3}, []byte{4}
	block := chaincfg.MainNetParams.GenesisBlock
	otherBlock := *block
	otherBlock.Header.Timestamp = otherBlock.Header.Timestamp.Add(time.Second)
	blockHash, otherHash := block.BlockHash(), otherBlock.BlockHash()
	pruned := &wire.MsgPrunedBlock{Header: block.Header, CoinbaseTx: block.Transactions[0]}
	otherPruned := *pruned
	otherPruned.Header = otherBlock.Header
	cases := []struct {
		name    string
		request wire.Message
		valid   wire.Message
		wrong   []wire.Message
	}{
		{"blocktx", wire.NewMsgGetBlockTx(blockHash, txA.TxHash()), wire.NewMsgBlockTx(blockHash, txA), []wire.Message{
			wire.NewMsgBlockTx(otherHash, txA), wire.NewMsgBlockTx(blockHash, txB),
		}},
		{"needset", wire.NewMsgNeedSet(blockHash, []chainhash.Hash{txA.TxHash(), txB.TxHash()}), wire.NewMsgNeedSetResult(blockHash, []*wire.MsgTxAbe{txB, txA}), []wire.Message{
			wire.NewMsgNeedSetResult(otherHash, []*wire.MsgTxAbe{txA, txB}),
		}},
	}
	for _, tc := range []struct {
		typ          wire.InvType
		hash         chainhash.Hash
		valid, wrong wire.Message
	}{
		{wire.InvTypeTx, txA.TxHash(), txA, txB},
		{wire.InvTypeWitnessTx, txA.TxHash(), txA, txB},
		{wire.InvTypeBlock, blockHash, block, &otherBlock},
		{wire.InvTypeWitnessBlock, blockHash, block, &otherBlock},
		{wire.InvTypePrunedBlock, blockHash, pruned, &otherPruned},
	} {
		gd := wire.NewMsgGetData()
		gd.AddInvVect(wire.NewInvVect(tc.typ, &tc.hash))
		cases = append(cases, struct {
			name    string
			request wire.Message
			valid   wire.Message
			wrong   []wire.Message
		}{tc.typ.String(), gd, tc.valid, []wire.Message{tc.wrong}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := wire.NewMessageRequests()
			defer requests.Close()
			if !requests.Add(tc.request) {
				t.Fatal("request was not admitted")
			}
			for _, wrong := range tc.wrong {
				err := readTrackedResponse(t, requests, wrong)
				// Direct tx relay may be allowed, but must never satisfy a
				// request for a different transaction.
				if wrong.Command() == wire.CmdTx && err != nil {
					t.Fatalf("independent transaction relay was rejected: %v", err)
				}
				if wrong.Command() != wire.CmdTx && err == nil {
					t.Fatal("wrong response identity was accepted")
				}
				if !requests.Expired(time.Now()) {
					t.Fatal("wrong response consumed an unrelated request")
				}
			}
			if err := readTrackedResponse(t, requests, tc.valid); err != nil {
				t.Fatalf("matching response rejected: %v", err)
			}
			if requests.Expired(time.Now()) {
				t.Fatal("matching response left a pending request")
			}
		})
	}
}

func TestInvalidNotFoundTypeIsRejectedBeforeAccounting(t *testing.T) {
	for _, typ := range []wire.InvType{wire.InvTypeError, wire.InvTypeFilteredBlock, wire.InvType(0xffffffff)} {
		t.Run(typ.String(), func(t *testing.T) {
			requests := wire.NewMessageRequests()
			defer requests.Close()
			gd := dataRequest(wire.InvTypeTx, 1)
			requests.Add(gd)
			nf := wire.NewMsgNotFound()
			nf.AddInvVect(gd.InvList[0])
			nf.AddInvVect(wire.NewInvVect(typ, &chainhash.Hash{}))
			if err := readTrackedResponse(t, requests, nf); err == nil {
				t.Fatal("filtering hid an invalid inventory type from rejection")
			}
			if count, _ := requests.GetDataStatus(); count != 1 {
				t.Fatal("invalid notfound partially consumed a valid request")
			}
		})
	}
}
