package wire_test

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func TestRequestsHaveNoByteQuota(t *testing.T) {
	a, b := wire.NewMessageRequests(), wire.NewMessageRequests()
	defer a.Close()
	defer b.Close()
	for _, requests := range []*wire.MessageRequests{a, b} {
		batch := dataRequest(wire.InvTypeWitnessBlock, 64)
		if !requests.Add(batch) {
			t.Fatal("full getdata batch was rejected")
		}
		if count, _ := requests.GetDataStatus(); count != 64 {
			t.Fatalf("batch was split or lost requests: %d", count)
		}
		if !requests.Add(wire.NewMsgGetBlockTx(chainhash.Hash{}, chainhash.Hash{})) {
			t.Fatal("pending blocks prevented supplemental requests")
		}
		requests.Close()
		if requests.Expired(time.Now()) || requests.Add(batch) {
			t.Fatal("closed tracker retained or accepted requests")
		}
	}
}

func TestRequestAgeStartsAtSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requests := wire.NewMessageRequests()
		defer requests.Close()
		started := time.Now()
		batch := dataRequest(wire.InvTypeBlock, 2)
		if !requests.Add(batch) || requests.Expired(started.Add(-time.Nanosecond)) {
			t.Fatal("request did not start its age at registration")
		}
		time.Sleep(time.Minute)
		nf := wire.NewMsgNotFound()
		nf.AddInvVect(batch.InvList[0])
		if err := readTrackedResponse(t, requests, nf); err != nil {
			t.Fatal(err)
		}
		if !requests.Expired(started) {
			t.Fatal("another response changed the remaining request's age")
		}
		nf.InvList[0] = batch.InvList[1]
		if err := readTrackedResponse(t, requests, nf); err != nil {
			t.Fatal(err)
		}
		if requests.Expired(time.Now()) {
			t.Fatal("completed request retained an age")
		}
		if !requests.Add(batch) || requests.Expired(started) {
			t.Fatal("new requests inherited the completed requests' age")
		}
	})
	for _, msg := range []wire.Message{
		dataRequest(wire.InvTypeTx, 1), wire.NewMsgGetHeaders(),
		wire.NewMsgGetBlockTx(chainhash.Hash{}, chainhash.Hash{}),
	} {
		t.Run(msg.Command(), func(t *testing.T) {
			r := wire.NewMessageRequests()
			if !r.Add(msg) || !r.Expired(time.Now()) {
				t.Fatal("registered request has no independent age")
			}
			r.Close()
			if r.Expired(time.Now()) {
				t.Fatal("closed request tracker retained an expiry")
			}
		})
	}
}

func TestDuplicateResponsesCompleteOldestRequest(t *testing.T) {
	for _, notFound := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
			hash := tx.TxHash()
			r := wire.NewMessageRequests()
			defer r.Close()
			started := time.Now()
			for i := 0; i < 3; i++ {
				kind := wire.InvTypeTx
				if !notFound && i != 0 {
					kind = wire.InvTypeWitnessTx // Equivalent response, different key.
				}
				gd := wire.NewMsgGetData()
				gd.AddInvVect(wire.NewInvVect(kind, &hash))
				r.Add(gd)
				time.Sleep(time.Second)
			}
			var response wire.Message = tx
			if notFound {
				nf := wire.NewMsgNotFound()
				nf.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &hash))
				response = nf
			}
			for i := 0; i < 2; i++ {
				if err := readTrackedResponse(t, r, response); err != nil {
					t.Fatal(err)
				}
			}
			if r.Expired(started.Add(time.Second)) || !r.Expired(started.Add(2*time.Second)) {
				t.Fatal("interchangeable responses left an older request to expire early")
			}
		})
	}
}
