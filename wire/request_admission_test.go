package wire_test

import (
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func TestNeedSetAdmissionDoesNotCopyTransactionHashes(t *testing.T) {
	hashes := make([]chainhash.Hash, wire.MaxInvPerMsg)
	for i := range hashes {
		hashes[i][0], hashes[i][1] = byte(i), byte(i>>8)
	}
	msg := wire.NewMsgNeedSet(chainhash.Hash{}, hashes)
	for _, limit := range []uint64{0, wire.MaxMessagePayload} {
		requests := wire.NewMessageRequests(wire.NewRequestCounter(limit))
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		accepted := requests.Add(msg)
		runtime.ReadMemStats(&after)
		requests.Close()
		if accepted != (limit != 0) {
			t.Fatal("needset admission ignored available capacity")
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256*1024 {
			t.Fatalf("needset admission copied its hash list: allocated=%d", allocated)
		}
	}
}

func TestRequestAgeStartsAtAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		counter := wire.NewRequestCounter(wire.MaxBlockPayloadAbe)
		requests := wire.NewMessageRequests(counter)
		defer requests.Close()
		batch := dataRequest(wire.InvTypeBlock, 2)
		started := time.Now()
		part, remainder := requests.ReserveNext(batch)
		if part == nil || remainder == nil || requests.Expired(started.Add(-time.Nanosecond)) {
			t.Fatal("request did not start its age at admission")
		}
		time.Sleep(time.Minute)
		nf := wire.NewMsgNotFound()
		nf.AddInvVect(batch.InvList[0])
		if err := readTrackedResponse(t, requests, nf); err != nil {
			t.Fatal(err)
		}
		if requests.Expired(time.Now()) {
			t.Fatal("unsent remainder acquired an age or completed request retained one")
		}
		if part, _ = requests.ReserveNext(remainder); part == nil || requests.Expired(started) {
			t.Fatal("queued remainder inherited the first request's age")
		}
	})

	for _, msg := range []wire.Message{
		dataRequest(wire.InvTypeTx, 1), wire.NewMsgGetHeaders(),
		wire.NewMsgGetBlockTx(chainhash.Hash{}, chainhash.Hash{}),
		wire.NewMsgNeedSet(chainhash.Hash{}, nil),
	} {
		t.Run(msg.Command(), func(t *testing.T) {
			r := wire.NewMessageRequests(nil)
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
			r := wire.NewMessageRequests(nil)
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
