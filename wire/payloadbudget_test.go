package wire_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func TestPayloadBudgetPreservesSupplementalCapacity(t *testing.T) {
	const limit = 768 * 1024 * 1024
	budget := wire.NewPayloadBudget(limit, wire.MaxMessagePayload+wire.MaxQueuedPayload)
	ordinary, ok := budget.TryReserve(limit-wire.MaxMessagePayload-wire.MaxQueuedPayload, false)
	if !ok {
		t.Fatal("ordinary capacity unavailable")
	}
	queued, ok := budget.TryReserveQueued(wire.MaxQueuedPayload, true)
	if !ok {
		t.Fatal("queued request capacity unavailable")
	}
	if _, ok := budget.TryReserve(1, false); ok {
		t.Fatal("ordinary work consumed completion headroom")
	}
	if _, ok := budget.TryReserveQueued(1, true); ok {
		t.Fatal("queued metadata exceeded its separate limit")
	}
	requests := wire.NewMessageRequests(wire.NewRequestCounter(512 * 1024 * 1024))
	defer requests.Close()
	requests.Add(wire.NewMsgNeedSet(chainhash.Hash{}, nil))
	var frame bytes.Buffer
	if err := wire.WriteMessage(&frame, wire.NewMsgNeedSetResult(chainhash.Hash{}, nil), wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	_, _, _, held, err := wire.ReadMessageWithBudgetN(&frame, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, requests, budget)
	if err != nil || budget.Usage() != limit {
		t.Fatalf("maximum supplemental response could not finish: used=%d err=%v", budget.Usage(), err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(held.Release)
	}
	wg.Wait()
	ordinary.Release()
	queued.Release()
	if budget.Usage() != 0 {
		t.Fatal("cleanup leaked or double-released a reservation")
	}
}

func TestPayloadBudgetRejectsBeforeBodyAndReleasesErrors(t *testing.T) {
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	frame := encodedMessage(t, tx)
	budget := wire.NewPayloadBudget(uint64(tx.MaxPayloadLength(wire.ProtocolVersion)), 0)
	occupied, _ := budget.TryReserve(uint64(tx.MaxPayloadLength(wire.ProtocolVersion)), false)
	r := bytes.NewReader(frame)
	n, msg, _, held, err := wire.ReadMessageWithBudgetN(r, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, nil, budget)
	if !errors.Is(err, wire.ErrPayloadLimit) || n != wire.MessageHeaderSize || msg != nil || held != nil || r.Len() != len(frame)-wire.MessageHeaderSize {
		t.Fatalf("capacity rejection read the body: n=%d remaining=%d err=%v", n, r.Len(), err)
	}
	occupied.Release()
	for _, data := range [][]byte{frame[:len(frame)-1], append([]byte{}, frame...)} {
		data[len(data)-1] ^= 1
		_, _, _, held, err := wire.ReadMessageWithBudgetN(bytes.NewReader(data), wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, nil, budget)
		if err == nil || held != nil || budget.Usage() != 0 {
			t.Fatalf("failed read retained payload capacity: %d, %v", budget.Usage(), err)
		}
	}
}

func TestQueuedPayloadLeavesSupplementalRequestCapacity(t *testing.T) {
	budget := wire.NewPayloadBudget(768*1024*1024, wire.MaxMessagePayload+wire.MaxQueuedPayload)
	ordinary, ok := budget.TryReserveQueued(wire.MaxQueuedPayload-2*1024*1024, false)
	if !ok {
		t.Fatal("ordinary queue capacity unavailable")
	}
	defer ordinary.Release()
	if _, ok := budget.TryReserveQueued(1, false); ok {
		t.Fatal("ordinary metadata consumed supplemental request capacity")
	}
	needset, ok := budget.TryReserveQueued(32+wire.MaxVarIntPayload+32*wire.MaxInvPerMsg, true)
	if !ok {
		t.Fatal("maximum needset request could not enter a saturated ordinary queue")
	}
	needset.Release()
}
