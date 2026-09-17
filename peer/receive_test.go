package peer

import (
	"bytes"
	"encoding/binary"
	"testing"
	"testing/synctest"
	"time"

	"github.com/abesuite/abec/wire"
)

func TestPartialPayloadDoesNotExtendReceiveDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		counter := wire.NewRequestCounter(512 * 1024 * 1024)
		p, remote := counterMessagePeer(t, counter)
		// The test helper's short I/O deadline must not mask the real peer
		// timer. Virtual time lets us test its production duration directly.
		if err := remote.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		go p.inHandler()
		t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
		var encoded bytes.Buffer
		if err := wire.WriteMessage(&encoded, wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.ProtocolVersion, wire.MainNet); err != nil {
			t.Fatal(err)
		}
		header := encoded.Bytes()[:wire.MessageHeaderSize]
		binary.LittleEndian.PutUint32(header[16:20], (&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion))
		if _, err := remote.Write(header); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			time.Sleep(idleTimeout / 5)
			if _, err := remote.Write([]byte{1}); err != nil {
				t.Fatalf("peer closed before its receive deadline: %v", err)
			}
		}
		time.Sleep(idleTimeout / 5)
		synctest.Wait()
		select {
		case <-p.inQuit:
		default:
			t.Fatal("partial bytes postponed the absolute receive deadline")
		}
		if count, size := counter.Usage(); count != 0 || size != 0 {
			t.Fatalf("timed-out progressive read retained credit: %d, %d", count, size)
		}
	})
}
