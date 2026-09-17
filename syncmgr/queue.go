package syncmgr

import "sync/atomic"

type queuedMessage struct {
	message interface{}
	done    chan struct{}
}

func (sm *SyncManager) enqueueMessage(msg interface{}) bool {
	sm.enqueueMtx.RLock()
	defer sm.enqueueMtx.RUnlock()
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return false
	}
	select {
	case sm.msgChan <- msg:
		return true
	case <-sm.quit:
		return false
	}
}

// queueMessage returns a receipt for this message alone. The sender owns its
// data until the receipt closes after handling, rejection, or shutdown discard.
func (sm *SyncManager) queueMessage(msg interface{}) <-chan struct{} {
	done := make(chan struct{})
	if !sm.enqueueMessage(&queuedMessage{message: msg, done: done}) {
		if pruned, ok := msg.(*prunedBlockMsg); ok {
			sm.notifyPrunedBlockProcessed(pruned)
		}
		close(done)
	}
	return done
}

func (sm *SyncManager) drainMessages() {
	// Exclude senders that passed the shutdown check before quit was closed.
	sm.enqueueMtx.Lock()
	defer sm.enqueueMtx.Unlock()
	for {
		select {
		case message := <-sm.msgChan:
			queued, wrapped := message.(*queuedMessage)
			if wrapped {
				message = queued.message
			}
			switch msg := message.(type) {
			case *prunedBlockMsg:
				sm.notifyPrunedBlockProcessed(msg)
			case *txMsgAbe:
				msg.reply <- struct{}{}
			case *blockMsgAbe:
				msg.reply <- struct{}{}
			}
			if wrapped {
				close(queued.done)
			}
		default:
			return
		}
	}
}
