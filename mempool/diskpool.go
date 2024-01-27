package mempool

import (
	"bytes"
	"encoding/binary"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/wire"
	"os"
	"time"
)

func (mp *TxPool) txMonitor() {
	if mp.txMonitoring {
		return
	}
	mp.txMonitorMu.Lock()
	if mp.txMonitoring {
		mp.txMonitorMu.Unlock()
		return
	}
	mp.txMonitoring = true
	mp.txMonitorMu.Unlock()
	log.Infof("start monitor transaction number in mempool")
	defer func() {
		mp.txMonitorMu.Lock()
		mp.txMonitoring = false
		mp.txMonitorMu.Unlock()
		log.Infof("stop monitor transaction number in mempool")
	}()
	// considerate a block would about 256s, and trigger early a little
	duration := 3 * time.Minute
	timer := time.NewTicker(duration)
	for {
		select {
		case <-timer.C:
			log.Infof("transaction in mempool:%d, cached in disk:%d", len(mp.poolAbe), len(mp.diskPool))
			if len(mp.poolAbe) >= MaxTransactionInMemoryNum {
				continue
			}
			log.Infof("loading transactions from disk...")
			filenames, err := mp.cfg.TxCacheRotator.RotatedRolled()
			if err != nil {
				log.Errorf("Unable to load cached transaction: %v", err)
				return
			}
			if len(filenames) == 0 {
				log.Infof("No cached transaction can be loaded.")
				return
			}

			var f *os.File
			for i := 0; i < len(filenames) && len(mp.poolAbe) < MaxTransactionInMemoryNum; i++ {
				name := filenames[i]
				log.Infof("loading some transactions from %s", name)
				f, err = os.OpenFile(name, os.O_RDONLY, 0644)
				if err != nil {
					continue
				}
				size := make([]byte, 8)
				for {
					// [transaction_size] [transaction_content]
					_, err = f.Read(size)
					if err != nil {
						break
					}
					contentSize := binary.LittleEndian.Uint64(size)
					content := make([]byte, contentSize)
					_, err = f.Read(content)
					if err != nil {
						break
					}
					buffer := bytes.NewBuffer(content)
					msgTx := &wire.MsgTxAbe{}
					err = msgTx.DeserializeFull(buffer)
					if err != nil {
						break
					}
					tx := abeutil.NewTxAbe(msgTx)
					log.Infof("load transaction %s from file %s", msgTx.TxHash(), name)
					_, err = mp.ProcessTransactionAbe(tx, false, false, 0, true)
					if err != nil {
						break
					}
				}
				f.Close()
				log.Infof("finish loading transactions from file %s, remove it...", name)
				os.Remove(name)
				f = nil
			}

			timer.Reset(duration)
		default:
		}
	}
}
