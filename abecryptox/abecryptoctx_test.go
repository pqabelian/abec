package abecryptox

import (
	"crypto/rand"
	"testing"

	"github.com/abesuite/abec/abecryptox/abecryptoutils"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
)

func TestAutCoinbaseTxGen(t *testing.T) {
	rootSeed := make([]byte, abecryptoutils.PRFKeyBytesLen)
	rand.Read(rootSeed)
	vpk, vsk, err := abecryptoxkey.CoinValueKeyGenByRootSeeds(abecryptoxparam.CryptoSchemePQRingCTX, abecryptoxkey.PrivacyLevelPSEUDONYMCT, rootSeed)
	if err != nil {
		t.Fatalf("CoinValueKeyGenByRootSeeds() error = %v", err)
		return
	}
	autTxOutputDescs := make([]*AutTxOutputDesc, 0, 5)
	for i := 0; i < 5; i++ {
		autTxOutputDescs = append(autTxOutputDescs, NewAutTxOutDesc(AutTxoTypeHidden, 400, vpk))
	}
	ctxCbTx, err := AutCoinbaseTxGen(3, 2000, autTxOutputDescs)
	if err != nil {
		t.Fatalf("AutCoinbaseTxGen() error = %v", err)
		return
	}
	err = AutCoinbaseTxVerify(ctxCbTx)
	if err != nil {
		t.Fatalf("AutCoinbaseTxVerify() error = %v", err)
		return
	}

	for i := 0; i < len(ctxCbTx.TxOuts); i++ {
		value, err := ExtractAutTxoValue(ctxCbTx.TxOuts[i], vpk, vsk)
		if err != nil {
			t.Fatalf("ExtractAutTxoValue() error = %v", err)
			return
		}
		if value != 400 {
			t.Fatalf("ExtractAutTxoValue() value = %v, want %v", value, 400)
			return
		}
	}

}
