package main

import (
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
)

func TestLookup(t *testing.T) {
	txhashMap := make(map[chainhash.Hash]struct{})
	txhashMap[chainhash.DoubleHashH([]byte{0})] = struct{}{}
	txhashMap[chainhash.DoubleHashH([]byte{1})] = struct{}{}
	txhashMap[chainhash.DoubleHashH([]byte{2})] = struct{}{}

	_, exist := txhashMap[chainhash.DoubleHashH([]byte{0})]
	if !exist {
		t.Fatalf("txhash 0 must exist")
	}
	_, exist = txhashMap[chainhash.DoubleHashH([]byte{3})]
	if exist {
		t.Fatalf("txhash 3 must not exist")
	}
}
