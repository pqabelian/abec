package ffldb

import (
	"fmt"
	"testing"
)

func TestEncodeTxWitnesses(t *testing.T) {
	var txWitness = []byte("")
	var autWitness = []byte("aaa")
	var witnesses []byte
	var txWitnessRec []byte
	var autWitnessRec []byte

	var err error

	witnesses = EncodeTxWitnesses(txWitness, autWitness)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(witnesses)

	txWitnessRec, autWitnessRec, err = DecodeTxWitnesses(witnesses)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("txWitness: %v \n", txWitnessRec)
	fmt.Printf("autWitness: %v \n", autWitnessRec)

	txWitness = []byte("bbb")
	autWitness = nil

	witnesses = EncodeTxWitnesses(txWitness, autWitness)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(witnesses)

	txWitnessRec, autWitnessRec, err = DecodeTxWitnesses(witnesses)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("txWitness: %v \n", txWitnessRec)
	fmt.Printf("autWitness: %v \n", autWitnessRec)

	txWitness = []byte("")
	autWitness = nil

	witnesses = EncodeTxWitnesses(txWitness, autWitness)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(witnesses)

	txWitnessRec, autWitnessRec, err = DecodeTxWitnesses(witnesses)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("txWitness: %v \n", txWitnessRec)
	fmt.Printf("autWitness: %v \n", autWitnessRec)

}
