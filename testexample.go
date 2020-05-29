package main

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
)

func main1() {

	hash1 := new(chainhash.Hash)

	fmt.Println(hash1)

	hash2 := chainhash.Hash{}

	fmt.Println(hash2)

	for i := 0; i < chainhash.HashSize; i++ {
		hash1[i] = uint8(i)
	}

	/*	for i:=0; i<chainhash.HashSize; i++ {
		fmt.Println(hash1[i])
	}*/

	for i := 0; i < chainhash.HashSize; i++ {
		hash2[i] = uint8(i)
	}
	/*	for i:=0; i<chainhash.HashSize; i++ {
		fmt.Println(hash2[i])
	}*/

	hash2[0] = uint8(1)
	hash1[31] = uint8(33)
	fmt.Println(hash1.String())
	fmt.Println(hash2.String())
	fmt.Println(hash1.String() < hash2.String())

	//	fmt.Println(hash)
	for i := 0; i < chainhash.HashSize; i++ {
		fmt.Println(hash2[i])
	}

	_ = hash2.String()

	for i := 0; i < chainhash.HashSize; i++ {
		fmt.Println(hash2[i])
	}

	//	fmt.Println(hash)
}

/*func main() {
	q := 11 / wire.TxRingSize
	r := 11 % wire.TxRingSize

	q = 9 / 2
	r = 10 / 2

	fmt.Println(q)
	fmt.Println(r)
}
*/
/*func main(){
	type txoFlags uint8

	const (
		// tfCoinBase indicates that a txout was contained in a coinbase tx.
		tfCoinBase txoFlags = 1 << iota

		// tfSpent indicates that a txout is spent.
		tfSpent

		// tfModified indicates that a txout has been modified since it was
		// loaded.
		tfModified

		tfTest
	)

	flag := tfModified | tfCoinBase
	fmt.Println( flag )

	flag |= tfSpent
	fmt.Println( flag )


	flag |= tfTest
	fmt.Println( flag )

	fmt.Println( flag & tfModified )

}*/
