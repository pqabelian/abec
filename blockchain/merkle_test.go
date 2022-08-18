package blockchain

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"math"
	"testing"
)

func TestNextPowerOfTwo(t *testing.T) {
	//for i := 1; i < 25; i++ {
	//	poft := nextPowerOfTwo(i)
	//	fmt.Println("i:", i, "nextPower2:", poft, "level num:", math.Log2(float64(poft))+1)
	//}

	for n := 1; n < 38; n++ {
		nextPoT := nextPowerOfTwo(n)
		arraySize := 2*nextPoT - 1
		merkles := make([]int, arraySize)
		for j := 0; j < arraySize; j++ {
			merkles[j] = j
		}

		//	pick up the sibling list
		levelNum := int(math.Log2(float64(nextPoT))) + 1
		rstSiblingHashes := make([]int, levelNum) //	2 for the bottom level and 0 for top level

		//	rstSiblingHashes[0] is a special one, is the start point
		locSibling := 0
		rstSiblingHashes[0] = merkles[0]
		locSibling++

		numInLevel := nextPoT // the number of nodes in the current level
		leftest := 0          //	the index of the leftest nodes in the current level
		for leftest+1 < arraySize {
			rstSiblingHashes[locSibling] = merkles[leftest+1]
			locSibling++

			leftest += numInLevel       //	the index of the left nodes of next(upper) level
			numInLevel = numInLevel / 2 // the number of nodes in the next(upper) level
		}

		fmt.Println("number of tx:", n, ". siblings:", rstSiblingHashes)
	}

}

func TestBuildMerkleTreeStoreAbeEthash(t *testing.T) {
	mr, sibling := FakeBuildMerkleTreeStoreAbeEthash(15)
	fmt.Println("merkle root generated :", mr)

	mrFromSibling := ComputeMerkleRootBySiblingHashes(sibling)
	fmt.Println("merkle root computated:", mrFromSibling)

	fmt.Println("merkle[0]:", sibling[0])
}

func FakeBuildMerkleTreeStoreAbeEthash(n int) (merkleRoot *chainhash.Hash, siblingHashes []*chainhash.Hash) {
	if n == 0 {
		return nil, nil
	}

	// Calculate how many entries are required to hold the binary merkle
	// tree as a linear array and create an array of that size.
	nextPoT := nextPowerOfTwo(n)
	arraySize := nextPoT*2 - 1
	merkles := make([]*chainhash.Hash, arraySize)

	// Create the base transaction hashes and populate the array with them.
	for i := 0; i < n; i++ {
		txBytes := []byte(fmt.Sprintf("itx: %d", i))
		witBytes := []byte(fmt.Sprintf("iwit:%d", 10000+i))
		tmp := make([]byte, chainhash.HashSize*2)
		// chainhash.DoubleHashH(tx Hash || txWitness Hash)
		//	todo: (EthashPoW) For transaction layer, for compatibility, we keep tx.Hash() and tx.WitnessHash() by chainhash.DoubleHashH.
		copy(tmp[:chainhash.HashSize], chainhash.DoubleHashB(txBytes))
		copy(tmp[chainhash.HashSize:], chainhash.DoubleHashB(witBytes))

		//	todo: (EthashPoW) for building merkle tree, using ChainHash
		tHash := chainhash.ChainHash(tmp)
		merkles[i] = &tHash
	}

	// Start the array offset after the last transaction and adjusted to the
	// next power of two.
	offset := nextPoT
	for i := 0; i < arraySize-1; i += 2 {
		switch {
		// When there is no left child node, the parent is nil too.
		case merkles[i] == nil:
			merkles[offset] = nil

		// When there is no right child, the parent is generated by
		// hashing the concatenation of the left child with itself.
		case merkles[i+1] == nil:
			newHash := HashMerkleBranchesEthash(merkles[i], merkles[i])
			merkles[offset] = newHash

		// The normal case sets the parent node to the double sha256
		// of the concatentation of the left and right children.
		default:
			newHash := HashMerkleBranchesEthash(merkles[i], merkles[i+1])
			merkles[offset] = newHash
		}
		offset++
	}

	//	pick up the sibling list
	levelNum := int(math.Log2(float64(nextPoT))) + 1
	rstSiblingHashes := make([]*chainhash.Hash, levelNum) //	2 for the bottom level and 0 for top level

	//	rstSiblingHashes[0] is a special one, is the start point
	locSibling := 0
	rstSiblingHashes[0] = merkles[0]
	locSibling++

	numInLevel := nextPoT // the number of nodes in the current level
	leftest := 0          //	the index of the leftest nodes in the current level
	for leftest+1 < arraySize {
		rstSiblingHashes[locSibling] = merkles[leftest+1]
		locSibling++

		leftest += numInLevel       //	the index of the left nodes of next(upper) level
		numInLevel = numInLevel / 2 // the number of nodes in the next(upper) level
	}

	return merkles[arraySize-1], rstSiblingHashes
}