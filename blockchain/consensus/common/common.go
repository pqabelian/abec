// Copyright (c) 2021-2025 The Abelian Foundation. All rights reserved.
// This file is part of Abelian.
//
// This source code is licensed under the MIT License found in the LICENSE file
// in the root directory of this source tree.
//
//
// Abelian Foundation 2021-2025
//
//

package common

import (
	"math/big"

	"github.com/pqabelian/abec/chainhash"
)

// HashToBig converts a chainhash.Hash into a big.Int that can be used to perform math comparisons.
func HashToBig(hash chainhash.Hash) *big.Int {
	// As (hash Hash) String() returns the Hash as the hexadecimal string of the byte-reversed hash,
	// to make the big.Int value to be consistent with the displayed string, here also reverse it.
	//	This is also to be compatible with the exiting blocks.
	tmpHash := chainhash.Hash{}

	for i := 0; i < chainhash.HashSize/2; i++ {
		tmpHash[i], tmpHash[chainhash.HashSize-1-i] = hash[chainhash.HashSize-1-i], hash[i]
	}

	return new(big.Int).SetBytes(tmpHash[:])
}
