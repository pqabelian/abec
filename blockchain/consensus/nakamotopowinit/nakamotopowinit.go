package nakamotopowinit

import (
	"fmt"
	"github.com/abesuite/abec/blockchain/consensus/common"
	"github.com/abesuite/abec/blockchain/ruleerror"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"math/big"
)

type NakamotoPowInit struct {
}

// NewNakamotoPowInit creates a new NakamotoPowInit.
func NewNakamotoPowInit() *NakamotoPowInit {
	return &NakamotoPowInit{}
}

// VerifySeal verifies whether the passed wire.BlockHeader is valid with respect the passed target,
// in the NakamotoPow consensus.
// review done 2025.12.12
func (nakamotoPowInit *NakamotoPowInit) VerifySeal(header *wire.BlockHeader, target *big.Int) error {
	if header == nil {
		return fmt.Errorf("NakamotoPowInit VerifySeal: the input header is nil")
	}

	if header.Version >= wire.BlockVersionEthashPow {
		return fmt.Errorf("NakamotoPowInit VerifySeal: wrong call on this funciton, "+
			"since header.Version (%d) >= wire.BlockVersionEthashPow", header.Version)
	}

	sealHash := header.BlockHash()
	hashNum := common.HashToBig(sealHash)
	if hashNum.Cmp(target) > 0 {
		str := fmt.Sprintf("NakamotoPowInit VerifySeal: seal hash (%s) of %064x is higher than "+
			"expected max of %064x", sealHash.String(), hashNum, target)
		return ruleerror.NewRuleError(ruleerror.ErrHighHash, str)
	}

	return nil
}

// HeaderContentHashDummy returns the hash of the passed BlockHeader's HeaderContent, computed by DoubleHash.
//
// This function is useless for NakamotoPowInit.
//
// See (bh *BlockHeader) HeaderContent() and ethashpow.HeaderContent().
func HeaderContentHashDummy(header *wire.BlockHeader) (*chainhash.Hash, error) {
	headerContent, err := header.HeaderContent()
	if err != nil {
		return nil, err
	}

	// todo: To have backward compatibility, still use DoubleHash
	headerContentHash := chainhash.DoubleHashH(headerContent)
	return &headerContentHash, nil
}

// SealHashFast returns the sealHash of the input block header.
//
// Note that for NakamotoPowInit, SealHashFast is the same as computing SealHash.
// This algorithm is used only where sealHash is needed independently, for example, for display.
//
// If this function is called on a bloclHeader with Version >= wire.BlockVersionEthashPow,
// it still returns BlockHash, which is not real sealHash.
// The caller needs to guarantee this function with right BlockHeader.
func SealHashFast(header *wire.BlockHeader) chainhash.Hash {
	if header == nil {
		return chainhash.InvalidHash
	}

	// if call this function on a BlockHeader with header.Version >= wire.BlockVersionEthashPow,
	// it still returns BlockHash, which is not sealHash.

	return header.BlockHash()
}
