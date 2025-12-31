package nakamotopowaconcagua

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/abesuite/abec/blockchain/consensus/common"
	"github.com/abesuite/abec/blockchain/ruleerror"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

type NakamotoPowAconcagua struct {
}

// NewNakamotoPowAconcagua creates a new NakamotoPowInit.
func NewNakamotoPowAconcagua() *NakamotoPowAconcagua {
	return &NakamotoPowAconcagua{}
}

// VerifySeal verifies whether the passed wire.BlockHeader is valid with respect the passed target,
// in the NakamotoPowAconcagua consensus.
// review done 2025.12.12
func (nakamotoPowAconcagua *NakamotoPowAconcagua) VerifySeal(header *wire.BlockHeader, target *big.Int) error {
	if header == nil {
		return fmt.Errorf("NakamotoPowAconcagua VerifySeal: the input header is nil")
	}

	if header.Version < wire.BlockVersionAconcagua {
		return fmt.Errorf("NakamotoPowAconcagua VerifySeal: wrong call on this funciton, "+
			"since header.Version (%d) < wire.BlockVersionAconcagua", header.Version)
	}

	//// Height in NonceExt should match with that in the header.
	//// It is set when mining successfully that
	//// - header.NonceExt = (uint64(header.Height) << 32) | (uint64(i))
	//height := int32((header.NonceExt >> 32) & 0x0000_0000_FFFF_FFFF)
	//if height != header.Height {
	//	str := fmt.Sprintf("NakamotoPowAconcagua VerifySeal: header.Height (%x) is not equal with that in NonceExt (%x)",
	//		height, header.NonceExt)
	//	return ruleerror.NewRuleError(ruleerror.ErrHighHash, str)
	//}

	fmt.Println("NakamotoPowAconcagua VerifySeal Header:")
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: ", target)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.Version ", header.Version)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.PrevBlock ", header.PrevBlock.String())
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.PrevBlock ", header.MerkleRoot.String())
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.Timestamp ", header.Timestamp.Unix())
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.Height ", header.Height)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.Bits ", header.Bits)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.BitsSecond ", header.BitsSecond)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.PowScaleSecond ", header.PowScaleSecond)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.ConsensusApplied ", header.ConsensusApplied)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.Nonce ", header.Nonce)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.NonceExt ", header.NonceExt)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: header.MixDigest ", header.MixDigest)

	sealHashPreImg, err := sealHashPreImage(header)
	if err != nil {
		return err
	}
	sealHash := chainhash.DoubleHashH(sealHashPreImg)
	fmt.Println("NakamotoPowAconcagua VerifySeal Target: sealHash ", sealHash.String())

	if !sealHash.IsEqual(&header.MixDigest) {
		str := fmt.Sprintf("NakamotoPowAconcagua VerifySeal: seal hash (%s) is not equal with mixDigest (%s)",
			sealHash.String(), header.MixDigest.String())
		return ruleerror.NewRuleError(ruleerror.ErrHighHash, str)
	}

	sealHashNum := common.HashToBig(sealHash)
	if sealHashNum.Cmp(target) > 0 {
		str := fmt.Sprintf("NakamotoPowAconcagua VerifySeal: seal hash stoared in MixDigest (%s) of %064x is higher than "+
			"expected max of %064x", header.MixDigest.String(), sealHashNum, target)
		return ruleerror.NewRuleError(ruleerror.ErrHighHash, str)
	}

	return nil
}

// HeaderContentHash returns the hash of the passed BlockHeader's HeaderContent, computed by SHA3-256.
//
// NakamotoPowAconcagua uses HeaderContentHash to build SealHashPreImage to mine/find the valid SealHash.
//
// See (bh *BlockHeader) HeaderContent(), sealHashPreImage(), and VerifySeal().
// review done 2025.12.12
func HeaderContentHash(header *wire.BlockHeader) (*chainhash.Hash, error) {
	if header == nil {
		return nil, fmt.Errorf("nakamotopowaconcagua.HeaderContentHash: the input header is nil")
	}

	if header.Version < wire.BlockVersionAconcagua {
		return nil, fmt.Errorf("nakamotopowaconcagua.HeaderContentHash: wrong call on this funciton, "+
			"since header.Version (%d) < wire.BlockVersionAconcagua", header.Version)
	}

	headerContent, err := header.HeaderContent()
	if err != nil {
		return nil, err
	}

	headerContentHash := chainhash.ChainHash(headerContent)
	return &headerContentHash, nil
}

// SealHashFast returns the sealHash of the input block header.
//
// Note that for NewNakamotoPowAconcagua, SealHashFast just returns the header.MixDigest, where SealHash is stored in.
// This algorithm is used only where sealHash is needed independently, for example, for display.
//
// If this function is called on a bloclHeader with Version < wire.BlockVersionAconcagua,
// it still returns header.MixDigest, which is not real sealHash.
// The caller needs to guarantee this function with right BlockHeader.
func SealHashFast(header *wire.BlockHeader) chainhash.Hash {
	if header == nil {
		return chainhash.InvalidHash
	}

	// if call this function on a BlockHeader with header.Version < wire.BlockVersionAconcagua,
	// it still returns BlockHash, which is not sealHash.
	return header.MixDigest
}

// helper functions

// sealHashPreImage returns the content of header that is used to compute SealHash.
// review done 2025.12.12
func sealHashPreImage(header *wire.BlockHeader) ([]byte, error) {
	if header == nil {
		return nil, fmt.Errorf("NakamotoPowAconcagua sealHashPreImage: the input header is nil")
	}

	if header.Version < wire.BlockVersionAconcagua {
		return nil, fmt.Errorf("NakamotoPowAconcagua sealHashPreImage: wrong call on this funciton, "+
			"since header.Version (%d) < wire.BlockVersionAconcagua", header.Version)
	}

	headerContentHash, err := HeaderContentHash(header)
	if err != nil {
		return nil, err
	}

	// when mining successful:
	//	- header.NonceExt <-- (uint64(nonceLeft)<<32) | (uint64(nonce))
	//	- where nonce is uint32
	// when verifying:
	//  - nonceLeft <-- uint32((header.NonceExt >> 32) & 0x0000_0000_FFFF_FFFF)
	//	- nonceRight <-- uint32(header.NonceExt & 0x0000_0000_FFFF_FFFF)

	nonceLeft := uint32((header.NonceExt >> 32) & 0x0000_0000_FFFF_FFFF)
	nonceRight := uint32(header.NonceExt & 0x0000_0000_FFFF_FFFF)

	buf := make([]byte, 80)
	offset := 0

	binary.LittleEndian.PutUint32(buf[offset:offset+4], nonceLeft)
	offset += 4

	copy(buf[offset:offset+chainhash.HashSize], header.PrevBlock[:])
	offset += chainhash.HashSize

	copy(buf[offset:offset+chainhash.HashSize], headerContentHash[:])
	offset += chainhash.HashSize

	binary.LittleEndian.PutUint32(buf[offset:offset+4], uint32(header.Height))
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:offset+4], header.Bits)
	offset += 4

	binary.LittleEndian.PutUint32(buf[offset:offset+4], nonceRight)
	offset += 4

	return buf, nil
}
