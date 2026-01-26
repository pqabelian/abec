package script

import (
	"fmt"

	"github.com/pqabelian/abec/chainhash"
	ctautwire "github.com/pqabelian/abec/ctaut/wire"
)

type AutScriptType uint8

const (
	AutScriptTypeRegistration   AutScriptType = 0
	AutScriptTypeReRegistration AutScriptType = 1
	AutScriptTypeMint           AutScriptType = 2
	AutScriptTypeTransfer       AutScriptType = 3
	AutScriptTypeBurn           AutScriptType = 4
)

var autScriptTypeStrings = map[AutScriptType]string{
	AutScriptTypeRegistration:   "AutScriptTypeRegistration",
	AutScriptTypeReRegistration: "AutScriptTypeReRegistration",
	AutScriptTypeTransfer:       "AutScriptTypeTransfer",
	AutScriptTypeMint:           "AutScriptTypeMint",
	AutScriptTypeBurn:           "AutScriptTypeBurn",
}

func (autScriptType AutScriptType) String() string {
	if str, ok := autScriptTypeStrings[autScriptType]; ok {
		return str
	}
	return fmt.Sprintf("Unknown AutScriptType (%d)", uint8(autScriptType))
}

type AutPrivacyType uint8

const (
	AutPrivacyTypeUnlimited     AutPrivacyType = 0
	AutPrivacyTypeLimitedPublic AutPrivacyType = 1
	AutPrivacyTypeLimitedHidden AutPrivacyType = 2
)

const MaxAutScriptLength uint32 = 128 * 1024 // 128K, consistent with MaxAllowedTxMemoSize

const AutIdentifierLength = chainhash.HashSize

// The following parameters would be chosen with the following references and actual limitation on Abelian
// 1. https://github.com/MetaMask/metamask-extension/issues/9243
// 2. https://eips.ethereum.org/EIPS/eip-20
// 3. https://medium.com/sphere-audits/in-depth-guide-on-how-to-write-an-erc20-token-contract-in-yul-b521b6d268f5
// The full, descriptive and human-readable name of the token

const MaxAutNameLength = 64

// A short, human-readable string that acts as a ticker for the token.
// The best practice in ERC-20 in length is on is 3~5 letters.

const MaxAutSymbolLength = 32

const MaxBaseUnitLength = 32
const MaxSubUnitLength = 32

const MaxAutMemoLength = 1024 // 1K

// The following limitation are derived from the constraints of the underlying cryptographic scheme and parameters
//  1. The value must be in the range (0, 2^51-1)
//  2. Each host transaction allows up to 100 pseudonym outputs, it means that up to 100 issuers for an CT-AUT instance
//  3. Each host transaction allows up to 100 pseudonym inputs but up to 50 different addresses are allowed,
//     it means that up to 50 for mint/reregistration threshold
//  4. the CT-Token would be generated up to 5 at a time

const MaxAmount = uint64(1)<<51 - 1 // TODO get the value from abecryptoxparam.???
const MaxNumToken = 100             // The allowed total number of output AutTokens in one AutTransaction.
const MaxNumHiddenToken = 5         // TODO get the value from abecryptoxparam.???
const MaxIssuerNum = 100            // TODO get the value from abecryptoxparam.GetTxOutputMaxNumForSingle(wire.TxVersion)

// The ValueScript in wire.AutTxo would be 10959 bytes (for hidden one) or 9 bytes (for public one)
// At this moment, there may be up to 5 hidden one and 95 public one, i.e. 10959*5 + 95*9 = 55650

const MaxAutValueScriptLength = 16 * 1024 // 16K
const MaxAutTxoLength = ctautwire.MaxAutTxoLength

const MaxScriptMemoLength = 1024 // 1K

const InfiniteExpireHeight = int32(-1)

var ZeroHash chainhash.Hash

func init() {
	for i := 0; i < chainhash.HashSize; i++ {
		ZeroHash[i] = 0
	}
}

// end of codes
