package ctaut

import (
	"github.com/abesuite/abec/chainhash"
)

// All CT-AUT Script must start with the following specified prefix.
// Any that starts with this prefix but does not have valid script content will be rejected.
// Use a constant string to avoid unconscious modifications
const commonPrefix = "AUTSCRIPT"

type AutScriptType = uint8

const (
	AutScriptTypeRegistration   AutScriptType = 0
	AutScriptTypeReRegistration AutScriptType = 1
	AutScriptTypeMint           AutScriptType = 2
	AutScriptTypeTransfer       AutScriptType = 3
	AutScriptTypeBurn           AutScriptType = 4
)

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
const MaxNumCTToken = 5             // TODO get the value from abecryptoxparam.???
const MaxIssuerNum = 100            // TODO get the value from abecryptoxparam.GetTxOutputMaxNumForSingle(wire.TxVersion)

const issuerLength = 193 // todo(ctaut): confirm to use coin address?

// The ValueScript in wire.AutTxo would be 10959 bytes (for hidden one) or 9 bytes (for public one)
// At this moment, there may be up to 5 hidden one and 95 public one, i.e. 10959*5 + 95*9 = 55650
const MaxAutValueScriptLength = 10963

const MaxScriptMemoLength = 1024 // 1K

const InfiniteExpireHeight = int32(-1)
