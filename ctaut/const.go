package ctaut

import "github.com/abesuite/abec/chainhash"

// All CT-AUT Script must start with the following specified prefix.
// Any that starts with this prefix but does not have valid script content will be rejected.
// Use a constant string to avoid unconscious modifications
const commonPrefix = "CTAUTSCRIPT"

type CTAUTScriptType = uint8

const (
	Registration   CTAUTScriptType = 0
	ReRegistration CTAUTScriptType = 1
	Mint           CTAUTScriptType = 2
	Transfer       CTAUTScriptType = 3
	Burn           CTAUTScriptType = 4
)

const CTAUTIdentifierLength = chainhash.HashSize

// The following parameters would be chosen with the following references and actual limitation on Abelian
// 1. https://github.com/MetaMask/metamask-extension/issues/9243
// 2. https://eips.ethereum.org/EIPS/eip-20
// 3. https://medium.com/sphere-audits/in-depth-guide-on-how-to-write-an-erc20-token-contract-in-yul-b521b6d268f5
// The full, descriptive and human-readable name of the token
const maxCTAUTNameLength = 64

// A short, human-readable string that acts as a ticker for the token.
// The best practice in ERC-20 in length is on is 3~5 letters.
const maxCTAUTSymbolLength = 32

const maxBaseUnitLength = 32
const maxSubUnitLength = 32

const maxCTAUTMemoLength = 1024

// The following limitation are derived from the constraints of the underlying cryptographic scheme and parameters
// 1.
//  2. Each host transaction allows up to 100 pseudonym outputs, it means that up to 100 issuers for an CT-AUT instance
//  3. Each host transaction allows up to 100 pseudonym inputs but up to 50 different addresses are allowed,
//     it means that up to 50 for mint/reregistration threshold
//  4. the CT-Token would be generated up to 5 at a time
const maxAmount = uint64(1)<<51 - 1
const maxNumToken = 100
const maxIssuerNum = 100
const maxNumCTToken = 5
const issuerTokenLength = 193 // todo(ctaut): confirm to use coin address?

// The ValueScript in wire.AutTxo would be 10959 bytes (for hidden one) or 9 bytes (for public one)
// At this moment, there may be up to 5 hidden one and 95 public one, i.e. 10959*5 + 95*9 = 55650
const MaxAUTValueScriptLength = 10959

const maxMemoLength = 1024 // 1K
