package abecryptoxparam

import (
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// API for Sizes	begin
// reviewed on 2023.12.07
func pqringctxGetCryptoSchemeParamSeedBytesLen(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetParamSeedBytesLen(pp)
}

//	API for Sizes	end

//	Transaction-related Params	begin

// GetNullSerialNumber() return the null serial number.
// reviewed on 2023.12.07
func pqringctxGetNullSerialNumber(pp *pqringctxapi.PublicParameter) []byte {
	return pqringctxapi.GetNullSerialNumber(pp)
}

// todo: review
func pqringctxGetTxInputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxInputMaxNum(pp)
}

// todo: review
func pqringctxGetTxOutputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxOutputMaxNum(pp)
}

//	Transaction-related Params	end
