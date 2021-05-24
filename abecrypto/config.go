package abecrypto

//	ABE can support at most 2^32 different CryptoSchemes
//	The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
//	e.g. SalrsV0, SalrsV1

type CryptoScheme uint32

const (
	CryptoSchemeSALRS      CryptoScheme = 0
	CryptoSchemePQRINGCT   CryptoScheme = 1
	CryptoSchemePQRINGCTV2 CryptoScheme = 2
)
