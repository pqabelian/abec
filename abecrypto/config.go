package abecrypto

//	ABE can support at most 2^16 different CryptoSchemes
//	The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
//	e.g. SalrsV0, SalrsV1

type CryptoScheme uint16

const (
	CryptoSchemeSALRS CryptoScheme = 0
)
