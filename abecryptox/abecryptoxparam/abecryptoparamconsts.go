package abecryptoxparam

// These constants are related/decided by the underlying crypto-schemes.
// When underlying crypto-schemes are updated, we need to check these constants, and update them when necessary.
const (
	//	PQRingCT, 2022.03.31
	MaxAllowedTxoSize = 1048576 //1024*1024*1, 1M bytes
)
const (
	// copyed from abecryptoparam 2024.01.04
	// These consts should be replaced/implemented by functions, but for back-compatability, we have to keep them here.

	MAXALLOWED uint32 = 4294967295 // 2^32-1
	// MaxAllowedTxMemoSize is larger than package abecryptoparam (for pqringct), to Support AUT script.
	MaxAllowedTxMemoSize uint32 = 65536 // 2^16, 64K bytes
	// MaxAllowedSerialNumberSize must have the same value as that in package abecryptoparam (for pqringct).
	MaxAllowedSerialNumberSize uint32 = 64       // 512 bits = 64 bytes
	MaxAllowedTxWitnessSize    uint32 = 16777216 // 2^24, 16M bytes
)
