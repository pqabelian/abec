package wire

// These version-constants are used to maintain the history AutScriptVersion.
// The main principles are following
// 1. the script version must be upgraded when it undergoes the transaction version upgrade.
// 2. The version of the generated token will be inherited from the script version
// 3. the version of the metadata would be inherited from the version of register or re-register script
const (
	AutScriptVersion_Unknown uint32 = 0 // reserved
	AutScriptVersion_1       uint32 = 1
)
