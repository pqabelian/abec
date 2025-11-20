package ctaut

import (
	"fmt"

	"github.com/abesuite/abec/wire"
)

// These version-constants are used to maintain the history AutScriptVersion.
// The main principles are following
// 1. the script version must be upgraded when it undergoes the transaction version upgrade.
// 2. The version of the generated token will be inherited from the script version
// 3. the version of the metadata would be inherited from the version of register or re-register script
const (
	AutScriptVersion_Unknown uint32 = 0 // reserved
	AutScriptVersion_1       uint32 = 1
)

// When TxoVersion upgrade happens, need
// (1) update AutMetadata's version by an upgrade function; This is to guarantee that AutMetadata has the latest script version
// (2) the clients get the AutMetadata's (latest/current) version to create new version AutScript.

// todo：define a map between TxVersion and AutScriptVersion
// host-Txo-Version supports which AutScriptVersion?
// allowed cases of (AutScriptVersion, Input AutScriptVersion)
func GetTxoVersionFromAutScriptVersion(autScriptVersion uint32) (uint32, error) {
	switch autScriptVersion {
	case AutScriptVersion_1:
		return wire.TxVersion_Height_464000_Aconcagua, nil
	default:
		return 0, fmt.Errorf("GetTxoVersionFromAutScriptVersion: autScriptVersion is %d, ", autScriptVersion)
	}
}

// todo: add a rule check on the version map
