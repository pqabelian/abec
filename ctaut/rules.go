package ctaut

import (
	"fmt"
	"github.com/abesuite/abec/wire"
)

const (
	AutScriptVersion_Unknown uint32 = 0
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
