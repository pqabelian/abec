package ctaut

//// When TxoVersion upgrade happens, need
//// (1) update AutMetadata's version by an upgrade function; This is to guarantee that AutMetadata has the latest script version
//// (2) the clients get the AutMetadata's (latest/current) version to create new version AutScript.
//
//// todo：define a map between TxVersion and AutScriptVersion
//// host-Txo-Version supports which AutScriptVersion?
//// allowed cases of (AutScriptVersion, Input AutScriptVersion)
//func GetTxVersionFromAutScriptVersion(autScriptVersion uint32) (uint32, error) {
//	switch autScriptVersion {
//	case ctautwire.AutScriptVersion_1:
//		return hostwire.TxVersion_Height_464000_Aconcagua, nil
//	default:
//		return 0, fmt.Errorf("GetTxVersionFromAutScriptVersion: autScriptVersion is %d, ", autScriptVersion)
//	}
//}
//
//// todo: add a rule check on the version map
