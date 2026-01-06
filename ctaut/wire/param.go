package wire

// Upgrade/Fork design:
// How a client obtains an AutScriptVersion?
// 1. Client has a local AutScriptVersion (aka. hardcoded when the client is developed)
// 2. Client queries AutScriptVersion from blockchain through API GetSupportedAutScriptVersions,
// and blockchain returns the current supported version-list.
// 3. If client's local version is not in the list, the client is forced to upgrade.

// The main principles on AutScriptVersion are following
// 1. The blockchain defines/specifies a new AutScriptVersion const when new features are developed or TxVersion upgrades,
// and AutScriptVersion variable will always point to the latest one.
// 1.1 The Aut Script Version must be upgraded when Transaction Version upgrades.
// 1.2 AutScript (including RegistrationScript, ReregistrationScript, MintScript, TransferScript, BurnScript) has a version field
// which uses the set of defined AutScriptVersions as the domain.
//
// 2. How a RegistrationScript is created and handled:
// 2.1 The client queries supportedAutScriptVersions by blockchain through GetSupportedAutScriptVersions().
// 2.2 If the client local AutScriptVersion is not in supportedAutScriptVersions, the client is forced to upgrade;
// otherwise, the client use the local AutScriptVersion to set the RegistrationScript's Version.
// 2.3 On the blockchain side,
// 2.3.1 RegistrationScript causes an AutInstance's metadata record to be added into blockchain,
// where metadata's version is set to 1 and RegistrationScript's version is added into metadata's updateScriptVersion list (as the first one).
// 2.3.2 RegistrationScript generates some AutRootTokens for the corresponding AutInstance, and
// these AutRootTokens has the same version as the RegistrationScript's version.
//
// 3. How a ReRegistrationScript is created and handled:
// 3.1 The client queries supportedAutScriptVersions by blockchain through GetSupportedAutScriptVersions().
// 3.2 If the client local AutScriptVersion is not in supportedAutScriptVersions, the client is forced to upgrade;
// otherwise, the client use the local AutScriptVersion to set the ReRegistrationScript's Version.
// 3.3 On the blockchain side,
// 3.3.1 ReRegistrationScript causes the corresponding AutInstance's metadata record to be updated.
// In particular,
// 3.3.1.1 Metadata's version increases by 1.
// 3.3.1.2 ReRegistrationScript's Version is appended to metadata's updateScriptVersion list.
// 3.3.1.2 A rule must be applied: For a ReRegistrationScript,
// if its version is smaller than the largest one in updateScriptVersion list, it cannot be executed.
// Note that
// the blockchain side will check the ReRegistrationScript's version to make sure
// (1) it is in the supportedAutScriptVersions, and (2) it is not smaller than the largest one in updateScriptVersion list;
// and the blockchain side will call the corresponding logic codes.
// 3.3.2 ReRegistrationScript consumes some existing AutRootToken and generates some new AutRootToken for that Aut Instance,
// where the new generated AutRootTokens have the same version as the ReRegistrationScript's version.
//
// 4. How a MintScript is created and handled:
// 4.1 The client queries supportedAutScriptVersions by blockchain through GetSupportedAutScriptVersions().
// 4.2 If the client local AutScriptVersion is not in supportedAutScriptVersions, the client is forced to upgrade;
// otherwise, the client use the local AutScriptVersion to set the MintScript's Version.
// 4.3 On the blockchain side,
// 4.3.1 MintScript consumes some existing AutRootTokens and generates some AutTokens, and
// these generated AutTokens have the same (script) Version as the MintScript's Version.
// Note that
// the blockchain side will check the MintScript's version to make sure it is in the supportedAutScriptVersions, and
// the blockchain side will call the corresponding logic codes.
// Note that the generated AutTokens will have version not smaller than that of the consumed AutRootTokens
// (this is a result of the Reregistration logic, since Reregistration will invalid all old AutRootTokens)
// (the verification of MintScript should check whether the MintScript's version is not smaller than that of AutRootTokens,
// which is actually the latest version in the metadata's updateScriptVersion).
//
// 5. How a TransferScript is created and handled:
// 5.1 The client queries supportedAutScriptVersions by blockchain through GetSupportedAutScriptVersions().
// 5.2 If the client local AutScriptVersion is not in supportedAutScriptVersions, the client is forced to upgrade;
// otherwise, the client use the local AutScriptVersion to set the TransferScript's Version.
// 5.3 On the blockchain side,
// 5.3.1 TransferScript consumes some existing AutTokens and generate some new AutTokens, and
// these generated tokens have the same (script) Version as the TransferScript's Version.
// Note that
// the blockchain side will check the TransferScript's version to make sure it is in the supportedAutScriptVersions, and
// the blockchain side will call the corresponding logic codes.
// Note that the generated AutTokens should have version not smaller than that of the consumed AutTokens
// (the verification of TransferScript should check that its version is not smaller than that of the consumed AutTokens).
//
// 6. How a client creates BurnScript:
// the same as that for TransferScript.

// These version-constants are used to maintain the history AutScriptVersion.
const (
	AutScriptVersion_Unknown uint32 = 0 // reserved
	AutScriptVersion_1       uint32 = 1
	// todo: when new versions added, add here and update AutScriptVersion and AutScriptVersionSet.
)

// AutScriptVersionSet collects all defined AutScriptVersions.
var AutScriptVersionSet = make(map[uint32]uint32)

// init put all defined AutScriptVersion into AutScriptVersionSet.
// When a new AutScriptVersion is defined, code here.
func init() {
	AutScriptVersionSet[AutScriptVersion_1] = AutScriptVersion_1
}

// AutScriptVersion is the current latest version of AutScript.
const AutScriptVersion = AutScriptVersion_1

// AutMetadataVersionInitValue defines the initial value for AutMetadata.Version,
// and increase by 1 each time the Metadata is updated due to ReRegistrationScript.
// DO NOT CHANGE THIS VALUE, NEVER!
const AutMetadataVersionInitValue = uint32(1)

// end of codes
