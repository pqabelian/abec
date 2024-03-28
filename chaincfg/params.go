package chaincfg

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a block can
	// have for the main network.  It is the value 2^224 - 1.
	// 0x1e
	//mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)
	mainPowLimit = new(big.Int).Lsh(new(big.Int).SetInt64(0x017c38), 208)

	// regressionPowLimit is the highest proof of work value a block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// simNetPowLimit is the highest proof of work value a block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// StartTime is the median block time after which voting on the
	// deployment starts.
	StartTime uint64

	// ExpireTime is the median block time after which the attempted
	// deployment expires.
	ExpireTime uint64
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.  This is useful to be able to get the details
// of a specific deployment by name.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package. The segwit package
	// includes the deployment of BIPS 141, 142, 144, 145, 147 and 173.
	DeploymentSegwit

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a network by its parameters.  These parameters may be
// used by applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.AbelianNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlockAbe

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// These fields are related to voting on consensus rule changes.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change. It should typically
	// be 95% for the main network and 75% for test networks.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32
	MinerConfirmationWindow       uint32
	Deployments                   [DefinedDeployments]ConsensusDeployment

	// Mempool parameters
	RelayNonStdTxs bool

	// Human-readable part for Bech32 encoded segwit addresses, as defined
	// in BIP 173.
	Bech32HRPSegwit string

	// Address encoding magics
	AbelAddressNetId        byte
	PQRingCTID              byte // First byte of a PQRingCT address
	PubKeyHashAddrID        byte // First byte of a P2PKH address
	ScriptHashAddrID        byte // First byte of a P2SH address
	PrivateKeyID            byte // First byte of a WIF private key
	WitnessPubKeyHashAddrID byte // First byte of a P2WPKH address
	WitnessScriptHashAddrID byte // First byte of a P2WSH address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW specifies the block height from which Ethash-PoW mining is applied.
	BlockHeightEthashPoW int32

	// EthashEpochLength specifies the epoch length of EthashPoW.
	EthashEpochLength int32

	// BlockHeightMLP specifies the block height from which MLP and AUT are supported.
	// ToDo(MLP):
	BlockHeightMLPAUT int32
	// BlockHeightMLPAUTCOMMIT specifies the block height
	// from which new transactions with version before TxVersion_Height_MLPAUT_300000 will not be accepted anymore.
	BlockHeightMLPAUTCOMMIT int32
}

// MainNetParams defines the network parameters for the main network.
var MainNetParams = Params{
	Name: "mainnet",
	Net:  wire.MainNet,
	//DefaultPort: "8333",
	DefaultPort: "8666",
	// TODO: this DNSSeed principle will be learned
	DNSSeeds: []DNSSeed{
		{"dnsseed.theabelian.net", false},
		/*		{"seed.bitcoin.sipa.be", true},
				{"dnsseed.bluematt.me", true},
				{"dnsseed.bitcoin.dashjr.org", false},
				{"seed.bitcoinstats.com", true},
				{"seed.bitnodes.io", false},
				{"seed.bitcoin.jonasschnelli.ch", true},*/

	},

	// Chain parameters
	GenesisBlock: &genesisBlock,
	GenesisHash:  &genesisHash,
	PowLimit:     mainPowLimit,
	PowLimitBits: 0x1d017c38, //,
	//PowLimitBits:             0x1d00ffff,
	//CoinbaseMaturity:         100,
	CoinbaseMaturity:         200,
	SubsidyReductionInterval: 400_000,
	TargetTimespan:           time.Second * 256 * 4000, // 14 days TODO(abe):this value may be need changed
	TargetTimePerBlock:       time.Second * 256,        // 10 minutes TODO(abe): this value may be need changed, now temporary to be 3 min
	RetargetAdjustmentFactor: 4,                        // 25% less, 400% more
	ReduceMinDifficulty:      false,                    // TODO(abe): this config may be used for adjust the difficult automatic?
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	// example: {1000, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")}, {...}
	Checkpoints: []Checkpoint{
		{20000, newHashFromStr("000000000c4b95ac27d9ae3db2cc5b37e21ac173c773976481fecb75533b61db")},
		{40000, newHashFromStr("0000000013c7a5d5ef76c11ae4775015620b3784590bdda12daf4ddd063b2c58")},
		{56000, newHashFromStr("26dc7b66d85d0b6336a1533b36590f6cc082f0ab1469a772e973159ce78456f6")},
		{60000, newHashFromStr("b7eb9ef9f4ec315b51fbe18e00b79a410f974ae24933ef65d8a40c643003fe10")},
		{80000, newHashFromStr("88334753bb1b4e53485ee3b48327067139ddb053178c0e1192046d4ee0ef4d8e")},
		{100000, newHashFromStr("e21edefcd3535977e916c1f945c701a47ef1cff0bb75b855690fb50e6bb4b32b")},
		{120000, newHashFromStr("fcc3966855fd3ea61d42e47be934e9f8c55607ad5b7cf2f0629516b012482bda")},
		{140000, newHashFromStr("7ff693005455c348e4b31596e2bef4e8a6d176ca87692705267eb01a4ae10b97")},
		{160000, newHashFromStr("cfe129e8b9427eed69c78b632f1f53a26b0c2f0bbe38c8b849a9a799dc474e1b")},
		{180000, newHashFromStr("117adee88b3dc210657fcba138c39295aac6e322361345aae14dba39c9a42693")},
		{196000, newHashFromStr("b504a4b4fb7e2141f493885d40e5742db7eab8359b6dfc9569dc5be58c020da4")},
		{200000, newHashFromStr("48804fd65122a6a5df5edb02f4351b8fe58e992245c0675588af690b267a103a")},
		{212000, newHashFromStr("4612a35933bc8161d781a4ce351295f9264b73ede03397b4da02ed9c8d03bdb4")},
	},
	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	//		todo: 20220324
	MinerConfirmationWindow: 2016, //
	// TODO(20220409): clear the deployment information
	Deployments: [DefinedDeployments]ConsensusDeployment{
		//DeploymentTestDummy: {
		//	BitNumber:  28,
		//	StartTime:  1199145601, // January 1, 2008 UTC
		//	ExpireTime: 1230767999, // December 31, 2008 UTC
		//},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "bc", // always bc for main net

	// Address encoding magics
	AbelAddressNetId:        0x00,
	PQRingCTID:              0x00, // starts with 1, TODO(abe): adjust the prefix
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW specifies the block height from which Ethash-PoW mining is applied.
	BlockHeightEthashPoW: 56000,

	// EthashEpochLength specifies the epoch length of EthashPoW.
	EthashEpochLength: 4000,

	// BlockHeightMLP specifies the block height from which MLP and AUT are supported.
	// ToDo(MLP):
	BlockHeightMLPAUT:       300000,
	BlockHeightMLPAUTCOMMIT: 320000,
}

// RegressionNetParams defines the network parameters for the regression test
// network.  Not to be confused with the test network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name: "regtest",
	Net:  wire.TestNet,
	//DefaultPort: "18444",
	DefaultPort: "18777",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         200,
	SubsidyReductionInterval: 400_000,
	TargetTimespan:           time.Second * 256 * 4000,
	TargetTimePerBlock:       time.Second * 256,
	RetargetAdjustmentFactor: 4, // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 108, // 75%  of MinerConfirmationWindow
	MinerConfirmationWindow:       144,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "rb",

	// Address encoding magics
	AbelAddressNetId:        0x01,
	PQRingCTID:              0x01, // starts with 1,
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW specifies the block height from which Ethash-PoW mining is applied.
	BlockHeightEthashPoW: 300,
	// EthashEpochLength specifies the epoch length of EthashPoW.
	EthashEpochLength: 200,

	// BlockHeightMLP specifies the block height from which MLP and AUT are supported.
	// ToDo(MLP):
	BlockHeightMLPAUT:       300000,
	BlockHeightMLPAUTCOMMIT: 320000,
}

// TestNet3Params defines the network parameters for the test network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name: "testnet3",
	Net:  wire.TestNet3,
	//DefaultPort: "18333",
	DefaultPort: "18666",
	DNSSeeds:    []DNSSeed{
		//{"testnet-seed.bitcoin.jonasschnelli.ch", true},
		//{"testnet-seed.bitcoin.schildbach.de", false},
		//{"seed.tbtc.petertodd.org", true},
		//{"testnet-seed.bluematt.me", false},
	},

	// Chain parameters
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
	PowLimit:                 testNet3PowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         200,
	SubsidyReductionInterval: 400_000,
	TargetTimespan:           time.Second * 256 * 4000, // 14 days TODO(abe):this value may be need changed
	TargetTimePerBlock:       time.Second * 256,        // 10 minutes TODO(abe): this value may be need changed, now temporary to be 3 min
	RetargetAdjustmentFactor: 4,                        // 25% less, 400% more
	ReduceMinDifficulty:      true,                     // TODO(abe): this config may be used for adjust the difficult automatic?
	MinDiffReductionTime:     time.Minute * 20,
	GenerateSupported:        true,
	// Checkpoints ordered from oldest to newest.
	// example: {1000, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")}, {...}
	Checkpoints: []Checkpoint{},

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 3800, // 95% of MinerConfirmationWindow
	//		todo: 20220324
	MinerConfirmationWindow: 4000, //
	// TODO(20220409): clear the deployment information
	Deployments: [DefinedDeployments]ConsensusDeployment{
		//DeploymentTestDummy: {
		//	BitNumber:  28,
		//	StartTime:  1199145601, // January 1, 2008 UTC
		//	ExpireTime: 1230767999, // December 31, 2008 UTC
		//},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tb",

	// Address encoding magics
	AbelAddressNetId:        0x02,
	PQRingCTID:              0x02, // starts with 1,
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW specifies the block height from which Ethash-PoW mining is applied.
	BlockHeightEthashPoW: 56000,
	// EthashEpochLength specifies the epoch length of EthashPoW.
	EthashEpochLength: 4000,

	// BlockHeightMLP specifies the block height from which MLP and AUT are supported.
	// ToDo(MLP):
	BlockHeightMLPAUT:       300000,
	BlockHeightMLPAUTCOMMIT: 320000,
}

// SimNetParams defines the network parameters for the simulation test
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18888",
	DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         200,
	SubsidyReductionInterval: 400_000,
	TargetTimespan:           time.Second * 256 * 4000,
	TargetTimePerBlock:       time.Second * 256,
	RetargetAdjustmentFactor: 4, // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	//
	// The miner confirmation window is defined as:
	//   target proof of work timespan / target proof of work spacing
	RuleChangeActivationThreshold: 75, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       100,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber:  28,
			StartTime:  0,             // Always available for vote
			ExpireTime: math.MaxInt64, // Never expires
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "sb", // always sb for sim net

	// Address encoding magics
	AbelAddressNetId:        0x03,
	PQRingCTID:              0x03, // starts with 1,
	PubKeyHashAddrID:        0x00, // starts with 1
	ScriptHashAddrID:        0x05, // starts with 3
	PrivateKeyID:            0x80, // starts with 5 (uncompressed) or K (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,

	// BlockHeightEthashPoW
	// BlockHeightEthashPoW specifies the block height from which Ethash-PoW mining is applied.
	BlockHeightEthashPoW: 300,
	// EthashEpochLength specifies the epoch length of EthashPoW.
	EthashEpochLength: 200,

	// BlockHeightMLP specifies the block height from which MLP and AUT are supported.
	// ToDo(MLP):
	BlockHeightMLPAUT:       1000,
	BlockHeightMLPAUTCOMMIT: 2000,
}

var (
	// ErrDuplicateNet describes an error where the parameters for a
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Abelian network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")
)

var (
	registeredNets       = make(map[wire.AbelianNet]struct{})
	pubKeyHashAddrIDs    = make(map[byte]struct{})
	scriptHashAddrIDs    = make(map[byte]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for an Abelian network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]

	// A valid Bech32 encoded segwit address always has as prefix the
	// human-readable part for the given net followed by '1'.
	bech32SegwitPrefixes[params.Bech32HRPSegwit+"1"] = struct{}{}
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for segwit
// addresses on any default or registered network.  This is used when decoding
// an address string into a specific address type.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}
