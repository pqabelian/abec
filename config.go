// Copyright (c) 2022-2023 The Abelian Foundation
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/consensus/ethash"
	"github.com/pqabelian/abec/wire"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abesuite/go-socks/socks"
	flags "github.com/jessevdk/go-flags"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/connmgr"
	"github.com/pqabelian/abec/database"
	_ "github.com/pqabelian/abec/database/ffldb"
	"github.com/pqabelian/abec/mempool"
	"github.com/pqabelian/abec/peer"
)

const (
	defaultConfigFilename       = "abec.conf"
	defaultDataDirname          = "data"
	defaultLogLevel             = "info"
	defaultLogDirname           = "logs"
	defaultLogFilename          = "abec.log"
	defaultTLogFilename         = "t.log"
	defaultMaxPeers             = 125
	defaultBanDuration          = time.Hour * 24
	defaultBanThreshold         = 100
	defaultConnectTimeout       = time.Second * 30
	defaultMaxRPCClients        = 10
	defaultMaxRPCWebsockets     = 25
	defaultMaxRPCConcurrentReqs = 20
	defaultDbType               = "ffldb"
	defaultFreeTxRelayLimit     = 15.0
	defaultTrickleInterval      = peer.DefaultTrickleInterval
	defaultBlockMinSize         = 0
	defaultBlockMaxSize         = 750000
	defaultBlockMinWeight       = 0
	defaultBlockMaxWeight       = 3000000
	blockMaxSizeMin             = 1000
	blockMaxSizeMax             = blockchain.MaxBlockBaseSize - 1000
	blockMaxWeightMin           = 4000
	blockMaxWeightMax           = blockchain.MaxBlockWeight - 4000

	// defaultBlockSizeMinMLPAUT / defaultBlockSizeMaxMLPAUT is used as default configuration
	//  if the network is not congested, gradually increase this to 8M
	defaultBlockSizeMinMLPAUT = 0
	defaultBlockSizeMaxMLPAUT = 1 * 1024 * 1024 // 1M
	// defaultBlockFullSizeMinMLPAUT / defaultBlockFullSizeMaxMLPAUT is used as default configuration
	//  if the network is not congested, gradually increase it to MaxBlockPayloadAbe
	defaultBlockFullSizeMinMLPAUT = 0
	defaultBlockFullSizeMaxMLPAUT = 64 * 1024 * 1024 // 64M
	blockSizeMaxMLPAUTMin         = 1000
	blockSizeMaxMLPAUTMax         = blockchain.MaxBlockBaseSizeMLPAUT - 1000
	blockFullSizeMaxMLPAUTMin     = 1000
	blockFullSizeMaxMLPAUTMax     = blockchain.MaxBlockFullSizeMLPAUT - 1000

	// todo(abe):
	defaultGenerate         = false
	defaultExternalGenerate = false
	//defaultGenerate              = true
	defaultHashRateWatermark     = 10
	defaultMaxOrphanTransactions = 100
	defaultMaxOrphanTxSize       = 5500000 // 5 500 000, For a 5(7)-5 transferTx, the witness size could be 5244527 bytes, and the content size could 110,000 bytes
	defaultSigCacheMaxSize       = 100000
	defaultWitnessCacheMaxSize   = 1000
	sampleConfigFilename         = "sample-abec.conf"
	defaultTxIndex               = false
	defaultAddrIndex             = false
	defaultNodeType              = "unsetnode"
	defaultMaxReservedWitness    = peer.DefaultMaxReservedWitness
	defaultAllowDiskCacheTx      = true
	defaultCacheTxDirname        = "txcaches"
	defaultCacheTxFilename       = "txcache.abe"
)

var (
	defaultHomeDir     = abeutil.AppDataDir("abec", false)
	defaultConfigFile  = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultDataDir     = filepath.Join(defaultHomeDir, defaultDataDirname)
	defaultCacheTxDir  = filepath.Join(defaultHomeDir, defaultCacheTxDirname)
	knownDbTypes       = database.SupportedDrivers()
	defaultRPCKeyFile  = filepath.Join(defaultHomeDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(defaultHomeDir, "rpc.cert")
	defaultLogDir      = filepath.Join(defaultHomeDir, defaultLogDirname)
)

// runServiceCommand is only set to a real function on Windows.  It is used
// to parse and execute service commands specified via the -s flag.
var runServiceCommand func(string) error

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// config defines the configuration options for abec.
//
// See loadConfig for details on the configuration load process.
type config struct {
	AddCheckpoints         []string      `long:"addcheckpoint" description:"Add a custom checkpoint.  Format: '<height>:<hash>'"`
	AddPeers               []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	AgentBlacklist         []string      `long:"agentblacklist" description:"A comma separated list of user-agent substrings which will cause abec to reject any peers whose user-agent contains any of the blacklisted substrings."`
	AgentWhitelist         []string      `long:"agentwhitelist" description:"A comma separated list of user-agent substrings which will cause abec to require all peers' user-agents to contain one of the whitelisted substrings. The blacklist is applied before the blacklist, and an empty whitelist will allow all agents that do not fail the blacklist."`
	BanDuration            time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold           uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers."`
	BlockMaxSize           uint32        `long:"blockmaxsize" description:"Maximum block size in bytes to be used when creating a block"`
	BlockMinSize           uint32        `long:"blockminsize" description:"Mininum block size in bytes to be used when creating a block"`
	BlockSizeMaxMLPAUT     uint32        `long:"blocksizemaxmlpaut" description:"Maximum block size in bytes to be used when creating a block after mlpaut"`
	BlockSizeMinMLPAUT     uint32        `long:"blocksizeminmlpaut" description:"Mininum block size in bytes to be used when creating a block after mlpaut"`
	BlockFullSizeMaxMLPAUT uint32        `long:"blockfullsizemaxmlpaut" description:"Maximum block full size in bytes to be used when creating a block"`
	BlockFullSizeMinMLPAUT uint32        `long:"blockfullsizeminmlpaut" description:"Mininum block full size in bytes to be used when creating a block"`
	BlockMaxWeight         uint32        `long:"blockmaxweight" description:"Maximum block weight to be used when creating a block"`
	BlockMinWeight         uint32        `long:"blockminweight" description:"Mininum block weight to be used when creating a block"`
	BlockPrioritySize      uint32        `long:"blockprioritysize" description:"Size in bytes for high-priority/low-fee transactions when creating a block"`
	BlocksOnly             bool          `long:"blocksonly" description:"Do not accept transactions from remote peers."`
	ConfigFile             string        `short:"C" long:"configfile" description:"Path to configuration file"`
	ConnectPeers           []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	CPUProfile             string        `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	DataDir                string        `short:"b" long:"datadir" description:"Directory to store data"`
	DbType                 string        `long:"dbtype" description:"Database backend to use for the Block Chain"`
	DebugLevel             string        `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	DropTxIndex            bool          `long:"droptxindex" description:"Deletes the hash-based transaction index from the database on start up and then exits."`
	ExternalIPs            []string      `long:"externalip" description:"Add an ip to the list of local addresses we claim to listen on to peers"`
	//	todo: (EthashPoW)
	EthashConfig           ethash.Config
	EthashVerifyByFullDAG  bool          `long:"ethashverifybyfulldag" description:"For a mining node, use full DAG to verify EthashPow"`
	Generate               bool          `long:"generate" description:"Generate (mine) ABEs using the CPU"`
	HashRateWatermark      int           `long:"hashratewatermark" description:"Watermark of CPU mining hashrate that will trigger a warning."`
	ExternalGenerate       bool          `long:"externalgenerate" description:"Generate (mine) ABEs using the external miners"`
	FreeTxRelayLimit       float64       `long:"limitfreerelay" description:"Limit relay of transactions with no transaction fee to the given amount in thousands of bytes per minute"`
	Listeners              []string      `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 8333, testnet: 18333)"`
	LogDir                 string        `long:"logdir" description:"Directory to log output."`
	MaxOrphanTxs           int           `long:"maxorphantx" description:"Max number of orphan transactions to keep in memory"`
	MaxPeers               int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	MiningAddrs            []string      `long:"miningaddr" description:"Add the specified payment address to the list of addresses to use for generated blocks -- At least one address is required if the generate or externalgenerate option is set"`
	MinRelayTxFee          uint64        `long:"minrelaytxfee" description:"The minimum transaction fee in Neutrino/kB to be considered a non-zero fee."`
	DisableBanning         bool          `long:"nobanning" description:"Disable banning of misbehaving peers"`
	NoCFilters             bool          `long:"nocfilters" description:"Disable committed filtering (CF) support"`
	DisableCheckpoints     bool          `long:"nocheckpoints" description:"Disable built-in checkpoints.  Don't do this unless you know what you're doing."`
	DisableDNSSeed         bool          `long:"nodnsseed" description:"Disable DNS seeding for peers"`
	DisableListen          bool          `long:"nolisten" description:"Disable listening for incoming connections -- NOTE: Listening is automatically disabled if the --connect or --proxy options are used without also specifying listen interfaces via --listen"`
	NodeType               string        `long:"nodetype" description:"Node type (fullnode/semifullnode/normalnode) default: normalnode"`
	NoOnion                bool          `long:"noonion" description:"Disable connecting to tor hidden services"`
	NoPeerBloomFilters     bool          `long:"nopeerbloomfilters" description:"Disable bloom filtering support"`
	NoRelayPriority        bool          `long:"norelaypriority" description:"Do not require free or low-fee transactions to have high priority for relaying"`
	DisableRPC             bool          `long:"norpc" description:"Disable built-in RPC server -- NOTE: The RPC server is disabled by default if no rpcuser/rpcpass or rpclimituser/rpclimitpass is specified"`
	DisableTLS             bool          `long:"notls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	EnableGetWorkRPC       bool          `long:"enablegetwork" description:"Enable get work RPC server, this server is TLS disabled"`
	OnionProxy             string        `long:"onion" description:"Connect to tor hidden services via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	OnionProxyPass         string        `long:"onionpass" default-mask:"-" description:"Password for onion proxy server"`
	OnionProxyUser         string        `long:"onionuser" description:"Username for onion proxy server"`
	Profile                string        `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	Proxy                  string        `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyPass              string        `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	ProxyUser              string        `long:"proxyuser" description:"Username for proxy server"`
	RegressionTest         bool          `long:"regtest" description:"Use the regression test network"`
	RejectNonStd           bool          `long:"rejectnonstd" description:"Reject non-standard transactions regardless of the default settings for the active network."`
	RejectReplacement      bool          `long:"rejectreplacement" description:"Reject transactions that attempt to replace existing transactions within the mempool through the Replace-By-Fee (RBF) signaling policy."`
	RelayNonStd            bool          `long:"relaynonstd" description:"Relay non-standard transactions regardless of the default settings for the active network."`
	RPCCert                string        `long:"rpccert" description:"File containing the certificate file"`
	RPCKey                 string        `long:"rpckey" description:"File containing the certificate key"`
	RPCLimitPass           string        `long:"rpclimitpass" default-mask:"-" description:"Password for limited RPC connections"`
	RPCLimitUser           string        `long:"rpclimituser" description:"Username for limited RPC connections"`
	RPCListeners           []string      `long:"rpclisten" description:"Add an interface/port to listen for RPC connections (default port: 8667, testnet: 18667, simnet: 18889)"`
	RPCListenersGetWork    []string      `long:"rpclistengetwork" description:"Add an interface/port to listen for RPC connections for get work (default port: 8668, testnet: 18668, simnet: 18890)"`
	RPCMaxClients          int           `long:"rpcmaxclients" description:"Max number of RPC clients for standard connections"`
	RPCMaxConcurrentReqs   int           `long:"rpcmaxconcurrentreqs" description:"Max number of concurrent RPC requests that may be processed concurrently"`
	RPCMaxWebsockets       int           `long:"rpcmaxwebsockets" description:"Max number of RPC websocket connections"`
	RPCQuirks              bool          `long:"rpcquirks" description:"Mirror some JSON-RPC quirks of Bitcoin Core -- NOTE: Discouraged unless interoperability issues need to be worked around"`
	RPCPass                string        `short:"P" long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	RPCUser                string        `short:"u" long:"rpcuser" description:"Username for RPC connections"`
	SigCacheMaxSize        uint          `long:"sigcachemaxsize" description:"The maximum number of entries in the signature verification cache"`
	WitnessCacheMaxSize    uint          `long:"witnesscachemaxsize" description:"The maximum number of entries in the witness cache"`
	SimNet                 bool          `long:"simnet" description:"Use the simulation test network"`
	AddFakePoWHeightScopes []string      `long:"addfakepowheightscope" description:"Add a custom height range for fake pow.  Format: '<start_height>:<end_height>'"`
	TestNet3               bool          `long:"testnet" description:"Use the test network"`
	TorIsolation           bool          `long:"torisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection."`
	TrickleInterval        time.Duration `long:"trickleinterval" description:"Minimum time between attempts to send new inventory to a connected peer"`
	TxIndex                bool          `long:"txindex" description:"Maintain a full hash-based transaction index which makes all transactions available via the getrawtransaction RPC"`
	UserAgentComments      []string      `long:"uacomment" description:"Comment to add to the user agent -- See BIP 14 for more information."`
	Upnp                   bool          `long:"upnp" description:"Use UPnP to map our listening port outside of NAT"`
	ShowVersion            bool          `short:"V" long:"version" description:"Display version information and exit"`
	Whitelists             []string      `long:"whitelist" description:"Add an IP network or IP that will not be banned. (eg. 192.168.1.0/24 or ::1)"`
	lookup                 func(string) ([]net.IP, error)
	oniondial              func(string, string, time.Duration) (net.Conn, error)
	dial                   func(string, string, time.Duration) (net.Conn, error)
	addCheckpoints         []chaincfg.Checkpoint
	addFakePowHeightScopes []blockchain.BlockHeightScope
	// todo: (ethmining) miningAddr vs. the above MiningAddr, need to clarify
	miningAddrs []abeutil.AbelAddress
	//miningAddrBytes []byte
	minRelayTxFee        abeutil.Amount
	nodeType             wire.NodeType
	witnessServiceHeight int32
	serviceFlag          wire.ServiceFlag
	whitelists           []*net.IPNet
	WorkingDir           string `long:"workingdir" description:"Working directory"`

	// transaction cache in disk
	AllowDiskCacheTx   bool   `long:"allowdiskcachetx" description:"Allow use disk to cache transaction if necessary"`
	CacheTxDir         string `long:"cachetxdir" description:"Directory to store cached transaction data when allow use disk to cache transaction if necessary"`
	tLogFilename       string
	maxReservedWitness uint32 //  `long:"maxreservedwitness" description:"The maximum number of blocks witness that the node stores (default: 4000)"`
}

// serviceOptions defines the configuration options for the daemon as a service on
// Windows.
type serviceOptions struct {
	ServiceCommand string `short:"s" long:"service" description:"Service command {install, remove, start, stop}"`
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(defaultHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	switch logLevel {
	case "trace":
		fallthrough
	case "debug":
		fallthrough
	case "info":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "critical":
		return true
	}
	return false
}

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsystems for stable display.
	sort.Strings(subsystems)
	return subsystems
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		setLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// validDbType returns whether or not dbType is a supported database type.
func validDbType(dbType string) bool {
	for _, knownType := range knownDbTypes {
		if dbType == knownType {
			return true
		}
	}

	return false
}

// removeDuplicateAddresses returns a new slice with all duplicate entries in
// addrs removed.
func removeDuplicateAddresses(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, val := range addrs {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}

// normalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func normalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func normalizeAddresses(addrs []string, defaultPort string) []string {
	for i, addr := range addrs {
		addrs[i] = normalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// newCheckpointFromStr parses checkpoints in the '<height>:<hash>' format.
func newCheckpointFromStr(checkpoint string) (chaincfg.Checkpoint, error) {
	parts := strings.Split(checkpoint, ":")
	if len(parts) != 2 {
		return chaincfg.Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q -- use the syntax <height>:<hash>",
			checkpoint)
	}

	height, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return chaincfg.Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to malformed height", checkpoint)
	}

	if len(parts[1]) == 0 {
		return chaincfg.Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to missing hash", checkpoint)
	}
	hash, err := chainhash.NewHashFromStr(parts[1])
	if err != nil {
		return chaincfg.Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to malformed hash", checkpoint)
	}

	return chaincfg.Checkpoint{
		Height: int32(height),
		Hash:   hash,
	}, nil
}

// parseCheckpoints checks the checkpoint strings for valid syntax
// ('<height>:<hash>') and parses them to chaincfg.Checkpoint instances.
func parseCheckpoints(checkpointStrings []string) ([]chaincfg.Checkpoint, error) {
	if len(checkpointStrings) == 0 {
		return nil, nil
	}
	checkpoints := make([]chaincfg.Checkpoint, len(checkpointStrings))
	for i, cpString := range checkpointStrings {
		checkpoint, err := newCheckpointFromStr(cpString)
		if err != nil {
			return nil, err
		}
		checkpoints[i] = checkpoint
	}
	return checkpoints, nil
}

// newCheckpointFromStr parses checkpoints in the '<height>:<hash>' format.
func newFakePowHeightScopeFromStr(heightScope string) (blockchain.BlockHeightScope, error) {
	parts := strings.Split(heightScope, ":")
	if len(parts) != 2 {
		return blockchain.BlockHeightScope{}, fmt.Errorf("unable to parse "+
			"heightScope %q -- use the syntax <start_height>:<end_height>",
			heightScope)
	}

	startHeight, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return blockchain.BlockHeightScope{}, fmt.Errorf("unable to parse "+
			"heightScope %q due to malformed height", heightScope)
	}

	endHeight, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return blockchain.BlockHeightScope{}, fmt.Errorf("unable to parse "+
			"heightScope %q due to malformed height", heightScope)
	}

	if startHeight > endHeight {
		return blockchain.BlockHeightScope{}, fmt.Errorf("unable to parse "+
			"heightScope %q due to malformed scope", heightScope)
	}

	return blockchain.BlockHeightScope{
		StartHeight: int32(startHeight),
		EndHeight:   int32(endHeight),
	}, nil
}

// parseFakePowHeightScopes checks the heightscope strings for valid syntax
// ('<start_height>:<end_height>') and parses them to blockchain.BlockHeightScopes instances.
func parseFakePowHeightScopes(fakePowHeightScopeStrings []string) ([]blockchain.BlockHeightScope, error) {
	if len(fakePowHeightScopeStrings) == 0 {
		return nil, nil
	}
	fakePoWHeightScopes := make([]blockchain.BlockHeightScope, len(fakePowHeightScopeStrings))
	for i, hrString := range fakePowHeightScopeStrings {
		fakePowHeightScope, err := newFakePowHeightScopeFromStr(hrString)
		if err != nil {
			return nil, err
		}
		fakePoWHeightScopes[i] = fakePowHeightScope
	}
	return fakePoWHeightScopes, nil
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, so *serviceOptions, options flags.Options) *flags.Parser {
	parser := flags.NewParser(cfg, options)
	if runtime.GOOS == "windows" {
		parser.AddGroup("Service Options", "Service Options", so)
	}
	return parser
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
//
// The above results in abec functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options.  Command line options always take precedence.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		ConfigFile:             defaultConfigFile,
		DebugLevel:             defaultLogLevel,
		MaxPeers:               defaultMaxPeers,
		BanDuration:            defaultBanDuration,
		BanThreshold:           defaultBanThreshold,
		RPCMaxClients:          defaultMaxRPCClients,
		RPCMaxWebsockets:       defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs:   defaultMaxRPCConcurrentReqs,
		DataDir:                defaultDataDir,
		LogDir:                 defaultLogDir,
		DbType:                 defaultDbType,
		RPCKey:                 defaultRPCKeyFile,
		RPCCert:                defaultRPCCertFile,
		MinRelayTxFee:          mempool.DefaultMinRelayTxFee,
		FreeTxRelayLimit:       defaultFreeTxRelayLimit,
		TrickleInterval:        defaultTrickleInterval,
		BlockMinSize:           defaultBlockMinSize,
		BlockMaxSize:           defaultBlockMaxSize,
		BlockSizeMinMLPAUT:     defaultBlockSizeMinMLPAUT,
		BlockSizeMaxMLPAUT:     defaultBlockSizeMaxMLPAUT,
		BlockFullSizeMinMLPAUT: defaultBlockFullSizeMinMLPAUT,
		BlockFullSizeMaxMLPAUT: defaultBlockFullSizeMaxMLPAUT,
		BlockMinWeight:         defaultBlockMinWeight,
		BlockMaxWeight:         defaultBlockMaxWeight,
		BlockPrioritySize:      mempool.DefaultBlockPrioritySize,
		MaxOrphanTxs:           defaultMaxOrphanTransactions,
		SigCacheMaxSize:        defaultSigCacheMaxSize,
		WitnessCacheMaxSize:    defaultWitnessCacheMaxSize,
		Generate:               defaultGenerate,
		ExternalGenerate:       defaultExternalGenerate,
		HashRateWatermark:      defaultHashRateWatermark,
		EthashConfig:           ethash.DefaultCfg,
		TxIndex:                defaultTxIndex,
		NodeType:               defaultNodeType,
		maxReservedWitness:     defaultMaxReservedWitness,
		AllowDiskCacheTx:       defaultAllowDiskCacheTx,
		CacheTxDir:             defaultCacheTxDir,
	}
	// Service options which are only added on Windows.
	// TODO(osy): this set is ingoned, we should detect it!
	// Answer(osy): this set is helpful for Windows, but we do not know the function.
	serviceOpts := serviceOptions{}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified.  Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	preParser := newConfigParser(&preCfg, &serviceOpts, flags.HelpFlag)
	_, err := preParser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version()) //this process is all in version.go
		os.Exit(0)
	}

	// Perform service command and exit if specified.  Invalid service
	// commands show an appropriate error.  Only runs on Windows since
	// the runServiceCommand function will be nil when not on Windows.
	if serviceOpts.ServiceCommand != "" && runServiceCommand != nil {
		err := runServiceCommand(serviceOpts.ServiceCommand)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(0)
	}

	// Change working directory if needed.
	if preCfg.WorkingDir != "" {
		err := os.Chdir(preCfg.WorkingDir)
		if err != nil {
			return nil, nil, err
		}
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, &serviceOpts, flags.Default)
	if !(preCfg.RegressionTest || preCfg.SimNet) || preCfg.ConfigFile !=
		defaultConfigFile {

		if _, err := os.Stat(preCfg.ConfigFile); os.IsNotExist(err) {
			err := createDefaultConfigFile(preCfg.ConfigFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating a "+
					"default config file: %v\n", err)
			}
		}

		err := flags.NewIniParser(parser).ParseFile(preCfg.ConfigFile)
		if err != nil {
			if _, ok := err.(*os.PathError); !ok {
				fmt.Fprintf(os.Stderr, "Error parsing config "+
					"file: %v\n", err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
			configFileError = err
		}
	}

	// Don't add peers from the config file when in regression test mode.
	if preCfg.RegressionTest && len(cfg.AddPeers) > 0 {
		cfg.AddPeers = nil
	}

	// Parse command line options again to ensure they take precedence.
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, nil, err
	}

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	err = os.MkdirAll(defaultHomeDir, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create home directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, err
	}

	// Multiple networks can't be selected simultaneously.
	numNets := 0
	// Count number of network flags passed; assign active network params
	// while we're at it
	if cfg.TestNet3 {
		numNets++
		activeNetParams = &testNet3Params
	}
	if cfg.RegressionTest {
		numNets++
		activeNetParams = &regressionNetParams
	}
	if cfg.SimNet {
		numNets++
		// Also disable dns seeding on the simulation test network.
		activeNetParams = &simNetParams
		cfg.DisableDNSSeed = true
	}
	if numNets > 1 {
		str := "%s: The testnet, regtest, segnet, and simnet params " +
			"can't be used together -- choose one of the four"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Check node type.
	// Different type would decide the service it can provide when communicating with its peers.
	// 1) full node: provide any witness
	// 2) semi full node: provide some witness
	// 3) normal node: provide some witness
	// Optimization: the service flag would use a bit to present the witness service, but it would
	// be supported by witness service height when initializing with its peers
	if cfg.NodeType == "fullnode" {
		cfg.nodeType = wire.FullNode
		cfg.serviceFlag = wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeTypeBit1
	} else if cfg.NodeType == "semifullnode" {
		cfg.nodeType = wire.SemiFullNode
		cfg.serviceFlag = wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeTypeBit2
	} else if cfg.NodeType == "normalnode" {
		cfg.nodeType = wire.NormalNode
		cfg.serviceFlag = wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeTypeBit1 | wire.SFNodeTypeBit2
	} else if cfg.NodeType == defaultNodeType {
		cfg.nodeType = wire.UnsetNode
	} else {
		return nil, nil, errors.New("nodetype should be fullnode or semifullnode or normalnode")
	}

	// Set the default policy for relaying non-standard transactions
	// according to the default of the active network. The set
	// configuration value takes precedence over the default value for the
	// selected network.
	relayNonStd := activeNetParams.RelayNonStdTxs
	switch {
	case cfg.RelayNonStd && cfg.RejectNonStd:
		str := "%s: rejectnonstd and relaynonstd cannot be used " +
			"together -- choose only one"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	case cfg.RejectNonStd:
		relayNonStd = false
	case cfg.RelayNonStd:
		relayNonStd = true
	}
	cfg.RelayNonStd = relayNonStd

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(activeNetParams))

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, netName(activeNetParams))

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Initialize log rotation.  After log rotation has been initialized, the
	// logger variables may be used.
	initLogRotator(filepath.Join(cfg.LogDir, defaultLogFilename))

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	cfg.CacheTxDir = cleanAndExpandPath(cfg.CacheTxDir)
	cfg.CacheTxDir = filepath.Join(cfg.CacheTxDir, netName(activeNetParams))

	cfg.tLogFilename = filepath.Join(cfg.DataDir, defaultTLogFilename)

	// Validate database type.
	if !validDbType(cfg.DbType) {
		str := "%s: The specified database type [%v] is invalid -- " +
			"supported types %v"
		err := fmt.Errorf(str, funcName, cfg.DbType, knownDbTypes)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate profile port number
	if cfg.Profile != "" {
		profilePort, err := strconv.Atoi(cfg.Profile)
		if err != nil || profilePort < 1024 || profilePort > 65535 {
			str := "%s: The profile port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// Don't allow ban durations that are too short.
	if cfg.BanDuration < time.Second {
		str := "%s: The banduration option may not be less than 1s -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.BanDuration)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate any given whitelisted IP addresses and networks.
	if len(cfg.Whitelists) > 0 {
		var ip net.IP
		cfg.whitelists = make([]*net.IPNet, 0, len(cfg.Whitelists))

		for _, addr := range cfg.Whitelists {
			_, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
				if ip == nil {
					str := "%s: The whitelist value of '%s' is invalid"
					err = fmt.Errorf(str, funcName, addr)
					fmt.Fprintln(os.Stderr, err)
					fmt.Fprintln(os.Stderr, usageMessage)
					return nil, nil, err
				}
				var bits int
				if ip.To4() == nil {
					// IPv6
					bits = 128
				} else {
					bits = 32
				}
				ipnet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(bits, bits),
				}
			}
			cfg.whitelists = append(cfg.whitelists, ipnet)
		}
	}

	// --addPeer and --connect do not mix.
	if len(cfg.AddPeers) > 0 && len(cfg.ConnectPeers) > 0 {
		str := "%s: the --addpeer and --connect options can not be " +
			"mixed"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// --proxy or --connect without --listen disables listening.
	if (cfg.Proxy != "" || len(cfg.ConnectPeers) > 0) &&
		len(cfg.Listeners) == 0 {
		cfg.DisableListen = true
	}
	// TODO(osy): This could be used to test in LAN
	// Connect means no DNS seeding.
	if len(cfg.ConnectPeers) > 0 {
		cfg.DisableDNSSeed = true
	}

	// Add the default listener if none were specified. The default
	// listener is all addresses on the listen port for the network
	// we are to connect to.
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []string{
			net.JoinHostPort("", activeNetParams.DefaultPort),
		}
	}

	// Check to make sure limited and admin users don't have the same username
	if cfg.RPCUser == cfg.RPCLimitUser && cfg.RPCUser != "" {
		str := "%s: --rpcuser and --rpclimituser must not specify the " +
			"same username"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Check to make sure limited and admin users don't have the same password
	if cfg.RPCPass == cfg.RPCLimitPass && cfg.RPCPass != "" {
		str := "%s: --rpcpass and --rpclimitpass must not specify the " +
			"same password"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// The RPC server is disabled if no username or password is provided.
	if (cfg.RPCUser == "" || cfg.RPCPass == "") &&
		(cfg.RPCLimitUser == "" || cfg.RPCLimitPass == "") {
		cfg.DisableRPC = true
	}

	if cfg.DisableRPC {
		abecLog.Infof("RPC service is disabled")
	}

	if cfg.EnableGetWorkRPC {
		abecLog.Infof("RPC server for getwork is enabled")
		cfg.ExternalGenerate = true
	}

	// Default RPC to listen on localhost only.
	if !cfg.DisableRPC && len(cfg.RPCListeners) == 0 {
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, activeNetParams.rpcPort)
			cfg.RPCListeners = append(cfg.RPCListeners, addr)
		}
	}

	// Setup RPC listeners for getwork.
	if cfg.EnableGetWorkRPC && len(cfg.RPCListenersGetWork) == 0 {
		// todo: localhost?
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCListenersGetWork = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, activeNetParams.rpcPortGetWork)
			cfg.RPCListenersGetWork = append(cfg.RPCListenersGetWork, addr)
		}
	}

	if cfg.RPCMaxConcurrentReqs < 0 {
		str := "%s: The rpcmaxwebsocketconcurrentrequests option may " +
			"not be less than 0 -- parsed [%d]"
		err := fmt.Errorf(str, funcName, cfg.RPCMaxConcurrentReqs)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate the the minrelaytxfee.
	cfg.minRelayTxFee = abeutil.Amount(cfg.MinRelayTxFee)

	// Limit the max block size to a sane value.
	if cfg.BlockMaxSize < blockMaxSizeMin || cfg.BlockMaxSize >
		blockMaxSizeMax {

		str := "%s: The blockmaxsize option must be in between %d " +
			"and %d -- parsed [%d]"
		err := fmt.Errorf(str, funcName, blockMaxSizeMin,
			blockMaxSizeMax, cfg.BlockMaxSize)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Limit the max block full size to a sane value.
	if cfg.BlockSizeMaxMLPAUT < blockSizeMaxMLPAUTMin || cfg.BlockSizeMaxMLPAUT >
		blockSizeMaxMLPAUTMax {

		str := "%s: The blocksizemaxmlpaut option must be in between %d " +
			"and %d -- parsed [%d]"
		err := fmt.Errorf(str, funcName, blockSizeMaxMLPAUTMin,
			blockSizeMaxMLPAUTMax, cfg.BlockFullSizeMaxMLPAUT)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}
	// Limit the max block full size to a sane value.
	if cfg.BlockFullSizeMaxMLPAUT < blockFullSizeMaxMLPAUTMin || cfg.BlockFullSizeMaxMLPAUT >
		blockFullSizeMaxMLPAUTMax {

		str := "%s: The blockfullsizemaxmlpaut option must be in between %d " +
			"and %d -- parsed [%d]"
		err := fmt.Errorf(str, funcName, blockFullSizeMaxMLPAUTMin,
			blockFullSizeMaxMLPAUTMax, cfg.BlockFullSizeMaxMLPAUT)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Limit the max block weight to a sane value.
	if cfg.BlockMaxWeight < blockMaxWeightMin ||
		cfg.BlockMaxWeight > blockMaxWeightMax {

		str := "%s: The blockmaxweight option must be in between %d " +
			"and %d -- parsed [%d]"
		err := fmt.Errorf(str, funcName, blockMaxWeightMin,
			blockMaxWeightMax, cfg.BlockMaxWeight)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Limit the max orphan count to a sane vlue.
	if cfg.MaxOrphanTxs < 0 {
		str := "%s: The maxorphantx option may not be less than 0 " +
			"-- parsed [%d]"
		err := fmt.Errorf(str, funcName, cfg.MaxOrphanTxs)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Limit the block priority and minimum block sizes to max block size.
	cfg.BlockPrioritySize = minUint32(cfg.BlockPrioritySize, cfg.BlockMaxSize)
	cfg.BlockMinSize = minUint32(cfg.BlockMinSize, cfg.BlockMaxSize)
	cfg.BlockMinWeight = minUint32(cfg.BlockMinWeight, cfg.BlockMaxWeight)

	cfg.BlockSizeMinMLPAUT = minUint32(cfg.BlockSizeMinMLPAUT, cfg.BlockSizeMaxMLPAUT)
	cfg.BlockFullSizeMinMLPAUT = minUint32(cfg.BlockFullSizeMinMLPAUT, cfg.BlockFullSizeMaxMLPAUT)

	switch {
	// If the max block size isn't set, but the max weight is, then we'll
	// set the limit for the max block size to a safe limit so weight takes
	// precedence.
	case cfg.BlockMaxSize == defaultBlockMaxSize &&
		cfg.BlockMaxWeight != defaultBlockMaxWeight:

		cfg.BlockMaxSize = blockchain.MaxBlockBaseSize - 1000

	// If the max block weight isn't set, but the block size is, then we'll
	// scale the set weight accordingly based on the max block size value.
	case cfg.BlockMaxSize != defaultBlockMaxSize &&
		cfg.BlockMaxWeight == defaultBlockMaxWeight:

		cfg.BlockMaxWeight = cfg.BlockMaxSize * blockchain.WitnessScaleFactor
	}

	// Look for illegal characters in the user agent comments.
	for _, uaComment := range cfg.UserAgentComments {
		if strings.ContainsAny(uaComment, "/:()") {
			err := fmt.Errorf("%s: The following characters must not "+
				"appear in user agent comments: '/', ':', '(', ')'",
				funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// --txindex and --droptxindex do not mix.
	if cfg.TxIndex && cfg.DropTxIndex {
		err := fmt.Errorf("%s: the --txindex and --droptxindex "+
			"options may  not be activated at the same time",
			funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	//	todo: (EthashPoW)
	if cfg.EthashVerifyByFullDAG {
		cfg.EthashConfig.VerifyByFullDAG = true
	}

	// Check mining addresses are valid and saved parsed versions.
	cfg.miningAddrs = make([]abeutil.AbelAddress, 0, len(cfg.MiningAddrs))
	for i, addrStr := range cfg.MiningAddrs {
		abelAddr, err := abeutil.DecodeAbelAddress(addrStr)
		if err != nil {
			err := fmt.Errorf("%d -th mining address failed to decode: %v", i, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
		if !abelAddr.IsForNet(activeNetParams.Params) {
			err := fmt.Errorf("%d -th mining address is on the wrong network", i)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
		cfg.miningAddrs = append(cfg.miningAddrs, abelAddr)
	}

	//	mining address
	// TODO(abe) This part should be re-thought.
	if cfg.Generate || cfg.ExternalGenerate {
		if len(cfg.MiningAddrs) == 0 {
			str := "%s: the generate/externalgenerate flag is set, but there are no mining " +
				"addresses specified "
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	} else {
		//	(EthashPoW)
		//	when CPU Ming is disabled, it is unnecessary to use FullDAG to verify the header's PoW
		cfg.EthashConfig.VerifyByFullDAG = false
	}

	//// Verify mining address
	//if cfg.miningAddrBytes != nil {
	//	if len(cfg.miningAddrBytes) < 33 {
	//		str := "%s: The length of mining address is incorrect"
	//		err := fmt.Errorf(str, funcName)
	//		fmt.Fprintln(os.Stderr, err)
	//		fmt.Fprintln(os.Stderr, usageMessage)
	//		return nil, nil, err
	//	}
	//
	//	// Check netID
	//	netID := cfg.miningAddrBytes[0]
	//	if netID != activeNetParams.PQRingCTID {
	//		str := "%s: The netID of mining address does not match the active net"
	//		err := fmt.Errorf(str, funcName)
	//		fmt.Fprintln(os.Stderr, err)
	//		fmt.Fprintln(os.Stderr, usageMessage)
	//		return nil, nil, err
	//	}
	//
	//	// Check verification hash
	//	verifyBytes := cfg.miningAddrBytes[:len(cfg.miningAddrBytes)-32]
	//	dstHash0 := cfg.miningAddrBytes[len(cfg.miningAddrBytes)-32:]
	//	dstHash, _ := chainhash.NewHash(dstHash0)
	//	realHash := chainhash.DoubleHashH(verifyBytes)
	//	if !dstHash.IsEqual(&realHash) {
	//		str := "%s: Mining address verification fails: verification hash does not match"
	//		err := fmt.Errorf(str, funcName)
	//		fmt.Fprintln(os.Stderr, err)
	//		fmt.Fprintln(os.Stderr, usageMessage)
	//		return nil, nil, err
	//	}
	//
	//	cfg.miningAddrBytes = verifyBytes[1:]
	//}

	// Add default port to all listener addresses if needed and remove
	// duplicate addresses.
	cfg.Listeners = normalizeAddresses(cfg.Listeners,
		activeNetParams.DefaultPort)

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners = normalizeAddresses(cfg.RPCListeners,
		activeNetParams.rpcPort)

	// Add default port to all getwork rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListenersGetWork = normalizeAddresses(cfg.RPCListenersGetWork,
		activeNetParams.rpcPortGetWork)

	// Only allow TLS to be disabled if the RPC is bound to localhost
	// addresses or is not mainnet.
	if activeNetParams.Net == wire.MainNet && !cfg.DisableRPC && cfg.DisableTLS {
		allowedTLSListeners := map[string]struct{}{
			"localhost": {},
			"127.0.0.1": {},
			"::1":       {},
		}
		for _, addr := range cfg.RPCListeners {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				str := "%s: RPC listen interface '%s' is " +
					"invalid: %v"
				err := fmt.Errorf(str, funcName, addr, err)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
			if _, ok := allowedTLSListeners[host]; !ok {
				str := "%s: the --notls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				err := fmt.Errorf(str, funcName, addr)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
		}
	}

	// Add default port to all added peer addresses if needed and remove
	// duplicate addresses.
	cfg.AddPeers = normalizeAddresses(cfg.AddPeers,
		activeNetParams.DefaultPort)
	cfg.ConnectPeers = normalizeAddresses(cfg.ConnectPeers,
		activeNetParams.DefaultPort)

	// --noonion and --onion do not mix.
	if cfg.NoOnion && cfg.OnionProxy != "" {
		err := fmt.Errorf("%s: the --noonion and --onion options may "+
			"not be activated at the same time", funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Check the checkpoints for syntax errors.
	cfg.addCheckpoints, err = parseCheckpoints(cfg.AddCheckpoints)
	if err != nil {
		str := "%s: Error parsing checkpoints: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	if activeNetParams.Net != wire.MainNet {
		// Check the checkpoints for syntax errors.
		cfg.addFakePowHeightScopes, err = parseFakePowHeightScopes(cfg.AddFakePoWHeightScopes)
		if err != nil {
			str := "%s: Error parsing fake pow height scope: %v"
			err := fmt.Errorf(str, funcName, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// Tor stream isolation requires either proxy or onion proxy to be set.
	if cfg.TorIsolation && cfg.Proxy == "" && cfg.OnionProxy == "" {
		str := "%s: Tor stream isolation requires either proxy or " +
			"onionproxy to be set"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Setup dial and DNS resolution (lookup) functions depending on the
	// specified options.  The default is to use the standard
	// net.DialTimeout function as well as the system DNS resolver.  When a
	// proxy is specified, the dial function is set to the proxy specific
	// dial function and the lookup is set to use tor (unless --noonion is
	// specified in which case the system DNS resolver is used).
	cfg.dial = net.DialTimeout
	cfg.lookup = net.LookupIP
	if cfg.Proxy != "" {
		_, _, err := net.SplitHostPort(cfg.Proxy)
		if err != nil {
			str := "%s: Proxy address '%s' is invalid: %v"
			err := fmt.Errorf(str, funcName, cfg.Proxy, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}

		// Tor isolation flag means proxy credentials will be overridden
		// unless there is also an onion proxy configured in which case
		// that one will be overridden.
		torIsolation := false
		if cfg.TorIsolation && cfg.OnionProxy == "" &&
			(cfg.ProxyUser != "" || cfg.ProxyPass != "") {

			torIsolation = true
			fmt.Fprintln(os.Stderr, "Tor isolation set -- "+
				"overriding specified proxy user credentials")
		}

		proxy := &socks.Proxy{
			Addr:         cfg.Proxy,
			Username:     cfg.ProxyUser,
			Password:     cfg.ProxyPass,
			TorIsolation: torIsolation,
		}
		cfg.dial = proxy.DialTimeout

		// Treat the proxy as tor and perform DNS resolution through it
		// unless the --noonion flag is set or there is an
		// onion-specific proxy configured.
		if !cfg.NoOnion && cfg.OnionProxy == "" {
			cfg.lookup = func(host string) ([]net.IP, error) {
				return connmgr.TorLookupIP(host, cfg.Proxy)
			}
		}
	}

	// Setup onion address dial function depending on the specified options.
	// The default is to use the same dial function selected above.  However,
	// when an onion-specific proxy is specified, the onion address dial
	// function is set to use the onion-specific proxy while leaving the
	// normal dial function as selected above.  This allows .onion address
	// traffic to be routed through a different proxy than normal traffic.
	if cfg.OnionProxy != "" {
		_, _, err := net.SplitHostPort(cfg.OnionProxy)
		if err != nil {
			str := "%s: Onion proxy address '%s' is invalid: %v"
			err := fmt.Errorf(str, funcName, cfg.OnionProxy, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}

		// Tor isolation flag means onion proxy credentials will be
		// overridden.
		if cfg.TorIsolation &&
			(cfg.OnionProxyUser != "" || cfg.OnionProxyPass != "") {
			fmt.Fprintln(os.Stderr, "Tor isolation set -- "+
				"overriding specified onionproxy user "+
				"credentials ")
		}

		cfg.oniondial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
			proxy := &socks.Proxy{
				Addr:         cfg.OnionProxy,
				Username:     cfg.OnionProxyUser,
				Password:     cfg.OnionProxyPass,
				TorIsolation: cfg.TorIsolation,
			}
			return proxy.DialTimeout(network, addr, timeout)
		}

		// When configured in bridge mode (both --onion and --proxy are
		// configured), it means that the proxy configured by --proxy is
		// not a tor proxy, so override the DNS resolution to use the
		// onion-specific proxy.
		if cfg.Proxy != "" {
			cfg.lookup = func(host string) ([]net.IP, error) {
				return connmgr.TorLookupIP(host, cfg.OnionProxy)
			}
		}
	} else {
		cfg.oniondial = cfg.dial
	}

	// Specifying --noonion means the onion address dial function results in
	// an error.
	if cfg.NoOnion {
		cfg.oniondial = func(a, b string, t time.Duration) (net.Conn, error) {
			return nil, errors.New("tor has been disabled")
		}
	}

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		abecLog.Warnf("%v", configFileError)
	}

	return &cfg, remainingArgs, nil
}

// createDefaultConfig copies the file sample-abec.conf to the given destination path,
// and populates it with some randomly generated RPC username and password.
func createDefaultConfigFile(destinationPath string) error {
	// Create the destination directory if it does not exists
	err := os.MkdirAll(filepath.Dir(destinationPath), 0700)
	if err != nil {
		return err
	}

	// We assume sample config file path is same as binary
	path, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	sampleConfigPath := filepath.Join(path, sampleConfigFilename)

	// We generate a random user and password
	randomBytes := make([]byte, 20)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return err
	}
	generatedRPCUser := base64.StdEncoding.EncodeToString(randomBytes)

	_, err = rand.Read(randomBytes)
	if err != nil {
		return err
	}
	generatedRPCPass := base64.StdEncoding.EncodeToString(randomBytes)

	src, err := os.Open(sampleConfigPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dest, err := os.OpenFile(destinationPath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer dest.Close()

	// We copy every line from the sample config file to the destination,
	// only replacing the two lines for rpcuser and rpcpass
	reader := bufio.NewReader(src)
	for err != io.EOF {
		var line string
		line, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}

		if strings.Contains(line, "rpcuser=") {
			line = "rpcuser=" + generatedRPCUser + "\n"
		} else if strings.Contains(line, "rpcpass=") {
			line = "rpcpass=" + generatedRPCPass + "\n"
		}

		if _, err := dest.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}

// abecDial connects to the address on the named network using the appropriate
// dial function depending on the address and configuration options.  For
// example, .onion addresses will be dialed using the onion specific proxy if
// one was specified, but will otherwise use the normal dial function (which
// could itself use a proxy or not).
func abecDial(addr net.Addr) (net.Conn, error) {
	if strings.Contains(addr.String(), ".onion:") {
		return cfg.oniondial(addr.Network(), addr.String(),
			defaultConnectTimeout)
	}
	return cfg.dial(addr.Network(), addr.String(), defaultConnectTimeout)
}

// abecLookup resolves the IP of the given host using the correct DNS lookup
// function depending on the configuration options.  For example, addresses will
// be resolved using tor when the --proxy flag was specified unless --noonion
// was also specified in which case the normal system DNS resolver will be used.
//
// Any attempt to resolve a tor address (.onion) will return an error since they
// are not intended to be resolved outside of the tor proxy.
func abecLookup(host string) ([]net.IP, error) {
	if strings.HasSuffix(host, ".onion") {
		return nil, fmt.Errorf("attempt to resolve tor address %s", host)
	}

	return cfg.lookup(host)
}
