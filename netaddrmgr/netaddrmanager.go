package netaddrmgr

import (
	"container/list"
	crand "crypto/rand" // for seeding
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// NetAddrManager provides a concurrency safe address manager for caching potential
// peers on the network.
type NetAddrManager struct {
	mtx               sync.Mutex
	peersFile         string // store the peers to quicker build connection when the btcd restart
	lookupFunc        func(string) ([]net.IP, error)
	rand              *rand.Rand
	key               [32]byte
	netAddrIndex      map[string]*KnownNetAddress // address key to ka for all netaddrs.
	netAddrNew        [newBucketCount]map[string]*KnownNetAddress
	netAddrTried      [triedBucketCount]*list.List
	started           int32
	shutdown          int32
	wg                sync.WaitGroup
	quit              chan struct{}
	nTried            int
	nNew              int
	lamtx             sync.Mutex
	localNetAddresses map[string]*localNetAddress
	version           int
}

type serializedKnownNetAddress struct {
	NetAddr     string
	Src         string
	Attempts    int
	TimeStamp   int64
	LastAttempt int64
	LastSuccess int64
	Services    wire.ServiceFlag
	SrcServices wire.ServiceFlag
	// no refcount or tried, that is available from context.
}

type serializedNetAddrManager struct {
	Version      int
	Key          [32]byte
	NetAddresses []*serializedKnownNetAddress
	NewBuckets   [newBucketCount][]string // string is NetAddressKey
	TriedBuckets [triedBucketCount][]string
}

type localNetAddress struct {
	na    *wire.NetAddress
	score NetAddressPriority
}

// NetAddressPriority type is used to describe the hierarchy of local net address
// discovery methods.
type NetAddressPriority int

const (
	// InterfacePrio signifies the address is on a local interface
	InterfacePrio NetAddressPriority = iota

	// BoundPrio signifies the address has been explicitly bounded to.
	BoundPrio

	// UpnpPrio signifies the address was obtained from UPnP.
	UpnpPrio

	// HTTPPrio signifies the address was obtained from an external HTTP service.
	HTTPPrio

	// ManualPrio signifies the address was provided by --externalip.
	ManualPrio
)

const (
	// needNetAddressThreshold is the number of addresses under which the
	// netaddress manager will claim to need more addresses.
	needNetAddressThreshold = 1000

	// dumpNetAddressInterval is the interval used to dump the address
	// cache to disk for future use.
	dumpNetAddressInterval = time.Minute * 10

	// triedBucketSize is the maximum number of addresses in each
	// tried address bucket.
	triedBucketSize = 256

	// triedBucketCount is the number of buckets we split tried
	// addresses over.
	triedBucketCount = 64

	// newBucketSize is the maximum number of addresses in each new address
	// bucket.
	newBucketSize = 64

	// newBucketCount is the number of buckets that we spread new addresses
	// over.
	newBucketCount = 1024

	// triedBucketsPerGroup is the number of tried buckets over which an
	// address group will be spread.
	triedBucketsPerGroup = 8

	// newBucketsPerGroup is the number of new buckets over which an
	// source address group will be spread.
	newBucketsPerGroup = 64

	// newBucketsPerAddress is the number of buckets a frequently seen new
	// address may end up in.
	newBucketsPerAddress = 8

	// numMissingDays is the number of days before which we assume an
	// address has vanished if we have not seen it announced  in that long.
	numMissingDays = 30

	// numRetries is the number of tried without a single success before
	// we assume an address is bad.
	numRetries = 3

	// maxFailures is the maximum number of failures we will accept without
	// a success before considering an address bad.
	maxFailures = 10

	// minBadDays is the number of days since the last success before we
	// will consider evicting an address.
	minBadDays = 7

	// getAddrMax is the most addresses that we will send in response
	// to a getAddr (in practise the most addresses we will return from a
	// call to AddressCache()).
	getNetAddrMax = 2500

	// getAddrPercent is the percentage of total addresses known that we
	// will share with a call to AddressCache.
	getNetAddrPercent = 23

	// serialisationVersion is the current version of the on-disk format.
	serialisationVersion = 2
)

// updateNetAddress is a helper function to either update an address already known
// to the net address manager, or to add the net address if not already known.
func (namgr *NetAddrManager) updateNetAddress(netAddr, srcNetAddr *wire.NetAddress) {
	// Filter out non-routable addresses. Note that non-routable
	// also includes invalid and local addresses.
	if !IsRoutable(netAddr) {
		return
	}

	addr := NetAddressKey(netAddr)
	kna := namgr.find(netAddr)
	if kna != nil {
		// TODO: only update addresses periodically.
		// Update the last seen time and services.
		// note that to prevent causing excess garbage on getaddr
		// messages the netaddresses in addrmaanger are *immutable*,
		// if we need to change them then we replace the pointer with a
		// new copy so that we don't have to copy every na for getaddr.
		if netAddr.Timestamp.After(kna.na.Timestamp) ||
			(kna.na.Services&netAddr.Services) !=
				netAddr.Services {

			naCopy := *kna.na
			naCopy.Timestamp = netAddr.Timestamp
			naCopy.AddService(netAddr.Services)
			kna.na = &naCopy
		}

		// If already in tried, we have nothing to do here.
		if kna.tried {
			return
		}

		// Already at our max?
		if kna.refs == newBucketsPerAddress {
			return
		}

		// The more entries we have, the less likely we are to add more.
		// likelihood is 2N.
		factor := int32(2 * kna.refs)
		if namgr.rand.Int31n(factor) != 0 {
			return
		}
	} else {
		// Make a copy of the net address to avoid races since it is
		// updated elsewhere in the addrmanager code and would otherwise
		// change the actual netaddress on the peer.
		netAddrCopy := *netAddr
		kna = &KnownNetAddress{na: &netAddrCopy, srcNetAddr: srcNetAddr}
		namgr.netAddrIndex[addr] = kna
		namgr.nNew++
		// XXX time penalty?
	}

	bucket := namgr.getNewBucket(netAddr, srcNetAddr)

	// Already exists?
	if _, ok := namgr.netAddrNew[bucket][addr]; ok {
		return
	}

	// Enforce max addresses.
	if len(namgr.netAddrNew[bucket]) > newBucketSize {
		log.Tracef("new bucket is full, expiring old")
		namgr.expireNew(bucket)
	}

	// Add to new bucket.
	kna.refs++
	namgr.netAddrNew[bucket][addr] = kna

	log.Tracef("Added new netaddress %s for a total of %d netaddresses", addr,
		namgr.nTried+namgr.nNew)
}

// expireNew makes space in the new buckets by expiring the really bad entries.
// If no bad entries are available we look at a few and remove the oldest.
func (namgr *NetAddrManager) expireNew(bucket int) {
	// First see if there are any entries that are so bad we can just throw
	// them away. otherwise we throw away the oldest entry in the cache.
	// Bitcoind here chooses four random and just throws the oldest of
	// those away, but we keep track of oldest in the initial traversal and
	// use that information instead.
	var oldest *KnownNetAddress
	for k, v := range namgr.netAddrNew[bucket] {
		if v.isBad() {
			log.Tracef("expiring bad address %v", k)
			delete(namgr.netAddrNew[bucket], k)
			v.refs--
			if v.refs == 0 {
				namgr.nNew--
				delete(namgr.netAddrIndex, k)
			}
			continue
		}
		if oldest == nil {
			oldest = v
		} else if !v.na.Timestamp.After(oldest.na.Timestamp) {
			oldest = v
		}
	}

	if oldest != nil {
		key := NetAddressKey(oldest.na)
		log.Tracef("expiring oldest address %v", key)

		delete(namgr.netAddrNew[bucket], key)
		oldest.refs--
		if oldest.refs == 0 {
			namgr.nNew--
			delete(namgr.netAddrIndex, key)
		}
	}
}

// pickTried selects an address from the tried bucket to be evicted.
// We just choose the eldest. Bitcoind selects 4 random entries and throws away
// the older of them.
func (namgr *NetAddrManager) pickTried(bucket int) *list.Element {
	var oldest *KnownNetAddress
	var oldestElem *list.Element
	for e := namgr.netAddrTried[bucket].Front(); e != nil; e = e.Next() {
		kna := e.Value.(*KnownNetAddress)
		if oldest == nil || oldest.na.Timestamp.After(kna.na.Timestamp) {
			oldestElem = e
			oldest = kna
		}

	}
	return oldestElem
}

func (namgr *NetAddrManager) getNewBucket(netAddr, srcAddr *wire.NetAddress) int {
	// bitcoind:
	// doublesha256(key + sourcegroup + int64(doublesha256(key + group + sourcegroup))%bucket_per_source_group) % num_new_buckets

	data1 := []byte{}
	data1 = append(data1, namgr.key[:]...)
	data1 = append(data1, []byte(GroupKey(netAddr))...)
	data1 = append(data1, []byte(GroupKey(srcAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= newBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, namgr.key[:]...)
	data2 = append(data2, GroupKey(srcAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % newBucketCount)
}

func (namgr *NetAddrManager) getTriedBucket(netAddr *wire.NetAddress) int {
	// bitcoind hashes this as:
	// doublesha256(key + group + truncate_to_64bits(doublesha256(key)) % buckets_per_group) % num_buckets
	data1 := []byte{}
	data1 = append(data1, namgr.key[:]...)
	data1 = append(data1, []byte(NetAddressKey(netAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= triedBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, namgr.key[:]...)
	data2 = append(data2, GroupKey(netAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % triedBucketCount)
}

// netAddressHandler is the main handler for the address manager.  It must be run
// as a goroutine.
func (namgr *NetAddrManager) netAddressHandler() {
	dumpAddressTicker := time.NewTicker(dumpNetAddressInterval)
	defer dumpAddressTicker.Stop()
out:
	for {
		select {
		case <-dumpAddressTicker.C:
			namgr.savePeers()

		case <-namgr.quit:
			break out
		}
	}
	namgr.savePeers()
	namgr.wg.Done()
	log.Trace("Address handler done")
}

// savePeers saves all the known addresses to a file so they can be read back
// in at next run.
func (namgr *NetAddrManager) savePeers() {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	// First we make a serialisable datastructure so we can encode it to
	// json.
	snam := new(serializedNetAddrManager)
	snam.Version = namgr.version
	copy(snam.Key[:], namgr.key[:])

	snam.NetAddresses = make([]*serializedKnownNetAddress, len(namgr.netAddrIndex))
	i := 0
	for k, v := range namgr.netAddrIndex {
		skna := new(serializedKnownNetAddress)
		skna.NetAddr = k
		skna.TimeStamp = v.na.Timestamp.Unix()
		skna.Src = NetAddressKey(v.srcNetAddr)
		skna.Attempts = v.attempts
		skna.LastAttempt = v.lastattempt.Unix()
		skna.LastSuccess = v.lastsuccess.Unix()
		if namgr.version > 1 {
			skna.Services = v.na.Services
			skna.SrcServices = v.srcNetAddr.Services
		}
		// Tried and refs are implicit in the rest of the structure
		// and will be worked out from context on unserialisation.
		snam.NetAddresses[i] = skna
		i++
	}
	for i := range namgr.netAddrNew {
		snam.NewBuckets[i] = make([]string, len(namgr.netAddrNew[i]))
		j := 0
		for k := range namgr.netAddrNew[i] {
			snam.NewBuckets[i][j] = k
			j++
		}
	}
	for i := range namgr.netAddrTried {
		snam.TriedBuckets[i] = make([]string, namgr.netAddrTried[i].Len())
		j := 0
		for e := namgr.netAddrTried[i].Front(); e != nil; e = e.Next() {
			kna := e.Value.(*KnownNetAddress)
			snam.TriedBuckets[i][j] = NetAddressKey(kna.na)
			j++
		}
	}

	w, err := os.Create(namgr.peersFile)
	if err != nil {
		log.Errorf("Error opening file %s: %v", namgr.peersFile, err)
		return
	}
	enc := json.NewEncoder(w)
	defer w.Close()
	if err := enc.Encode(&snam); err != nil {
		log.Errorf("Failed to encode file %s: %v", namgr.peersFile, err)
		return
	}
}

// loadPeers loads the known address from the saved file.  If empty, missing, or
// malformed file, just don't load anything and start fresh
func (namgr *NetAddrManager) loadPeers() {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	err := namgr.deserializePeers(namgr.peersFile)
	if err != nil {
		log.Errorf("Failed to parse file %s: %v", namgr.peersFile, err)
		// if it is invalid we nuke the old one unconditionally.
		err = os.Remove(namgr.peersFile)
		if err != nil {
			log.Warnf("Failed to remove corrupt peers file %s: %v",
				namgr.peersFile, err)
		}
		namgr.reset()
		return
	}
	log.Infof("Loaded %d addresses from file '%s'", namgr.numNetAddresses(), namgr.peersFile)
}

func (namgr *NetAddrManager) deserializePeers(filePath string) error {

	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	r, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("%s error opening file: %v", filePath, err)
	}
	defer r.Close()

	// deserialize the perr.json to snam
	var snam serializedNetAddrManager
	dec := json.NewDecoder(r)
	err = dec.Decode(&snam)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filePath, err)
	}

	// Since decoding JSON is backwards compatible (i.e., only decodes
	// fields it understands), we'll only return an error upon seeing a
	// version past our latest supported version.
	if snam.Version > serialisationVersion {
		return fmt.Errorf("unknown version %v in serialized "+
			"addrmanager", snam.Version)
	}

	copy(namgr.key[:], snam.Key[:])

	// assign values to netAddrIndex
	for _, v := range snam.NetAddresses {
		kna := new(KnownNetAddress)

		// The first version of the serialized address manager was not
		// aware of the service bits associated with this address, so
		// we'll assign a default of SFNodeNetwork to it.
		if snam.Version == 1 {
			v.Services = wire.SFNodeNetwork
		}
		kna.na, err = namgr.DeserializeNetAddress(v.NetAddr, v.Services)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.NetAddr, err)
		}

		// The first version of the serialized address manager was not
		// aware of the service bits associated with the source address,
		// so we'll assign a default of SFNodeNetwork to it.
		if snam.Version == 1 {
			v.SrcServices = wire.SFNodeNetwork
		}
		kna.srcNetAddr, err = namgr.DeserializeNetAddress(v.Src, v.SrcServices)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Src, err)
		}

		kna.attempts = v.Attempts
		kna.lastattempt = time.Unix(v.LastAttempt, 0)
		kna.lastsuccess = time.Unix(v.LastSuccess, 0)
		namgr.netAddrIndex[NetAddressKey(kna.na)] = kna
	}

	// assign values to netAddrNew
	for i := range snam.NewBuckets {
		for _, val := range snam.NewBuckets[i] {
			ka, ok := namgr.netAddrIndex[val]
			if !ok {
				return fmt.Errorf("newbucket contains %s but "+
					"none in address list", val)
			}

			if ka.refs == 0 {
				namgr.nNew++
			}
			ka.refs++
			namgr.netAddrNew[i][val] = ka
		}
	}

	// assign values to netAddrTried
	for i := range snam.TriedBuckets {
		for _, val := range snam.TriedBuckets[i] {
			ka, ok := namgr.netAddrIndex[val]
			if !ok {
				return fmt.Errorf("Newbucket contains %s but "+
					"none in address list", val)
			}

			ka.tried = true
			namgr.nTried++
			namgr.netAddrTried[i].PushBack(ka)
		}
	}

	// Sanity checking.
	for k, v := range namgr.netAddrIndex {
		if v.refs == 0 && !v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"with no references", k)
		}

		if v.refs > 0 && v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"which is both new and tried!", k)
		}
	}

	return nil
}

// DeserializeNetAddress converts a given address string to a *wire.NetAddress.
func (namgr *NetAddrManager) DeserializeNetAddress(addr string,
	services wire.ServiceFlag) (*wire.NetAddress, error) {

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	return namgr.HostToNetAddress(host, uint16(port), services)
}

// Start begins the core address handler which manages a pool of known
// addresses, timeouts, and interval based writes.
func (namgr *NetAddrManager) Start() {
	// Already started?
	if atomic.AddInt32(&namgr.started, 1) != 1 {
		return
	}

	log.Trace("Starting address manager")

	// Load peers we already know about from file.
	namgr.loadPeers()

	// Start the address ticker to save addresses periodically.
	namgr.wg.Add(1)
	go namgr.netAddressHandler()
}

// Stop gracefully shuts down the address manager by stopping the main handler.
func (namgr *NetAddrManager) Stop() error {
	if atomic.AddInt32(&namgr.shutdown, 1) != 1 {
		log.Warnf("Address manager is already in the process of " +
			"shutting down")
		return nil
	}

	log.Infof("Address manager shutting down")
	close(namgr.quit)
	namgr.wg.Wait()
	return nil
}

// AddAddresses adds new addresses to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
func (namgr *NetAddrManager) AddAddresses(netAddrs []*wire.NetAddress, srcNetAddr *wire.NetAddress) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	for _, na := range netAddrs {
		namgr.updateNetAddress(na, srcNetAddr)
	}
}

// AddAddress adds a new address to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
func (namgr *NetAddrManager) AddNetAddress(netAddr, srcNetAddr *wire.NetAddress) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	namgr.updateNetAddress(netAddr, srcNetAddr)
}

// AddNetAddressByIP adds an address where we are given an ip:port and not a
// wire.NetAddress.
func (namgr *NetAddrManager) AddNetAddressByIP(addrIP string) error {
	// Split IP and port
	netAddr, portStr, err := net.SplitHostPort(addrIP)
	if err != nil {
		return err
	}
	// Put it in wire.Netaddress
	ip := net.ParseIP(netAddr)
	if ip == nil {
		return fmt.Errorf("invalid ip address %s", netAddr)
	}
	port, err := strconv.ParseUint(portStr, 10, 0)
	if err != nil {
		return fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), 0)
	namgr.AddNetAddress(na, na) // XXX use correct src address
	return nil
}

// NumAddresses returns the number of addresses known to the address manager.
func (namgr *NetAddrManager) numNetAddresses() int {
	return namgr.nTried + namgr.nNew
}

// NumAddresses returns the number of addresses known to the address manager.
func (namgr *NetAddrManager) NumNetAddresses() int {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	return namgr.numNetAddresses()
}

// NeedMoreNetAddresses returns whether or not the address manager needs more
// addresses.
func (namgr *NetAddrManager) NeedMoreNetAddresses() bool {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	return namgr.numNetAddresses() < needNetAddressThreshold
}

// NetAddressCache returns the current address cache.  It must be treated as
// read-only (but since it is a copy now, this is not as dangerous).
func (namgr *NetAddrManager) NetAddressCache() []*wire.NetAddress {
	allNetAddr := namgr.getNetAddresses()

	numNetAddresses := len(allNetAddr) * getNetAddrPercent / 100
	if numNetAddresses > getNetAddrMax {
		numNetAddresses = getNetAddrMax
	}

	// Fisher-Yates shuffle the array. We only need to do the first
	// `numAddresses' since we are throwing the rest.
	for i := 0; i < numNetAddresses; i++ {
		// pick a number between current index and the end
		j := rand.Intn(len(allNetAddr)-i) + i
		allNetAddr[i], allNetAddr[j] = allNetAddr[j], allNetAddr[i]
	}

	// slice off the limit we are willing to share.
	return allNetAddr[0:numNetAddresses]
}

// getNetAddresses returns all of the net addresses currently found within the
// manager's address cache.
func (namgr *NetAddrManager) getNetAddresses() []*wire.NetAddress {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	addrIndexLen := len(namgr.netAddrIndex)
	if addrIndexLen == 0 {
		return nil
	}

	netAddrs := make([]*wire.NetAddress, 0, addrIndexLen)
	for _, v := range namgr.netAddrIndex {
		netAddrs = append(netAddrs, v.na)
	}

	return netAddrs
}

// reset resets the net address manager by reinitialising the random source
// and allocating fresh empty bucket storage.
func (namgr *NetAddrManager) reset() {

	namgr.netAddrIndex = make(map[string]*KnownNetAddress)

	// fill key with bytes from a good random source.
	io.ReadFull(crand.Reader, namgr.key[:])
	for i := range namgr.netAddrNew {
		namgr.netAddrNew[i] = make(map[string]*KnownNetAddress)
	}
	for i := range namgr.netAddrTried {
		namgr.netAddrTried[i] = list.New()
	}
}

// HostToNetAddress returns a netaddress given a host address.  If the address
// is a Tor .onion address this will be taken care of.  Else if the host is
// not an IP address it will be resolved (via Tor if required).
func (namgr *NetAddrManager) HostToNetAddress(host string, port uint16, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// Tor address is 16 char base32 + ".onion"
	var ip net.IP
	if len(host) == 22 && host[16:] == ".onion" {
		// go base32 encoding uses capitals (as does the rfc
		// but Tor and bitcoind tend to user lowercase, so we switch
		// case here.
		data, err := base32.StdEncoding.DecodeString(
			strings.ToUpper(host[:16]))
		if err != nil {
			return nil, err
		}
		prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
		ip = net.IP(append(prefix, data...))
	} else if ip = net.ParseIP(host); ip == nil {
		ips, err := namgr.lookupFunc(host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		ip = ips[0]
	}

	return wire.NewNetAddressIPPort(ip, port, services), nil
}

// ipString returns a string for the ip from the provided NetAddress. If the
// ip is in the range used for Tor addresses then it will be transformed into
// the relevant .onion address.
func ipString(na *wire.NetAddress) string {
	if IsOnionCatTor(na) {
		// We know now that na.IP is long enough.
		base32 := base32.StdEncoding.EncodeToString(na.IP[6:])
		return strings.ToLower(base32) + ".onion"
	}

	return na.IP.String()
}

// NetAddressKey returns a string key in the form of ip:port for IPv4 addresses
// or [ip]:port for IPv6 addresses.
func NetAddressKey(na *wire.NetAddress) string {
	port := strconv.FormatUint(uint64(na.Port), 10)

	return net.JoinHostPort(ipString(na), port)
}

// GetNetAddress returns a single address that should be routable.  It picks a
// random one from the possible addresses with preference given to ones that
// have not been used recently and should not pick 'close' addresses
// consecutively.
func (namgr *NetAddrManager) GetNetAddress() *KnownNetAddress {
	// Protect concurrent access.
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	if namgr.numNetAddresses() == 0 {
		return nil
	}

	// Use a 50% chance for choosing between tried and new table entries.
	if namgr.nTried > 0 && (namgr.nNew == 0 || namgr.rand.Intn(2) == 0) {
		// Tried entry.
		large := 1 << 30
		factor := 1.0
		for {
			// pick a random bucket.
			bucket := namgr.rand.Intn(len(namgr.netAddrTried))
			if namgr.netAddrTried[bucket].Len() == 0 {
				continue
			}

			// Pick a random entry in the list
			e := namgr.netAddrTried[bucket].Front()
			for i :=
				namgr.rand.Int63n(int64(namgr.netAddrTried[bucket].Len())); i > 0; i-- {
				e = e.Next()
			}
			ka := e.Value.(*KnownNetAddress)
			randval := namgr.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from tried bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	} else {
		// new node.
		// XXX use a closure/function to avoid repeating this.
		large := 1 << 30
		factor := 1.0
		for {
			// Pick a random bucket.
			bucket := namgr.rand.Intn(len(namgr.netAddrNew))
			if len(namgr.netAddrNew[bucket]) == 0 {
				continue
			}
			// Then, a random entry in it.
			var kna *KnownNetAddress
			nth := namgr.rand.Intn(len(namgr.netAddrNew[bucket]))
			for _, value := range namgr.netAddrNew[bucket] {
				if nth == 0 {
					kna = value
				}
				nth--
			}
			randval := namgr.rand.Intn(large)
			if float64(randval) < (factor * kna.chance() * float64(large)) {
				log.Tracef("Selected %v from new bucket",
					NetAddressKey(kna.na))
				return kna
			}
			factor *= 1.2
		}
	}
}

func (namgr *NetAddrManager) find(netAddr *wire.NetAddress) *KnownNetAddress {
	return namgr.netAddrIndex[NetAddressKey(netAddr)]
}

// Attempt increases the given address' attempt counter and updates
// the last attempt time.
func (namgr *NetAddrManager) Attempt(addr *wire.NetAddress) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	// find address.
	// Surely address will be in tried by now?
	kna := namgr.find(addr)
	if kna == nil {
		return
	}
	// set last tried time to now
	kna.attempts++
	kna.lastattempt = time.Now()
}

// Connected Marks the given address as currently connected and working at the
// current time.  The address must already be known to AddrManager else it will
// be ignored.
func (namgr *NetAddrManager) Connected(netAddr *wire.NetAddress) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	kna := namgr.find(netAddr)
	if kna == nil {
		return
	}

	// Update the time as long as it has been 20 minutes since last we did
	// so.
	now := time.Now()
	if now.After(kna.na.Timestamp.Add(time.Minute * 20)) {
		// ka.na is immutable, so replace it.
		naCopy := *kna.na
		naCopy.Timestamp = time.Now()
		kna.na = &naCopy
	}
}

// Good marks the given address as good.  To be called after a successful
// connection and version exchange.  If the address is unknown to the address
// manager it will be ignored.
func (namgr *NetAddrManager) Good(addr *wire.NetAddress) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	ka := namgr.find(addr)
	if ka == nil {
		return
	}

	// ka.Timestamp is not updated here to avoid leaking information
	// about currently connected peers.
	now := time.Now()
	ka.lastsuccess = now
	ka.lastattempt = now
	ka.attempts = 0

	// move to tried set, optionally evicting other addresses if neeed.
	if ka.tried {
		return
	}

	// ok, need to move it to tried.

	// remove from all new buckets.
	// record one of the buckets in question and call it the `first'
	addrKey := NetAddressKey(addr)
	oldBucket := -1
	for i := range namgr.netAddrNew {
		// we check for existence so we can record the first one
		if _, ok := namgr.netAddrNew[i][addrKey]; ok {
			delete(namgr.netAddrNew[i], addrKey)
			ka.refs--
			if oldBucket == -1 {
				oldBucket = i
			}
		}
	}
	namgr.nNew--

	if oldBucket == -1 {
		// What? wasn't in a bucket after all.... Panic?
		return
	}

	bucket := namgr.getTriedBucket(ka.na)

	// Room in this tried bucket?
	if namgr.netAddrTried[bucket].Len() < triedBucketSize {
		ka.tried = true
		namgr.netAddrTried[bucket].PushBack(ka)
		namgr.nTried++
		return
	}

	// No room, we have to evict something else.
	entry := namgr.pickTried(bucket)
	rmkna := entry.Value.(*KnownNetAddress)

	// First bucket it would have been put in.
	newBucket := namgr.getNewBucket(rmkna.na, rmkna.srcNetAddr)

	// If no room in the original bucket, we put it in a bucket we just
	// freed up a space in.
	if len(namgr.netAddrNew[newBucket]) >= newBucketSize {
		newBucket = oldBucket
	}

	// replace with ka in list.
	ka.tried = true
	entry.Value = ka

	rmkna.tried = false
	rmkna.refs++

	// We don't touch a.nTried here since the number of tried stays the same
	// but we decemented new above, raise it again since we're putting
	// something back.
	namgr.nNew++

	rmkey := NetAddressKey(rmkna.na)
	log.Tracef("Replacing %s with %s in tried", rmkey, addrKey)

	// We made sure there is space here just above.
	namgr.netAddrNew[newBucket][rmkey] = rmkna
}

// SetServices sets the services for the given address to the provided value.
func (namgr *NetAddrManager) SetServices(netAddr *wire.NetAddress, services wire.ServiceFlag) {
	namgr.mtx.Lock()
	defer namgr.mtx.Unlock()

	kna := namgr.find(netAddr)
	if kna == nil {
		return
	}

	// Update the services if needed.
	if kna.na.Services != services {
		// ka.na is immutable, so replace it.
		naCopy := *kna.na
		naCopy.Services = services
		kna.na = &naCopy
	}
}

// AddLocalAddress adds na to the list of known local addresses to advertise
// with the given priority.
func (namgr *NetAddrManager) AddLocalNetAddress(na *wire.NetAddress, priority NetAddressPriority) error {
	if !IsRoutable(na) {
		return fmt.Errorf("address %s is not routable", na.IP)
	}

	namgr.lamtx.Lock()
	defer namgr.lamtx.Unlock()

	key := NetAddressKey(na)
	lna, ok := namgr.localNetAddresses[key]
	if !ok || lna.score < priority {
		if ok {
			lna.score = priority + 1
		} else {
			namgr.localNetAddresses[key] = &localNetAddress{
				na:    na,
				score: priority,
			}
		}
	}
	return nil
}

// getReachabilityFrom returns the relative reachability of the provided local
// address to the provided remote address.
func getReachabilityFrom(localNetAddr, remoteNetAddr *wire.NetAddress) int {
	const (
		Unreachable = 0
		Default     = iota
		Teredo
		Ipv6Weak
		Ipv4
		Ipv6Strong
		Private
	)

	if !IsRoutable(remoteNetAddr) {
		return Unreachable
	}

	if IsOnionCatTor(remoteNetAddr) {
		if IsOnionCatTor(localNetAddr) {
			return Private
		}

		if IsRoutable(localNetAddr) && IsIPv4(localNetAddr) {
			return Ipv4
		}

		return Default
	}

	if IsRFC4380(remoteNetAddr) {
		if !IsRoutable(localNetAddr) {
			return Default
		}

		if IsRFC4380(localNetAddr) {
			return Teredo
		}

		if IsIPv4(localNetAddr) {
			return Ipv4
		}

		return Ipv6Weak
	}

	if IsIPv4(remoteNetAddr) {
		if IsRoutable(localNetAddr) && IsIPv4(localNetAddr) {
			return Ipv4
		}
		return Unreachable
	}

	/* ipv6 */
	var tunnelled bool
	// Is our v6 is tunnelled?
	if IsRFC3964(localNetAddr) || IsRFC6052(localNetAddr) || IsRFC6145(localNetAddr) {
		tunnelled = true
	}

	if !IsRoutable(localNetAddr) {
		return Default
	}

	if IsRFC4380(localNetAddr) {
		return Teredo
	}

	if IsIPv4(localNetAddr) {
		return Ipv4
	}

	if tunnelled {
		// only prioritise ipv6 if we aren't tunnelling it.
		return Ipv6Weak
	}

	return Ipv6Strong
}

// GetBestLocalNetAddress returns the most appropriate local address to use
// for the given remote address.
func (namgr *NetAddrManager) GetBestLocalAddress(remoteAddr *wire.NetAddress) *wire.NetAddress {
	namgr.lamtx.Lock()
	defer namgr.lamtx.Unlock()

	bestreach := 0
	var bestscore NetAddressPriority
	var bestAddress *wire.NetAddress
	for _, lna := range namgr.localNetAddresses {
		reach := getReachabilityFrom(lna.na, remoteAddr)
		if reach > bestreach ||
			(reach == bestreach && lna.score > bestscore) {
			bestreach = reach
			bestscore = lna.score
			bestAddress = lna.na
		}
	}
	if bestAddress != nil {
		log.Debugf("Suggesting address %s:%d for %s:%d", bestAddress.IP,
			bestAddress.Port, remoteAddr.IP, remoteAddr.Port)
	} else {
		log.Debugf("No worthy address for %s:%d", remoteAddr.IP,
			remoteAddr.Port)

		// Send something unroutable if nothing suitable.
		var ip net.IP
		if !IsIPv4(remoteAddr) && !IsOnionCatTor(remoteAddr) {
			ip = net.IPv6zero
		} else {
			ip = net.IPv4zero
		}
		// TODO(ABE): ABE does not support filter.
		//services := wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeBloom
		services := wire.SFNodeNetwork | wire.SFNodeWitness
		bestAddress = wire.NewNetAddressIPPort(ip, 0, services)
	}

	return bestAddress
}

// New returns a new abec address manager.
// Use Start to begin processing asynchronous address updates.
func New(dataDir string, lookupFunc func(string) ([]net.IP, error)) *NetAddrManager {
	namgr := NetAddrManager{
		peersFile:         filepath.Join(dataDir, "peers.json"),
		lookupFunc:        lookupFunc,
		rand:              rand.New(rand.NewSource(time.Now().UnixNano())),
		quit:              make(chan struct{}),
		localNetAddresses: make(map[string]*localNetAddress),
		version:           serialisationVersion,
	}
	namgr.reset()
	return &namgr
}
