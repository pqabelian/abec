package txscript

import (
	"github.com/abesuite/abec/chainhash"
	"sync"
)

// WitnessCache implements a transaction witness verification cache with a randomized
// entry eviction policy. Only valid transactions will be added to the cache.
// It can speed up the validation of transactions within a block,
// if they've already been seen and verified within the mempool.
type WitnessCache struct {
	sync.RWMutex
	validTransactions map[chainhash.Hash]struct{}
	maxEntries        uint
}

// NewWitnessCache creates and initializes a new instance of WitnessCache.
// Parameter 'maxEntries' represents the maximum number of entries allowed to
// exist in the WitnessCache at any particular moment. Random entries are evicted
// to make room for new entries that would cause the number of entries in the
// cache to exceed the max.
func NewWitnessCache(maxEntries uint) *WitnessCache {
	return &WitnessCache{
		validTransactions: make(map[chainhash.Hash]struct{}, maxEntries),
		maxEntries:        maxEntries,
	}
}

// Exists returns true if a transaction is found within the WitnessCache.
// Otherwise, false is returned.
//
// NOTE: This function is safe for concurrent access. Readers won't be blocked
// unless there exists a writer, adding an entry to the WitnessCache.
func (s *WitnessCache) Exists(txHash chainhash.Hash) bool {
	s.RLock()
	_, ok := s.validTransactions[txHash]
	s.RUnlock()

	return ok
}

// Add adds a transaction to the witness cache. In the event that
// the WitnessCache is full, an existing entry is randomly chosen to be
// evicted in order to make space for the new one.
//
// NOTE: This function is safe for concurrent access. Writers will block
// simultaneous readers until function execution has concluded.
func (s *WitnessCache) Add(txHash chainhash.Hash) {
	s.Lock()
	defer s.Unlock()

	if s.maxEntries <= 0 {
		return
	}

	// If adding this new entry will put us over the max number of allowed
	// entries, then evict an entry.
	if uint(len(s.validTransactions)+1) > s.maxEntries {
		// Remove a random entry from the map.
		for witnessEntry := range s.validTransactions {
			delete(s.validTransactions, witnessEntry)
			break
		}
	}
	s.validTransactions[txHash] = struct{}{}
}
