package wire

import (
	"errors"
	"sync"
)

// ErrPayloadLimit is local congestion, not malformed input or peer misconduct.
var ErrPayloadLimit = errors.New("P2P payload capacity exhausted")

// MaxQueuedPayload bounds lightweight queued requests and announcements. It is
// included in reserved headroom alongside one maximum supplemental response.
const MaxQueuedPayload = 32 * 1024 * 1024

// One maximum needset request fits here; getblocktx's bounded window is smaller.
const supplementalQueueReserve = 2 * 1024 * 1024

// PayloadBudget bounds protocol payload maxima held during message reads,
// queued processing, and response service. It is separate from download credit
// and is not a process RSS limit. Reserved capacity is for supplemental replies
// needed to finish an already accepted reconstruction.
type PayloadBudget struct {
	mu       sync.Mutex
	limit    uint64
	reserved uint64
	used     uint64
	queued   uint64
}

func NewPayloadBudget(limit, reserved uint64) *PayloadBudget {
	return &PayloadBudget{limit: limit, reserved: min(limit, reserved)}
}

// TryReserve never waits while holding another message. Nil disables the budget.
func (b *PayloadBudget) TryReserve(size uint64, supplemental bool) (*PayloadReservation, bool) {
	if b == nil || size == 0 {
		return nil, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.limit
	if !supplemental {
		limit -= b.reserved
	}
	if b.used > limit || size > limit-b.used {
		return nil, false
	}
	b.used += size
	return &PayloadReservation{budget: b, size: size}, true
}

// TryReserveQueued also leaves room for the requests that complete an accepted
// reconstruction when ordinary announcements/download queues are saturated.
func (b *PayloadBudget) TryReserveQueued(size uint64, supplemental bool) (*PayloadReservation, bool) {
	if b == nil || size == 0 {
		return nil, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := uint64(MaxQueuedPayload)
	if !supplemental {
		limit -= supplementalQueueReserve
	}
	if b.queued > limit || size > limit-b.queued || size > b.limit-b.used {
		return nil, false
	}
	b.used += size
	b.queued += size
	return &PayloadReservation{budget: b, size: size, queued: true}, true
}

func (b *PayloadBudget) Usage() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// PayloadReservation belongs to one holder until its data is processed or
// discarded. Release is safe on nil and on concurrent error/cleanup paths.
type PayloadReservation struct {
	budget *PayloadBudget
	size   uint64
	once   sync.Once
	queued bool
}

func (r *PayloadReservation) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		r.budget.mu.Lock()
		r.budget.used -= r.size
		if r.queued {
			r.budget.queued -= r.size
		}
		r.budget.mu.Unlock()
	})
}
