// Package kdfbudget bounds the TOTAL key-derivation work spent opening one
// volume or key.
//
// A header read from an image is untrusted. Checking each KDF run against its
// own limit is not enough: a hostile header can hold many runs (key slots
// times digests, lockers, every KDF a format tries in turn), each one within
// its limit, and the sum is unbounded. A Budget is created for one unlock and
// every run is charged to it BEFORE it is spent; a charge that does not fit is
// refused with ErrLimit and spends nothing.
//
//	b := kdfbudget.Default()
//	for _, slot := range slots {
//		if err := b.ChargePBKDF2(kdfbudget.CostSHA512, slot.Iterations); err != nil {
//			return err // errors.Is(err, kdfbudget.ErrLimit)
//		}
//		key := pbkdf2(slot) // only now
//	}
//
// # Cost model
//
// Work is counted in units, one unit being the compression of one 64-byte
// block by a plain hash (SHA-1, SHA-256, RIPEMD-160, BLAKE2s):
//
//   - PBKDF2-HMAC runs the hash twice per iteration (inner and outer) for
//     each output block: 2 * iterations * hashBlockCost. The Cost constants
//     give hashBlockCost; SHA-512 is 2 because its block is 128 bytes.
//     Charge once per output block when the derived key is longer than the
//     hash output.
//   - Argon2 fills passes * memKiB blocks of 1 KiB; one block fill is
//     charged Argon2BlockCost (8) units, which puts Argon2 and PBKDF2 within
//     a small factor of each other in time on one core. Threads do not
//     change the work, only the elapsed time.
//
// The constants are round, conservative estimates, not measurements of one
// machine: the budget is a denial-of-service bound, accurate to a small
// factor, not a timer.
//
// Memory is a peak, not a sum: runs are sequential, so each Argon2 run is
// checked against MaxMemory and none is added to another.
package kdfbudget

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"time"
)

// ErrLimit is returned, wrapped, by every refused charge. Packages that had
// their own ErrLimit can alias it: var ErrLimit = kdfbudget.ErrLimit.
var ErrLimit = errors.New("kdfbudget: the key derivation asks for more than the budget allows")

// Relative cost of one compression of the named hash, for ChargePBKDF2. The
// unit is a 64-byte block of a plain hash. SHA-512 takes 128 bytes per block,
// hence 2; Whirlpool and Streebog are table or S-box heavy and rounded up to 4.
// A hash not listed takes the cost of the nearest one, rounded up.
const (
	CostSHA1      uint64 = 1
	CostRIPEMD160 uint64 = 1
	CostSHA256    uint64 = 1
	CostBLAKE2s   uint64 = 1
	CostSHA512    uint64 = 2
	CostWhirlpool uint64 = 4
	CostStreebog  uint64 = 4
)

// Argon2BlockCost is the cost of filling one 1 KiB Argon2 block.
const Argon2BlockCost uint64 = 8

// Defaults, from the maxima of the tools that write volumes.
const (
	// DefaultMaxMemory is 4 GiB: cryptsetup's ceiling for Argon2 memory
	// (crypt_pbkdf_get_limits).
	DefaultMaxMemory uint64 = 4 << 30
	// DefaultMaxThreads is 255, what golang.org/x/crypto/argon2 takes (its
	// parallelism is a uint8); cryptsetup writes 1 to 4.
	DefaultMaxThreads uint8 = math.MaxUint8
	// DefaultMaxWork is 2^32 units, about three minutes of one core. It
	// covers a LUKS2 volume with its 32 key slots each calibrated to about
	// two seconds, tried in turn with a wrong passphrase, with margin; and
	// 2^31 PBKDF2-SHA1 iterations, far more than OpenZFS writes (its minimum
	// is 100000 and it sets no maximum). A header that wants more is refused:
	// use Unlimited for a volume you trust.
	DefaultMaxWork uint64 = 1 << 32
)

// A Budget bounds the key-derivation work of one unlock. It is safe for
// concurrent use, but its limit fields must not change after the first
// charge. Create it with Default or Unlimited, or fill the fields; the zero
// Budget refuses every charge, and so does a nil *Budget.
type Budget struct {
	// MaxMemory bounds the memory of one Argon2 run, in bytes.
	MaxMemory uint64
	// MaxThreads bounds the parallelism of one Argon2 run.
	MaxThreads uint8
	// MaxWork bounds the sum of every charge, in units (see the package
	// comment).
	MaxWork uint64
	// Deadline, when not zero, refuses every charge made after it.
	Deadline time.Time

	mu    sync.Mutex
	spent uint64
	now   func() time.Time // time.Now when nil; replaced by tests
}

// Default returns a Budget with the Default constants and no deadline.
func Default() *Budget {
	return &Budget{MaxMemory: DefaultMaxMemory, MaxThreads: DefaultMaxThreads, MaxWork: DefaultMaxWork}
}

// Unlimited returns a Budget that only keeps the structural bounds (Argon2
// needs 1 to 255 threads and 8 KiB per thread) and counts the work spent. Use
// it for a header you wrote or trust.
func Unlimited() *Budget {
	return &Budget{MaxMemory: math.MaxUint64, MaxThreads: math.MaxUint8, MaxWork: math.MaxUint64}
}

// Spent returns the work charged so far.
func (b *Budget) Spent() uint64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.spent
}

// ChargePBKDF2 charges a PBKDF2-HMAC run of iters iterations with a hash of
// relative cost hashBlockCost (the Cost constants), for one output block.
// Call it before deriving, once per output block.
func (b *Budget) ChargePBKDF2(hashBlockCost, iters uint64) error {
	if hashBlockCost == 0 || iters == 0 {
		return fmt.Errorf("%w: PBKDF2 with %d iterations at cost %d", ErrLimit, iters, hashBlockCost)
	}
	perIter, ok := mul(hashBlockCost, 2)
	if !ok {
		return fmt.Errorf("%w: PBKDF2 hash cost %d overflows", ErrLimit, hashBlockCost)
	}
	work, ok := mul(perIter, iters)
	if !ok {
		return fmt.Errorf("%w: %d PBKDF2 iterations overflow the work count", ErrLimit, iters)
	}
	return b.charge(work, fmt.Sprintf("%d PBKDF2 iterations", iters))
}

// ChargeCompressions charges n compressions of a hash of relative cost
// hashBlockCost, for a derivation that is not PBKDF2: BitLocker's key stretch
// hashes 0x100000 times an 88-byte structure, 2 blocks each, which is
// ChargeCompressions(CostSHA256, 2*0x100000).
func (b *Budget) ChargeCompressions(hashBlockCost, n uint64) error {
	work, ok := mul(hashBlockCost, n)
	if !ok || work == 0 {
		return fmt.Errorf("%w: %d compressions at cost %d", ErrLimit, n, hashBlockCost)
	}
	return b.charge(work, fmt.Sprintf("%d hash compressions", n))
}

// ChargeArgon2 charges an Argon2 run of memKiB KiB, passes passes and threads
// lanes. Besides the budget it refuses parameters argon2 itself cannot take
// (no pass, no thread, fewer than 8 KiB per thread), which would otherwise
// panic or be truncated, and memory above MaxMemory. Call it before deriving.
func (b *Budget) ChargeArgon2(memKiB, passes, threads uint64) error {
	if b == nil {
		return fmt.Errorf("%w: no budget", ErrLimit)
	}
	switch {
	case threads < 1 || threads > uint64(b.MaxThreads):
		return fmt.Errorf("%w: %d Argon2 threads (1 to %d)", ErrLimit, threads, b.MaxThreads)
	case passes < 1:
		return fmt.Errorf("%w: 0 Argon2 passes", ErrLimit)
	case memKiB < 8*threads: // threads <= 255: no overflow
		return fmt.Errorf("%w: %d KiB of Argon2 memory for %d threads (8 per thread)", ErrLimit, memKiB, threads)
	case memKiB > b.MaxMemory/1024:
		return fmt.Errorf("%w: %d KiB of Argon2 memory, at most %d", ErrLimit, memKiB, b.MaxMemory/1024)
	}
	blocks, ok := mul(memKiB, passes)
	if !ok {
		return fmt.Errorf("%w: Argon2 %d KiB x %d passes overflows the work count", ErrLimit, memKiB, passes)
	}
	work, ok := mul(blocks, Argon2BlockCost)
	if !ok {
		return fmt.Errorf("%w: Argon2 %d KiB x %d passes overflows the work count", ErrLimit, memKiB, passes)
	}
	return b.charge(work, fmt.Sprintf("Argon2 %d KiB x %d passes", memKiB, passes))
}

func (b *Budget) charge(work uint64, what string) error {
	if b == nil {
		return fmt.Errorf("%w: no budget", ErrLimit)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	if !b.Deadline.IsZero() && now().After(b.Deadline) {
		return fmt.Errorf("%w: the deadline has passed", ErrLimit)
	}
	// spent <= MaxWork always holds, so the subtraction cannot wrap.
	if work > b.MaxWork-b.spent {
		return fmt.Errorf("%w: %s needs %d units, %d of %d left", ErrLimit, what, work, b.MaxWork-b.spent, b.MaxWork)
	}
	b.spent += work
	return nil
}

func mul(a, b uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	return lo, hi == 0
}
