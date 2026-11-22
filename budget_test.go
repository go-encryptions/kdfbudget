package kdfbudget

import (
	"errors"
	"math"
	"testing"
	"time"
)

func mustAccept(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
}

func mustRefuse(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}
}

// A hostile header holds many runs, each within its own limit. The total is
// refused at exactly the run that crosses the budget, and the refusal spends
// nothing.
func TestHostilePBKDF2Multiplication(t *testing.T) {
	b := Default()
	const perRun = 1 << 26 // luks DefaultLimits.MaxPBKDF2Iterations
	// 2 * 2 * 2^26 = 2^28 units a run; 2^32 / 2^28 = 16 runs fit.
	for i := 0; i < 16; i++ {
		mustAccept(t, b.ChargePBKDF2(CostSHA512, perRun))
	}
	spent := b.Spent()
	if spent != DefaultMaxWork {
		t.Fatalf("spent %d after 16 runs, want %d", spent, DefaultMaxWork)
	}
	for i := 0; i < 3155; i++ { // luks #32: slots x digests
		mustRefuse(t, b.ChargePBKDF2(CostSHA512, perRun))
	}
	if b.Spent() != spent {
		t.Fatal("a refused charge spent work")
	}
	// Nothing is left, not even a cheap run.
	mustRefuse(t, b.ChargePBKDF2(CostSHA1, 1))
}

func TestHostileArgon2Multiplication(t *testing.T) {
	b := Default()
	const memKiB = 4 << 20 // 4 GiB, cryptsetup's ceiling
	// One pass costs 2^22 * 8 = 2^25 units: 128 runs fit (apfs #35: 888).
	for i := 0; i < 128; i++ {
		mustAccept(t, b.ChargeArgon2(memKiB, 1, 1))
	}
	for i := 0; i < 888-128; i++ {
		mustRefuse(t, b.ChargeArgon2(memKiB, 1, 1))
	}
	if b.Spent() != DefaultMaxWork {
		t.Fatalf("spent %d, want %d", b.Spent(), DefaultMaxWork)
	}
}

func TestDefaultsAcceptRealWorldMaxima(t *testing.T) {
	cases := []struct {
		name string
		run  func(b *Budget) error
	}{
		{"cryptsetup argon2 4 GiB, 4 threads, 10 passes", func(b *Budget) error { return b.ChargeArgon2(4<<20, 10, 4) }},
		{"cryptsetup argon2 32 slots x 1 GiB 4 passes", func(b *Budget) error {
			for i := 0; i < 32; i++ {
				if err := b.ChargeArgon2(1<<20, 4, 4); err != nil {
					return err
				}
			}
			return nil
		}},
		{"luks1 pbkdf2-sha1 8 slots x 2^26", func(b *Budget) error {
			for i := 0; i < 8; i++ {
				if err := b.ChargePBKDF2(CostSHA1, 1<<26); err != nil {
					return err
				}
			}
			return nil
		}},
		{"openzfs minimum pbkdf2iters 100000 sha1", func(b *Budget) error { return b.ChargePBKDF2(CostSHA1, 100000) }},
		{"openzfs pbkdf2iters 2^31 sha1 (no maximum)", func(b *Budget) error { return b.ChargePBKDF2(CostSHA1, 1<<31) }},
		{"bitlocker stretch 0x100000 x 2 blocks", func(b *Budget) error { return b.ChargeCompressions(CostSHA256, 2*0x100000) }},
		{"apfs argon2 255 threads", func(b *Budget) error { return b.ChargeArgon2(255*8, 1, 255) }},
		{"veracrypt every variant, PIM 2000 (15000+1000*PIM iterations)", func(b *Budget) error {
			const iters = 15000 + 1000*2000
			for _, c := range []uint64{CostSHA512, CostWhirlpool, CostSHA256, CostBLAKE2s, CostRIPEMD160, CostStreebog} {
				if err := b.ChargePBKDF2(c, iters); err != nil {
					return err
				}
			}
			return nil
		}},
		{"veracrypt argon2 1 GiB (PIM formula of cryptsetup)", func(b *Budget) error { return b.ChargeArgon2(1<<20, 100, 1) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { mustAccept(t, c.run(Default())) })
	}
}

func TestPBKDF2Arithmetic(t *testing.T) {
	b := Default()
	mustAccept(t, b.ChargePBKDF2(CostSHA512, 1000))
	if got := b.Spent(); got != 2*2*1000 {
		t.Fatalf("spent %d, want 4000", got)
	}
	mustRefuse(t, b.ChargePBKDF2(0, 10))
	mustRefuse(t, b.ChargePBKDF2(1, 0))
	mustRefuse(t, b.ChargePBKDF2(math.MaxUint64, 1))   // 2*cost overflows
	mustRefuse(t, b.ChargePBKDF2(2, math.MaxUint64/2)) // product overflows
	mustRefuse(t, (*Budget)(nil).ChargePBKDF2(1, 1))
	mustRefuse(t, new(Budget).ChargePBKDF2(1, 1)) // zero Budget refuses
	if b.Spent() != 4000 {
		t.Fatal("a refusal spent work")
	}
}

func TestCompressions(t *testing.T) {
	b := Default()
	mustAccept(t, b.ChargeCompressions(CostSHA512, 5))
	if b.Spent() != 10 {
		t.Fatalf("spent %d", b.Spent())
	}
	mustRefuse(t, b.ChargeCompressions(0, 5))
	mustRefuse(t, b.ChargeCompressions(5, 0))
	mustRefuse(t, b.ChargeCompressions(math.MaxUint64, 2))
}

func TestArgon2Refusals(t *testing.T) {
	b := Default()
	mustRefuse(t, b.ChargeArgon2(1024, 1, 0))
	mustRefuse(t, b.ChargeArgon2(1024, 1, 256)) // truncated to 0 as a uint8: apfs
	mustRefuse(t, b.ChargeArgon2(1<<20, 1<<40, 256))
	mustRefuse(t, b.ChargeArgon2(1024, 0, 1))
	mustRefuse(t, b.ChargeArgon2(15, 1, 2))      // under 8 KiB per thread
	mustRefuse(t, b.ChargeArgon2(4<<20+1, 1, 1)) // above 4 GiB
	mustRefuse(t, b.ChargeArgon2(1<<62, 1, 1))   // 2^62 KiB: zfs-style absurd
	mustRefuse(t, (*Budget)(nil).ChargeArgon2(8, 1, 1))
	if b.Spent() != 0 {
		t.Fatal("a refusal spent work")
	}
	mustAccept(t, b.ChargeArgon2(16, 3, 2))
	if b.Spent() != 16*3*Argon2BlockCost {
		t.Fatalf("spent %d", b.Spent())
	}
	// Work overflow with the structural bounds satisfied.
	u := Unlimited()
	mustRefuse(t, u.ChargeArgon2(1<<40, 1<<40, 1)) // memory x passes overflows 2^64
	mustRefuse(t, u.ChargeArgon2(1<<40, 1<<22, 1)) // x 8 overflows, product alone does not
	mustAccept(t, u.ChargeArgon2(1<<40, 1<<20, 1))
}

func TestMaxThreadsAndMemoryAreTheCallers(t *testing.T) {
	b := &Budget{MaxMemory: 1 << 30, MaxThreads: 4, MaxWork: math.MaxUint64}
	mustAccept(t, b.ChargeArgon2(1<<20, 1, 4))
	mustRefuse(t, b.ChargeArgon2(1<<20, 1, 5))
	mustRefuse(t, b.ChargeArgon2(1<<20+1, 1, 1))
}

func TestDeadline(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	b := Default()
	b.Deadline = now.Add(time.Minute)
	b.now = func() time.Time { return now }
	mustAccept(t, b.ChargePBKDF2(1, 1))
	now = now.Add(time.Minute) // at the deadline: still allowed
	mustAccept(t, b.ChargePBKDF2(1, 1))
	now = now.Add(time.Nanosecond)
	mustRefuse(t, b.ChargePBKDF2(1, 1))
	mustRefuse(t, b.ChargeArgon2(8, 1, 1))
	// The real clock: a deadline in the past refuses, one far ahead does not.
	b = Default()
	b.Deadline = time.Now().Add(-time.Second)
	mustRefuse(t, b.ChargePBKDF2(1, 1))
	b.Deadline = time.Now().Add(time.Hour)
	mustAccept(t, b.ChargePBKDF2(1, 1))
}

func TestUnlimitedAndNil(t *testing.T) {
	u := Unlimited()
	mustAccept(t, u.ChargePBKDF2(CostSHA512, 1<<40))
	mustAccept(t, u.ChargeArgon2(1<<30, 1000, 255))
	var n *Budget
	if n.Spent() != 0 {
		t.Fatal("nil Spent")
	}
}

func TestExactBoundary(t *testing.T) {
	b := &Budget{MaxMemory: 1 << 20, MaxThreads: 1, MaxWork: 100}
	mustAccept(t, b.ChargeCompressions(1, 100)) // exactly the budget
	mustRefuse(t, b.ChargeCompressions(1, 1))
	b = &Budget{MaxWork: 100}
	mustRefuse(t, b.ChargeCompressions(1, 101))
	mustAccept(t, b.ChargeCompressions(1, 100))
}

func TestConcurrent(t *testing.T) {
	b := &Budget{MaxWork: 1000}
	done := make(chan bool)
	ok := 0
	for i := 0; i < 50; i++ {
		go func() { done <- b.ChargeCompressions(1, 10) == nil }()
	}
	for i := 0; i < 50; i++ {
		if <-done {
			ok++
		}
	}
	if ok != 50 || b.Spent() != 500 {
		t.Fatalf("ok %d spent %d", ok, b.Spent())
	}
	for i := 0; i < 100; i++ {
		go func() { done <- b.ChargeCompressions(1, 10) == nil }()
	}
	ok = 0
	for i := 0; i < 100; i++ {
		if <-done {
			ok++
		}
	}
	if ok != 50 || b.Spent() != 1000 {
		t.Fatalf("ok %d spent %d", ok, b.Spent())
	}
}

// FuzzCharge asserts the invariants of the arithmetic under any input,
// including values above 2^32 on a 32-bit build: spent never exceeds MaxWork,
// never decreases, a refusal spends nothing and an acceptance spends exactly
// the cost model's amount.
func FuzzCharge(f *testing.F) {
	f.Add(uint64(1), uint64(1), uint64(1), uint64(1), uint64(100))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(255), uint64(math.MaxUint64))
	f.Add(uint64(1<<32), uint64(1<<31), uint64(1<<63), uint64(256), uint64(1<<32))
	f.Add(uint64(4<<20), uint64(3), uint64(4), uint64(4), uint64(DefaultMaxWork))
	f.Fuzz(func(t *testing.T, a, c, d, threads, max uint64) {
		b := &Budget{MaxMemory: DefaultMaxMemory, MaxThreads: math.MaxUint8, MaxWork: max}
		check := func(err error, want uint64, wantOK bool) {
			t.Helper()
			if err != nil {
				if !errors.Is(err, ErrLimit) {
					t.Fatalf("non-ErrLimit error %v", err)
				}
				return
			}
			if !wantOK {
				t.Fatal("accepted a charge whose cost overflows")
			}
			if b.Spent() < want {
				t.Fatalf("spent %d under the cost %d", b.Spent(), want)
			}
			if b.Spent() > b.MaxWork {
				t.Fatalf("spent %d over the budget %d", b.Spent(), b.MaxWork)
			}
		}
		// Each charge starts from a fresh budget so the cost is exact.
		fresh := func() { b = &Budget{MaxMemory: DefaultMaxMemory, MaxThreads: math.MaxUint8, MaxWork: max} }

		fresh()
		per, ok1 := mul(a, 2)
		w, ok2 := mul(per, c)
		err := b.ChargePBKDF2(a, c)
		if a != 0 && c != 0 && ok1 && ok2 && w <= max && err != nil {
			t.Fatalf("refused an affordable PBKDF2 charge: %v", err)
		}
		check(err, w, ok1 && ok2 && a != 0 && c != 0)
		if err == nil && b.Spent() != w {
			t.Fatalf("PBKDF2 spent %d, want %d", b.Spent(), w)
		}

		fresh()
		w, ok := mul(a, c)
		err = b.ChargeCompressions(a, c)
		check(err, w, ok && w != 0)
		if err == nil && b.Spent() != w {
			t.Fatalf("compressions spent %d, want %d", b.Spent(), w)
		}

		fresh()
		blocks, okA := mul(a, d)
		w, okB := mul(blocks, Argon2BlockCost)
		err = b.ChargeArgon2(a, d, threads)
		if err == nil {
			if !okA || !okB || threads < 1 || threads > 255 || d < 1 || a < 8*threads || a > DefaultMaxMemory/1024 {
				t.Fatalf("accepted Argon2 %d KiB x %d passes x %d threads", a, d, threads)
			}
			if b.Spent() != w {
				t.Fatalf("Argon2 spent %d, want %d", b.Spent(), w)
			}
		} else if !errors.Is(err, ErrLimit) {
			t.Fatalf("non-ErrLimit error %v", err)
		}
	})
}
