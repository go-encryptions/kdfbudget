# kdfbudget

One shared bound on the TOTAL key-derivation work spent opening a volume or key.

A header read from an image is untrusted. Limiting each KDF run is not enough:
a hostile header can hold many runs (key slots times digests, keybag lockers,
every KDF a format tries in turn), each one within its limit, and the sum is
unbounded. Measured on the fleet: 3155 runs for any password in LUKS
([go-fde/luks#32](https://github.com/go-fde/luks/issues/32)), 888 with no
passphrase in APFS ([go-fde/apfs#35](https://github.com/go-fde/apfs/issues/35)),
`pbkdf2iters` of 2^62 in zfscrypt, and a facade that cannot pass limits
([go-fde/fde#41](https://github.com/go-fde/fde/issues/41)).

A `Budget` is made for one unlock. Every run is charged BEFORE it is spent; a
charge that does not fit returns `ErrLimit` and spends nothing.

```go
b := kdfbudget.Default() // or Unlimited() for a header you trust

for _, slot := range slots {
	if err := b.ChargePBKDF2(kdfbudget.CostSHA512, slot.Iterations); err != nil {
		return err // errors.Is(err, kdfbudget.ErrLimit)
	}
	key := pbkdf2(slot) // only now
}
if err := b.ChargeArgon2(memKiB, passes, threads); err != nil { ... }
if err := b.ChargeCompressions(kdfbudget.CostSHA256, 2*0x100000); err != nil { ... } // BitLocker stretch
```

## API

| | |
|---|---|
| `Budget{MaxMemory, MaxThreads, MaxWork, Deadline}` | limits for one unlock; safe for concurrent use; the zero value and a nil pointer refuse everything |
| `Default()`, `Unlimited()` | the defaults below; structural bounds only |
| `ChargePBKDF2(hashBlockCost, iters)` | one output block |
| `ChargeArgon2(memKiB, passes, threads)` | also refuses what `argon2` cannot take (0 passes, 0 or more than 255 threads, under 8 KiB per thread) |
| `ChargeCompressions(hashBlockCost, n)` | any other hash chain |
| `Spent()`, `ErrLimit` | `ErrLimit` can be aliased by a package that had its own |

Parameters are `uint64`, so a value above 2^32 is refused rather than
truncated (an APFS locker with 256 threads became 0 as a `uint8`).

## Cost model

One unit is the compression of one 64-byte block by a plain hash.

- PBKDF2-HMAC: `2 * iterations * hashBlockCost` (inner and outer hash per
  iteration). Costs: SHA-1, SHA-256, RIPEMD-160, BLAKE2s 1; SHA-512 2 (128-byte
  block); Whirlpool, Streebog 4.
- Argon2: `passes * memKiB * 8`. Threads change elapsed time, not work.
- Memory is a peak: each Argon2 run is checked against `MaxMemory`, never
  summed.

The constants are round, conservative estimates, not measurements of a
machine: the budget is a denial-of-service bound accurate to a small factor,
not a timer.

## Defaults

`MaxMemory` 4 GiB (cryptsetup's Argon2 ceiling), `MaxThreads` 255 (what
`x/crypto/argon2` takes; cryptsetup writes 1 to 4), `MaxWork` 2^32 units, about
three minutes of one core. The tests assert that these accept: a 4 GiB Argon2
with 4 threads; 32 LUKS2 slots each 1 GiB x 4 passes; 8 LUKS1 slots of 2^26
PBKDF2 iterations; OpenZFS's minimum `pbkdf2iters` (100000, no maximum) and
2^31; BitLocker's fixed 0x100000-round stretch; every VeraCrypt variant at PIM
2000 (15000 + 1000 x PIM iterations). A hostile header is refused at the run
that crosses the budget: the 17th LUKS slot of 2^26 SHA-512 iterations, the
129th 4 GiB Argon2 locker. Use `Unlimited()` for a volume you trust.

## Tests

100% statement coverage, race detector, a fuzz target on the charge arithmetic
(overflow, thread truncation, exact cost), a committed seed corpus, and a
32-bit (386) lane.
