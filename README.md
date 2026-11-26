Keygen FAST Bitcoin Generator
=============================

Fast P2PKH ("1...") Bitcoin address generator that **matches in memory**
against a list of target addresses — no `awk`, no giant intermediate file.

Forked from Fast Vanity Bitcoin address generator for Linux using the
[secp256k1_fast_unsafe](https://github.com/llamasoft/secp256k1_fast_unsafe)
library. Modified by `magnuspub` from the original work of `gandalf@winds.org`.

> **This application is a curiosity.** You cannot generate random addresses
> and expect to hit a funded one — the key space is 2^160. Bitcoin is STRONG.

What changed in this version
----------------------------
The old workflow was: print every generated key to a huge file, then compare
it against a target list with `awk`. That had three problems:

1. **Matching now happens in-process.** Target addresses are decoded once to
   their 20-byte HASH160 and stored in an in-memory open-addressing hash set
   (the C equivalent of awk's `arr[$0]`, but on raw bytes). Each generated key
   is checked by comparing 20 bytes — no base58 per key, no output file to
   grep. This alone removes the `awk` dependency entirely.

2. **The fast batch engine is restored.** The previous build did a full scalar
   multiplication (actually two) and a `/dev/urandom` read for *every* key. It
   now reads one random start key per batch and derives `STEP` consecutive
   public keys by cheap incremental point addition plus a single batched field
   inversion. Result: ~45× faster per thread (≈1M keys/s/core here, vs ≈23k/s).

3. **Threads live inside one process.** Each hit is written as one atomic,
   flushed line under a mutex. The old "run 8 copies all appending to the same
   file with `>>`" pattern corrupted ~2.5% of lines (interleaved, mismatched
   Address/Privkey) because of block-buffered stdout — that is gone.

Usage
-----

    # 1) Prepare a target file: one address ("1...") or 40-hex HASH160 per line
    $ cat targets.txt
    1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    1LysQiFRavU58yVZ5Htn8dwgtJmJR2dgfo
    ...

    # 2) Search (uses all CPU cores by default). Hits go to stdout.
    $ ./keygen -f targets.txt
    Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH Privkey: KwDiBf89Qg...

    # Append hits to a file and run 8 threads:
    $ ./keygen -f targets.txt -t 8 -o hits.txt

Options:

    -f <file>   target addresses or 40-hex HASH160, one per line ("-" = stdin)
    -t <n>      worker threads (default: all cores)
    -o <file>   append hits here (default: stdout)
    -q          quiet: no periodic rate line on stderr
    -k <hex>    fixed starting key for the first batch (benchmark/test only;
                must be greater than STEP)
    -h          help

Only compressed-key P2PKH ("1...") addresses are generated and matched.
Bech32 ("bc1...") and P2SH ("3...") are not produced by this generator, so
such lines in the target file are skipped (with a count printed at startup).

Tuning
------
`STEP` (compile-time, top of `keygen.c`, default 4096) sets the batch size:
larger amortizes the field inversion over more keys (faster) at the cost of a
little more per-thread memory. 1024–8192 is a sensible range.

The target hash set uses about `next_pow2(2 * N) * 20` bytes for `N` targets
(≈40 bytes/target). For very large lists on a memory-constrained box, a Bloom
pre-filter in front of the set is the natural next optimization.

Build Prerequisites
-------------------
* GCC, Make, Libtool, Autotools, GMP (pthreads are part of libc)

Ubuntu:

    $ sudo apt-get install build-essential automake autoconf libtool libgmp-dev

RedHat/Fedora:

    $ sudo yum -y install gcc make automake autoconf libtool gmp-devel

Build
-----

    $ make

This configures and compiles the bundled secp256k1 library, then the tool.
If GMP is unavailable you can drop `-lgmp` from the Makefile and configure
secp256k1 with `--with-bignum=no`.

Warning
-------
**Verify any generated key before use.** This is beta software; always confirm
that a reported private/public key pair is correct before relying on it.

License
-------
Distributed under the GPLv2. Individual portions are under compatible MIT or
BSD licenses; see each file for details.
