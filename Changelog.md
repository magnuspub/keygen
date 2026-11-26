Changelog
=========

Version 1.0 - Nov 2026
----------------------
* Native in-memory matching: targets are decoded to HASH160 and looked up in
  an open-addressing hash set. No more `awk` and no intermediate dump file.
* Restored the batch EC engine (one random seed + one scalar mult per STEP
  keys, then incremental point additions + a single batched field inversion).
  ~45x faster per thread than 0.3 (~1M keys/s/core vs ~23k/s here).
* Multithreaded inside one process; each hit is one atomic, flushed line.
  Fixes the garbled/mismatched lines caused by running several copies with
  `>>` into one block-buffered file.
* Fixed missing field normalization before pubkey serialization (only ever
  correct by luck at STEP=1 before).
* New flags: -f (targets), -t (threads), -o (output), -q (quiet), -k (fixed
  start key for benchmarking), -h (help).

Version 0.1 - Apr  23 2019
-------------------------
* Initial release. ~20000 Keys/s per thread.
  On a AMD2700X (8 thread) ~170000 Keys/s
