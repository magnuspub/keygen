/* keygen.c - FAST Bitcoin address generator with native in-memory matching
 *
 * Rewritten by request:
 *   - no more awk: targets are matched in-process against an in-memory
 *     hash set of 20-byte HASH160 values (the C equivalent of awk's
 *     associative array `arr[$0]`, but on raw bytes instead of base58
 *     strings, so we never base58-encode a key unless it is a hit);
 *   - the batch EC engine of the original vanitygen is restored: one
 *     /dev/urandom read and one scalar multiplication per STEP keys,
 *     then STEP cheap point additions + a single batched field inversion;
 *   - multithreaded inside ONE process; each hit is written as one atomic
 *     full-line write() under a mutex, so output is never garbled (the old
 *     "run N copies with >> into the same file" pattern corrupted ~2.5%
 *     of lines through stdout block-buffering + interleaved appends).
 *
 * Forked from Super Vanitygen - Vanity Bitcoin address generator.
 * Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>  (MIT, see below)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

#include "externs.h"
#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>

/* Number of secp256k1 operations per batch. Larger = faster (amortizes the
 * single expensive field inversion over more keys) at the cost of memory
 * (STEP * sizeof(gej/ge/fe)). 1024-8192 is a good range. */
#ifndef STEP
#define STEP 4096
#endif

#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"

#define MY_VERSION "1.0"

/**** Small helpers **********************************************************/

static void die(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}

static void *xmalloc(size_t n)
{
  void *p = malloc(n);
  if(!p) die("out of memory (requested %zu bytes)", n);
  return p;
}

static inline uint64_t load_u64_le(const u8 *p)
{
  uint64_t v;
  memcpy(&v, p, 8);
  return v;  /* host-endian; only used as a hash, consistency is all we need */
}

/**** HASH160 target set  (open-addressing hash set over 20-byte keys) ******
 *
 * HASH160 values are already uniformly distributed, so we use the first 8
 * bytes directly as the hash and resolve collisions with linear probing.
 * At load factor 0.5 a *miss* (the overwhelmingly common case in the hot
 * loop) resolves in ~1 probe = one cache line. This is what makes it as
 * fast as, and usually faster than, the awk approach: no base58 per key,
 * just a masked index and a 20-byte compare.
 */

typedef struct {
  u8      (*slot)[20];   /* slot[i] = 20-byte key, all-zero means empty      */
  size_t    cap;         /* power of two                                     */
  size_t    mask;        /* cap - 1                                          */
  size_t    count;       /* number of distinct keys inserted                 */
  int       has_zero;    /* the all-zero HASH160 is (impossibly) a target    */
} h160set;

static int is_zero20(const u8 *k)
{
  for(int i = 0; i < 20; i++) if(k[i]) return 0;
  return 1;
}

static size_t next_pow2(size_t n)
{
  size_t p = 1;
  while(p < n) p <<= 1;
  return p;
}

static void set_init(h160set *s, size_t expected)
{
  size_t want = next_pow2((expected < 8 ? 8 : expected) * 2);
  s->cap  = want;
  s->mask = want - 1;
  s->count = 0;
  s->has_zero = 0;
  s->slot = xmalloc(want * 20);
  memset(s->slot, 0, want * 20);
}

static void set_place(h160set *s, const u8 *k)   /* insert, assumes room */
{
  size_t i = load_u64_le(k) & s->mask;
  for(;;) {
    u8 *slot = s->slot[i];
    if(is_zero20(slot)) { memcpy(slot, k, 20); s->count++; return; }
    if(!memcmp(slot, k, 20)) return;            /* duplicate */
    i = (i + 1) & s->mask;
  }
}

static void set_grow(h160set *s)                 /* double capacity, rehash */
{
  size_t old_cap = s->cap;
  u8 (*old)[20] = s->slot;
  s->cap  <<= 1;
  s->mask  = s->cap - 1;
  s->count = 0;
  s->slot  = xmalloc(s->cap * 20);
  memset(s->slot, 0, s->cap * 20);
  for(size_t i = 0; i < old_cap; i++)
    if(!is_zero20(old[i])) set_place(s, old[i]);
  free(old);
}

static void set_insert(h160set *s, const u8 *k)
{
  if(is_zero20(k)) { s->has_zero = 1; return; }
  if(s->count + 1 > (s->cap >> 1))               /* keep load factor <= 0.5 */
    set_grow(s);
  set_place(s, k);
}

/* The hot-path lookup. Branch-predicted as "not found". */
static inline int set_contains(const h160set *s, const u8 *k)
{
  size_t i = load_u64_le(k) & s->mask;
  for(;;) {
    const u8 *slot = s->slot[i];
    if(is_zero20(slot)) return 0;               /* empty -> stop, miss */
    if(!memcmp(slot, k, 20)) return 1;
    i = (i + 1) & s->mask;
  }
}

/**** Loading the target list ***********************************************/

static int hexval(int c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Parse one line into a 20-byte HASH160.
 * Accepts: a base58check P2PKH address ("1...") or a bare 40-char hex HASH160.
 * Returns 1 on success, 0 to skip the line. */
static int line_to_h160(const char *line, u8 out[20])
{
  /* trim leading/trailing whitespace */
  while(*line == ' ' || *line == '\t') line++;
  size_t len = strlen(line);
  while(len && (line[len-1] == '\n' || line[len-1] == '\r' ||
                line[len-1] == ' '  || line[len-1] == '\t')) len--;
  if(len == 0) return 0;

  /* bare 40-hex HASH160 */
  if(len == 40) {
    int ok = 1;
    for(size_t i = 0; i < 40; i++) if(hexval(line[i]) < 0) { ok = 0; break; }
    if(ok) {
      for(int i = 0; i < 20; i++)
        out[i] = (hexval(line[2*i]) << 4) | hexval(line[2*i+1]);
      return 1;
    }
  }

  /* base58check address -> 25 bytes: version(1) + h160(20) + checksum(4).
   * b58tobin decodes into exactly *binszp bytes, so ask for 25. */
  u8 bin[25];
  size_t binsz = 25;
  if(!b58tobin(bin, &binsz, line, len)) return 0;
  if(binsz != 25) return 0;
  if(bin[0] != 0x00) return 0;                   /* only P2PKH (addresses "1…") */

  /* verify checksum = first 4 bytes of sha256(sha256(version+h160)) */
  align8 u8 blk[64], cks[64], chk[32];
  sha256_prepare(blk, 21);
  memcpy(blk, bin, 21);
  sha256_prepare(cks, 32);
  sha256_hash(cks, blk);
  sha256_hash(chk, cks);
  if(memcmp(chk, bin + 21, 4) != 0) return 0;    /* bad checksum -> skip */

  memcpy(out, bin + 1, 20);
  return 1;
}

static void load_targets(h160set *s, const char *path)
{
  FILE *fp;
  if(!strcmp(path, "-")) fp = stdin;
  else if(!(fp = fopen(path, "r"))) die("cannot open target file: %s", path);

  /* First pass would let us size exactly, but counting lines on huge files
   * is cheap enough to skip: we grow by starting roomy and never rehash is
   * simpler. Instead we size from the file length as a rough upper bound. */
  size_t guess = 1 << 16;
  if(fp != stdin) {
    if(!fseek(fp, 0, SEEK_END)) {
      long sz = ftell(fp);
      if(sz > 0) guess = (size_t)sz / 20 + 16;   /* ~ addresses, overestimate */
      fseek(fp, 0, SEEK_SET);
    }
  }
  set_init(s, guess);

  char *buf = NULL;
  size_t bufcap = 0;
  ssize_t n;
  size_t lines = 0, bad = 0;
  u8 h160[20];
  while((n = getline(&buf, &bufcap, fp)) != -1) {
    lines++;
    if(line_to_h160(buf, h160)) set_insert(s, h160);
    else {
      /* ignore blank lines silently; count real rejects */
      const char *p = buf;
      while(*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
      if(*p) bad++;
    }
  }
  free(buf);
  if(fp != stdin) fclose(fp);

  double mb = (double)(s->cap * 20) / (1024.0 * 1024.0);
  fprintf(stderr,
    "[keygen] loaded %zu target(s) from %s (%zu line(s), %zu skipped), "
    "table %zu slots, %.1f MB%s\n",
    s->count, strcmp(path,"-")?path:"stdin", lines, bad, s->cap, mb,
    s->has_zero ? ", plus the all-zero HASH160" : "");
  if(s->count == 0 && !s->has_zero)
    die("[keygen] no valid targets loaded - nothing to search for.");
}

/**** Output ****************************************************************/

static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *out_fp;                 /* where hits go (default stdout)       */

/* Build the WIF/address strings for a hit and write the whole line in one
 * locked, flushed step so lines never interleave. */
static void emit_hit(const u8 priv[32], const u8 h160[20])
{
  align8 u8 pub_block[64], priv_block[64], cksum_block[64], checksum[32];
  char addr[64], wif[64], line[192];

  /* Address = base58check(0x00 || h160) */
  sha256_prepare(cksum_block, 32);
  sha256_prepare(pub_block, 21);
  pub_block[0] = 0x00;
  memcpy(pub_block + 1, h160, 20);
  sha256_hash(cksum_block, pub_block);
  sha256_hash(checksum, cksum_block);
  memcpy(pub_block + 21, checksum, 4);
  b58enc(addr, pub_block, 25);

  /* Private key (compressed) WIF = base58check(0x80 || priv || 0x01) */
  sha256_prepare(priv_block, 34);
  priv_block[0] = 0x80;
  memcpy(priv_block + 1, priv, 32);
  priv_block[33] = 0x01;                 /* compressed pubkey marker */
  sha256_hash(cksum_block, priv_block);
  sha256_hash(checksum, cksum_block);
  memcpy(priv_block + 34, checksum, 4);
  b58enc(wif, priv_block, 38);

  int len = snprintf(line, sizeof(line),
                     "Address: %s Privkey: %s\n", addr, wif);

  pthread_mutex_lock(&out_lock);
  fwrite(line, 1, (size_t)len, out_fp);
  fflush(out_fp);
  if(out_fp != stdout) {               /* also echo hits to the terminal */
    fputs("[HIT] ", stderr);
    fwrite(line, 1, (size_t)len, stderr);
  }
  pthread_mutex_unlock(&out_lock);
}

/**** libsecp256k1 batch helpers (thread-safe: no statics) ******************/

static void fe_inv_all(secp256k1_fe *r, const secp256k1_gej *a, int n)
{
  secp256k1_fe u;
  int i;
  r[0] = a[0].z;
  for(i = 1; i < n; i++)
    secp256k1_fe_mul(&r[i], &r[i-1], &a[i].z);
  secp256k1_fe_inv_var(&u, &r[--i]);
  for(; i > 0; i--) {
    secp256k1_fe_mul(&r[i], &r[i-1], &u);
    secp256k1_fe_mul(&u, &u, &a[i].z);
  }
  r[0] = u;
}

static void ge_set_all_gej(secp256k1_ge *r, const secp256k1_gej *a,
                           secp256k1_fe *azi, int n)
{
  int i;
  fe_inv_all(azi, a, n);
  for(i = 0; i < n; i++)
    secp256k1_ge_set_gej_zinv(&r[i], &a[i], &azi[i]);
}

static void gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a,
                           const secp256k1_ge *b)
{
  /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
  secp256k1_fe z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;

  secp256k1_fe_sqr(&z12, &a->z);
  u1 = a->x; secp256k1_fe_normalize_weak(&u1);
  secp256k1_fe_mul(&u2, &b->x, &z12);
  s1 = a->y; secp256k1_fe_normalize_weak(&s1);
  secp256k1_fe_mul(&s2, &b->y, &z12); secp256k1_fe_mul(&s2, &s2, &a->z);
  secp256k1_fe_negate(&h, &u1, 1); secp256k1_fe_add(&h, &u2);
  secp256k1_fe_negate(&i, &s1, 1); secp256k1_fe_add(&i, &s2);
  secp256k1_fe_sqr(&i2, &i);
  secp256k1_fe_sqr(&h2, &h);
  secp256k1_fe_mul(&h3, &h, &h2);
  secp256k1_fe_mul(&r->z, &a->z, &h);
  secp256k1_fe_mul(&t, &u1, &h2);
  r->x = t; secp256k1_fe_mul_int(&r->x, 2); secp256k1_fe_add(&r->x, &h3);
  secp256k1_fe_negate(&r->x, &r->x, 3); secp256k1_fe_add(&r->x, &i2);
  secp256k1_fe_negate(&r->y, &r->x, 5); secp256k1_fe_add(&r->y, &t);
  secp256k1_fe_mul(&r->y, &r->y, &i);
  secp256k1_fe_mul(&h3, &h3, &s1); secp256k1_fe_negate(&h3, &h3, 1);
  secp256k1_fe_add(&r->y, &h3);
}

/**** Hash engine (one per thread) ******************************************/

static const h160set *g_set;         /* read-only after load                */
static volatile uint64_t g_count;    /* keys tried (relaxed counter)        */
static volatile uint64_t g_hits;
static volatile int g_stop;

/* Optional fixed starting key for the first batch of thread 0, for
 * reproducible benchmarks/tests (-k <hex>). Empty => random as usual. */
static int   g_fixed_k0 = 0;
static u8    g_fixed_seed[32];

typedef struct { int id; } thread_arg;

/* True if 0 < s <= STEP (or s == 0). Portable across scalar limb layouts. */
static int scalar_small(const secp256k1_scalar *s)
{
  u8 b[32];
  secp256k1_scalar_get_b32(b, s);
  for(int i = 0; i < 28; i++) if(b[i]) return 0;
  uint32_t low = ((uint32_t)b[28] << 24) | ((uint32_t)b[29] << 16) |
                 ((uint32_t)b[30] << 8)  |  (uint32_t)b[31];
  return low <= (uint32_t)STEP;
}

static void *engine(void *varg)
{
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_scalar  scalar_key, scalar_one = {{1}};
  secp256k1_gej     temp;
  secp256k1_ge      offset;            /* affine G */

  /* Per-thread scratch (heap: STEP*these is too large for the stack). */
  secp256k1_gej *base = xmalloc(sizeof(*base) * STEP);
  secp256k1_ge  *rslt = xmalloc(sizeof(*rslt) * STEP);
  secp256k1_fe  *azi  = xmalloc(sizeof(*azi)  * STEP);

  align8 u8 sha_block[64], rmd_block[64];
  u8 h160[20];
  int fd, k;

  sha256_prepare(sha_block, 33);       /* input length 33 (compressed pubkey) */
  rmd160_prepare(rmd_block, 32);       /* input length 32 (sha256 output)     */

  /* offset = 1*G in affine form, computed once */
  secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &temp, &scalar_one);
  secp256k1_ge_set_gej_var(&offset, &temp);

  if((fd = open("/dev/urandom", O_RDONLY | O_NOCTTY)) == -1)
    die("/dev/urandom: %s", strerror(errno));

  u8 seed[32];
  uint64_t local = 0;
  int first = 1;
  thread_arg *ta = (thread_arg *)varg;

  while(!g_stop) {
    int overflow = 1;
    /* Fresh random starting key per batch (one syscall per STEP keys).
     * We reject k0 <= STEP so that k0..k0+STEP-1 never includes the scalar 1;
     * that keeps base[j] != G for the whole batch, so the fast (incomplete)
     * point-addition formula never hits its a==b doubling case. For a random
     * 256-bit k0 this rejects essentially nothing. */
    if(g_fixed_k0 && first && ta && ta->id == 0) {
      memcpy(seed, g_fixed_seed, 32);
      secp256k1_scalar_set_b32(&scalar_key, seed, &overflow);
      if(overflow || scalar_small(&scalar_key))
        die("[keygen] -k value must be > STEP (%d); it is a debug/benchmark "
            "aid, use a realistic key.", STEP);
    } else do {
      ssize_t len = read(fd, seed, 32);
      if(len != 32) die("/dev/urandom short read");
      secp256k1_scalar_set_b32(&scalar_key, seed, &overflow);
    } while(overflow || scalar_small(&scalar_key));
    first = 0;

    /* base[0] = k0*G ; base[j] = base[j-1] + G = (k0+j)*G */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &base[0], &scalar_key);
    for(k = 1; k < STEP; k++)
      gej_add_ge_var(&base[k], &base[k-1], &offset);

    /* Convert the whole batch to affine with ONE field inversion. */
    ge_set_all_gej(rslt, base, azi, STEP);

    for(k = 0; k < STEP; k++) {
      /* compressed pubkey -> sha256 -> rmd160 = HASH160.
       * set_gej_zinv leaves x,y un-normalized; normalize before serializing. */
      secp256k1_fe_normalize_var(&rslt[k].x);
      secp256k1_fe_normalize_var(&rslt[k].y);
      sha_block[0] = secp256k1_fe_is_odd(&rslt[k].y) ? 0x03 : 0x02;
      secp256k1_fe_get_b32(sha_block + 1, &rslt[k].x);
      sha256_hash(rmd_block, sha_block);
      rmd160_hash(h160, rmd_block);

      if(unlikely(set_contains(g_set, h160))) {
        /* Reconstruct the exact private key = (k0 + k) mod n, bulletproof. */
        secp256k1_scalar sk, sj;
        u8 priv[32];
        secp256k1_scalar_set_int(&sj, (unsigned)k);
        secp256k1_scalar_add(&sk, &scalar_key, &sj);
        secp256k1_scalar_get_b32(priv, &sk);
        emit_hit(priv, h160);
        __sync_fetch_and_add(&g_hits, 1);
      }
    }

    local += STEP;
    if(local >= (1u << 20)) {          /* fold into global counter now & then */
      __sync_fetch_and_add(&g_count, local);
      local = 0;
    }
  }

  __sync_fetch_and_add(&g_count, local);
  close(fd);
  free(base); free(rslt); free(azi);
  secp256k1_context_destroy(ctx);
  return NULL;
}

/**** Stats + main **********************************************************/

static void *stats_thread(void *arg)
{
  (void)arg;
  uint64_t last = 0;
  struct timespec t0, t;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  while(!g_stop) {
    struct timespec req = { 2, 0 };
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t);
    uint64_t cur = g_count;
    double dt = (t.tv_sec - t0.tv_sec) + (t.tv_nsec - t0.tv_nsec) / 1e9;
    double rate = dt > 0 ? (cur - last) / dt : 0;
    fprintf(stderr, "\r[keygen] %.1f Mkeys  %.0f keys/s  hits=%" PRIu64 "   ",
            cur / 1e6, rate, (uint64_t)g_hits);
    fflush(stderr);
    last = cur;
    t0 = t;
  }
  return NULL;
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(const char *prog)
{
  fprintf(stderr,
    "keygen " MY_VERSION " - Bitcoin P2PKH generator with native matching\n"
    "usage: %s -f <targets> [-t <threads>] [-o <outfile>] [-q]\n"
    "  -f <file>   file of target addresses (\"1...\") or 40-hex HASH160,\n"
    "              one per line; use \"-\" to read from stdin\n"
    "  -t <n>      number of worker threads (default: all cores)\n"
    "  -o <file>   append hits here (default: stdout)\n"
    "  -q          quiet: no periodic rate line on stderr\n"
    "  -h          this help\n\n"
    "Hits are written as:  Address: <addr> Privkey: <wif>\n"
    "No awk needed; matching happens in memory as keys are generated.\n",
    prog);
}

int main(int argc, char *argv[])
{
  const char *target_file = NULL, *out_file = NULL, *fixed_hex = NULL;
  int threads = 0, quiet = 0, opt;

  while((opt = getopt(argc, argv, "f:t:o:k:qh")) != -1) {
    switch(opt) {
      case 'f': target_file = optarg; break;
      case 't': threads = atoi(optarg); break;
      case 'o': out_file = optarg; break;
      case 'k': fixed_hex = optarg; break;
      case 'q': quiet = 1; break;
      case 'h': usage(argv[0]); return 0;
      default:  usage(argv[0]); return 1;
    }
  }
  if(fixed_hex) {
    /* parse up to 64 hex chars into the low bytes of a 32-byte big-endian seed */
    size_t hl = strlen(fixed_hex);
    if(hl > 64) die("-k: key too long");
    char pad[65];
    memset(pad, '0', 64 - hl);
    memcpy(pad + (64 - hl), fixed_hex, hl);
    pad[64] = 0;
    for(int i = 0; i < 32; i++) {
      int hi = hexval(pad[2*i]), lo = hexval(pad[2*i+1]);
      if(hi < 0 || lo < 0) die("-k: not hex");
      g_fixed_seed[i] = (hi << 4) | lo;
    }
    g_fixed_k0 = 1;
  }
  if(!target_file) { usage(argv[0]); return 1; }
  if(threads <= 0) {
    threads = get_nprocs();
    if(threads <= 0) threads = 1;
  }

  /* Pick the fastest available SHA-256 implementation. */
  sha256_register(0);

  h160set set;
  load_targets(&set, target_file);
  g_set = &set;

  out_fp = stdout;
  if(out_file && !(out_fp = fopen(out_file, "a")))
    die("cannot open output file: %s", out_file);

  signal(SIGINT,  on_signal);
  signal(SIGTERM, on_signal);

  fprintf(stderr, "[keygen] searching with %d thread(s), STEP=%d. "
                  "Ctrl-C to stop.\n", threads, STEP);

  pthread_t *tids = xmalloc(sizeof(pthread_t) * threads);
  thread_arg *args = xmalloc(sizeof(thread_arg) * threads);
  for(int i = 0; i < threads; i++) {
    args[i].id = i;
    if(pthread_create(&tids[i], NULL, engine, &args[i]) != 0)
      die("pthread_create failed");
  }
  pthread_t stats_tid = 0;
  if(!quiet) pthread_create(&stats_tid, NULL, stats_thread, NULL);

  for(int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
  g_stop = 1;
  if(stats_tid) pthread_join(stats_tid, NULL);

  fprintf(stderr, "\n[keygen] stopped: %" PRIu64 " keys tried, %" PRIu64 " hit(s).\n",
          (uint64_t)g_count, (uint64_t)g_hits);
  if(out_fp != stdout) fclose(out_fp);
  free(tids); free(args);
  return 0;
}
