/*
 * EAC In-Game Service: start_service (export _x) — Decompiled from effect trace
 *
 * Source: 6.7M instruction Unicorn trace of eac_service_decoded.dylib
 * Method: effect-level decompilation (observable import calls with arguments)
 * Date: 2026-08-20
 *
 * The service is protected by Code Virtualizer with 247 handler entries,
 * each handler ~100K obfuscated ARM64 instructions. This decompilation
 * captures the BEHAVIOR, not the obfuscated instruction stream.
 */

#include <stdint.h>
#include <pthread.h>
#include <mach/mach.h>

// ── Service context: 0x2B20 (11040) bytes ──────────────────────────
typedef struct {
    // 0x000: vtable pointer (set by init to off_B42A8)
    void *vtable;

    // 0x028..0x470: padding / internal state
    uint8_t _pad0[0x428 - 8];

    // 0x428: three 16-byte state blocks (zeroed on init)
    uint8_t state_block_a[0x10];     // +0x428
    uint8_t state_block_b[0x20];     // +0x43C
    uint8_t state_block_c[0x10];     // +0x45C

    // 0x478: channel state A (416 bytes, zeroed on init + reinit)
    uint8_t channel_state_a[0x1A0];  // +0x478

    // 0x618: crypto buffer (1024 bytes)
    uint8_t crypto_buf[0x400];       // +0x618

    // 0xA18: hash catalogue state (344 bytes)
    uint8_t hash_catalogue[0x158];   // +0xA18

    // 0xB70: integrity state (336 bytes)
    uint8_t integrity_state[0x150];  // +0xB70

    // 0xCC0: detection state (248 bytes)
    uint8_t detection_state[0xF8];   // +0xCC0

    // 0xDB8: main mutex
    pthread_mutex_t main_mutex;      // +0xDB8

    // 0xE00..0x1790: channel state B (mirror of A for second channel)
    uint8_t channel_b[0x990];

    // 0x1790: channel B mutex
    pthread_mutex_t channel_b_mutex;

    // 0x1830: session mutex
    pthread_mutex_t session_mutex;
    // 0x1890: session state mutex
    pthread_mutex_t session_state_mutex;

    // 0x1A10: crypto mutex
    pthread_mutex_t crypto_mutex;

    // 0x1A50..0x2F20: worker queues, condition variables, more mutexes
    // (52 mutexes total, 14 condition variables, 5 worker queues)

} eac_service_ctx_t;


// ── DH parameters (hardcoded in .rodata) ───────────────────────────
static const char DH_PRIME[] =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234"
    "C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7ED"     // RFC 3526 Group 14
    "...";                                   // truncated
static const char DH_GENERATOR[] = "02";


// ── Decompiled start_service (_x export) ───────────────────────────

int eac_start_service(eac_v1_args_t *args, uint32_t args_size) {

    // ── 1. Validate arguments ──────────────────────────────────────
    if (args_size < 0x14) return error;
    if (args->version > 2) return error;
    if (args->size != args_size) return error;
    if (args->flags != 1) return error;

    // One-shot guard: casalb on global flag, reject if already started
    if (atomic_cas(&g_started, 0, 1) != 0) return error;

    // ── 2. Allocate service context ────────────────────────────────
    eac_service_ctx_t *ctx = new eac_service_ctx_t;  // 0x2B20 bytes
    service_ctx_init(ctx);  // sets vtable, inits sub-objects
    g_service_ctx = ctx;    // singleton at qword_C1278

    // Store callback from args
    ctx->callback = args->callback;  // args+0xC

    // ── 3. Initialize channel A (main channel) ─────────────────────
    pthread_mutex_lock(&ctx->main_mutex);

    // Clear all channel state
    memset(&ctx->channel_state_a, 0, 0x1A0);
    memset(&ctx->crypto_buf, 0, 0x400);
    memset(&ctx->hash_catalogue, 0, 0x158);
    memset(&ctx->integrity_state, 0, 0x150);
    memset(&ctx->detection_state, 0, 0xF8);
    memset(&ctx->state_block_a, 0, 0x10);
    memset(&ctx->state_block_b, 0, 0x20);
    memset(&ctx->state_block_c, 0, 0x10);
    bzero(&ctx->crypto_buf, 0x400);

    // ── 4. Seed CSPRNG from /dev/urandom ───────────────────────────
    FILE *f = fopen("/dev/urandom", "rb");
    uint8_t random_seed[128];
    fread(random_seed, 1, 128, f);
    fclose(f);

    // ── 5. Initialize Diffie-Hellman key exchange ──────────────────
    // Copy static DH base point (0x70 bytes from rodata 0xAAEA0)
    memcpy(dh_params, DH_BASE_POINT, 0x70);
    memcpy(dh_iv, initial_vector, 0x10);

    // Build session key material from random seed + timestamps
    memcpy(ctx->crypto_buf + 0x50, random_seed, 2);    // nonce prefix
    memcpy(ctx->crypto_buf + 0x52, random_seed + 0x80, 64);  // random block

    gettimeofday(&timestamp, NULL);

    // More key material assembly
    memcpy(ctx->crypto_buf + 0x92, random_seed, 2);     // nonce
    memcpy(ctx->crypto_buf + 0x94, random_seed, 8);     // seed fragment
    memcpy(ctx->crypto_buf + 0x9C, DH_BASE_POINT, 0x24); // curve params
    memcpy(ctx->crypto_buf + 0xC0, derived_key, 0x10);  // derived

    // Compute session ECDH shared secret
    // (multiple rounds of memcpy + XOR with DH params)

    // ── 6. Parse DH prime and generator as bignums ─────────────────
    // Prime: RFC 3526 Group 14 (2048-bit MODP)
    size_t prime_len = strlen(DH_PRIME);     // 96 hex chars
    uint32_t *prime_bn = calloc(64, 4);      // 256 bytes bignum
    parse_bignum(DH_PRIME, prime_bn);

    size_t gen_len = strlen(DH_GENERATOR);   // "02"
    uint32_t *gen_bn = calloc(1, 4);
    parse_bignum(DH_GENERATOR, gen_bn);

    // Compute DH public key
    uint32_t *pubkey = calloc(32, 4);        // 128 bytes
    uint32_t *privkey = calloc(1, 4);
    // modpow(gen_bn, privkey, prime_bn) → pubkey

    pthread_mutex_unlock(&ctx->main_mutex);

    // ── 7. Initialize channel B (identical structure) ──────────────
    pthread_mutex_lock(&ctx->channel_b_mutex);
    // ... same init sequence as channel A ...
    // fopen("/dev/urandom"), fread(128), fclose()
    // DH key generation for second channel
    pthread_mutex_unlock(&ctx->channel_b_mutex);

    // ── 8. Acquire session state ───────────────────────────────────
    pthread_mutex_lock(&ctx->session_state_mutex);
    pthread_mutex_unlock(&ctx->session_state_mutex);
    pthread_mutex_lock(&ctx->session_mutex);
    pthread_mutex_unlock(&ctx->session_mutex);

    // ── 9. Initialize timing subsystem (once) ──────────────────────
    static bool timing_initialized = false;  // guard at 0xBEBC0
    if (!timing_initialized) {
        timing_initialized = true;

        pthread_mutex_lock(&ctx->timing_mutex);
        pthread_mutex_unlock(&ctx->timing_mutex);

        auto now = steady_clock::now();

        // Initialize worker subsystems
        // Each worker: 3 mutexes + 1 cond + state
    }

    // ── 10. Initialize worker threads ──────────────────────────────
    // Creates 10 worker queue pairs, each with:
    //   - 3 mutexes (work, state, sync)
    //   - 1 condition variable
    //   - state buffer
    // Total: 52 mutexes, 14 cond vars across all workers

    for (int i = 0; i < 10; i++) {
        init_worker_queue(&ctx->workers[i]);
    }

    // Signal all workers ready
    pthread_mutex_lock(&ctx->worker_sync);
    pthread_cond_broadcast(&ctx->worker_cond);
    pthread_mutex_unlock(&ctx->worker_sync);

    // ── 11. Store product/sandbox/deployment IDs ───────────────────
    // Copy GUIDs from args block into service context
    string product_id;
    product_id.assign(args->guids[0]);   // "429c2212ad284866aee071454c2125b5"

    string sandbox_id;
    sandbox_id.assign(args->guids[1]);   // "ec47bae0651a4765a063c1e83ec41b34"

    string deployment_id;
    deployment_id.assign(args->guids[2]); // "76796531e86443548754600511f42e9e"

    // Store into global service state
    g_product_id = product_id;
    g_sandbox_id = sandbox_id;
    g_deployment_id = deployment_id;

    // ── 12. Format client identifier string ────────────────────────
    char client_id[37];
    vsnprintf(client_id, 37, "%s", ...);  // likely formats PID or GUID
    g_client_id = client_id;

    // Store IDs into worker state
    pthread_mutex_lock(&ctx->id_mutex);
    ctx->worker_product_id = product_id;
    ctx->worker_sandbox_id = sandbox_id;
    ctx->worker_deployment_id = deployment_id;
    ctx->worker_client_id = client_id;
    // ... more string copies for other subsystems ...
    pthread_mutex_unlock(&ctx->id_mutex);

    // ── 13. Get game name and build system info ────────────────────
    size_t game_len = strlen(args->guids[4]);  // "Rust"
    memcpy(game_name, args->guids[4], game_len);

    // Copy launch parameters (76 bytes from args+0x2DC)
    memcpy(ctx->launch_params, args->launch_data, 0x4C);

    // ── 14. Collect system fingerprint ─────────────────────────────
    pid_t pid = getpid();

    // Count HID input events (anti-automation check)
    uint32_t input_count = CGEventSourceCounterForEventType(
        kCGEventSourceStateHIDSystemState,  // 1
        5                                    // event type
    );

    gettimeofday(&system_time, NULL);

    // ── 15. Build telemetry/fingerprint buffer ─────────────────────
    // Assemble: PID + input_count + timestamp + random nonces
    // into a buffer for the initial server handshake
    memcpy(fingerprint, system_info, 7);
    memcpy(fingerprint + 8, machine_id, 7);

    // Allocate growing vector for fingerprint data
    void *fp_buf = new(8);
    void *fp_buf2 = new(16);
    memcpy(fp_buf2, fp_buf, 8);
    delete fp_buf;

    void *fp_buf3 = new(32);
    memcpy(fp_buf3, fp_buf2, 16);
    delete fp_buf2;

    // ── 16. Check environment ──────────────────────────────────────
    char *env = getenv(...);  // likely checks for debug/VM environment vars

    // ── 17. Return ─────────────────────────────────────────────────
    // Loads return code from [x21 + 0xC50] (global status word)
    return g_status;
}
