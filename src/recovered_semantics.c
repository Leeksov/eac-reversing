/*
 * C-like semantic reconstruction of mac_arm64.decoded.
 *
 * This is analysis output, not a buildable replacement.  "verified" means
 * that the result was checked by differential Unicorn executions.  The four
 * Mbed TLS routines were additionally matched to the upstream 2.4.1 source.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PT_DENY_ATTACH = 31,
    P_TRACED = 0x800,
    IMAGE_FILE_MACHINE_I386 = 0x014c,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
};

/* 0x38B0 -- verified with 0, 1, 2 and UINT32_MAX. */
bool cv_u32_is_one(const void *unused, const uint32_t *value)
{
    (void)unused;
    return *value == 1;
}

/* 0x3D24 -- exact 0x4c-byte write and passthrough behavior verified. */
uintptr_t cv_validation_state_init(uintptr_t passthrough, void *state,
                                   uintptr_t unused)
{
    (void)unused;
    memset(state, 0, 0x4c);
    ((uint32_t *)state)[0] = 1;
    ((uint32_t *)state)[1] = 1;
    return passthrough;
}

/* 0x4E1D4 -- verified with a broad signed/unsigned value set. */
bool cv_field8_is_minus_one(const void *object,
                            const void *unused1,
                            const void *unused2)
{
    (void)unused1;
    (void)unused2;
    return *(const int32_t *)((const uint8_t *)object + 8) == -1;
}

/* 0x4A04, reached by export e.  The complete cfg key/value parser is large,
 * but success/failure and the localization-path contract were verified with
 * the real Rust en_us.cfg. */
bool cv_load_localization(void *launcher, const char *base_path,
                          const char *locale)
{
    string directory = join_path(base_path, "EasyAntiCheat/Localization");
    string selected = select_localization_cfg(directory, locale, "en_us");
    byte_vector contents;
    if (!read_file(selected.c_str(), &contents))
        return false;
    return parse_localization_table(launcher_localization_state(launcher),
                                    contents.data(), contents.size());
}

/* 0x52ED4 -- exact Darwin sysctl predicate.  Failure is fail-open. */
bool cv_is_not_traced_sysctl(void)
{
    int mib[4] = { 1 /* CTL_KERN */, 14 /* KERN_PROC */,
                   1 /* KERN_PROC_PID */, getpid() };
    struct kinfo_proc info = {0};
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0)
        return true;
    return (info.kp_proc.p_flag & P_TRACED) == 0;
}

/* 0x52B64 -- verified with several contents and memory-effect comparison. */
void cv_read_and_discard_tmp_eac_flag(void)
{
    int fd = open("/tmp/eac.flag", 0);
    if (fd >= 0) {
        char buffer[32] = {0};
        (void)read(fd, buffer, sizeof(buffer));
        close(fd);
    }
}

/* 0x52AE0 -- verified for traced/untraced and sysctl-failure models. */
bool cv_enable_anti_debug(void)
{
    if (!cv_is_not_traced_sysctl())
        return false;
    cv_read_and_discard_tmp_eac_flag();
    (void)ptrace(PT_DENY_ATTACH, 0, 0, 0);
    return true;
}

/* 0x52540 -- verified truth table. */
bool cv_init_anti_debug(bool bypass)
{
    if (bypass)
        return true;
    return cv_enable_anti_debug();
}

/* Native 0x542B4. */
bool cv_locate_pe_headers(const uint8_t *image, size_t image_size,
                          const void **out_dos, const void **out_nt)
{
    if (!image || image_size < 0x1000)
        return false;
    if (*(const uint16_t *)image != 0x5a4d) /* MZ */
        return false;
    uint32_t nt_offset = *(const uint32_t *)(image + 0x3c);
    if (!nt_offset || nt_offset > image_size || image_size - nt_offset < 248)
        return false;
    if (*(const uint32_t *)(image + nt_offset) != 0x00004550) /* PE\0\0 */
        return false;
    if (out_dos) *out_dos = image;
    if (out_nt)  *out_nt = image + nt_offset;
    return true;
}

/* 0x54AAC -- verified using invalid bytes, a real I386 PE and mutations of
 * IMAGE_FILE_HEADER.Machine to AMD64, ARM64 and an unknown value. */
bool cv_get_pe_bitness(const char *path, uint32_t *out_bits)
{
    uint8_t first_page[0x1000];
    size_t size = read_file_prefix(path, first_page, sizeof(first_page));
    const uint8_t *nt;
    *out_bits = 0;
    if (!cv_locate_pe_headers(first_page, size, NULL, (const void **)&nt))
        return false;
    switch (*(const uint16_t *)(nt + 4)) {
    case IMAGE_FILE_MACHINE_I386:
        *out_bits = 32;
        return true;
    case IMAGE_FILE_MACHINE_AMD64:
        *out_bits = 64;
        return true;
    default:
        return false;
    }
}

/* 0x548DC -- verified with an empty argument vector.  The protected routine
 * owns the final argv materialization; exact PE-specific argument rewriting
 * inside that materialization is still being classified. */
int cv_exec_target_with_args(const string *executable,
                             const string_vector *arguments)
{
    uint32_t pe_bits = 0;
    (void)cv_get_pe_bitness(executable->c_str(), &pe_bits);
    char_pointer_vector argv = {0};
    argv.push_back(executable->c_str());
    for (const string *it = arguments->begin; it != arguments->end; ++it)
        argv.push_back(it->c_str());
    argv.push_back(NULL);
    return execv(executable->c_str(), argv.data());
}

/* 0x4CD8 -- recovered call sequence. */
bool cv_prepare_child_process(void)
{
    unsetenv("DYLD_INSERT_LIBRARIES");
    for (int fd = 3; fd < 1024; ++fd)
        close(fd);
    (void)ptrace(PT_DENY_ATTACH, 0, 0, 0);
    return true;
}

/* 0x4D90 -- high-level reconstruction; serialization helper details omitted. */
bool cv_publish_embedded_image_shm(void *launcher, const void *metadata)
{
    char name[37];
    make_uuid_like_name(name);
    int fd = shm_open(name, 0x0a02, 035);
    if (fd < 0)
        return false;
    shm_unlink(name);
    uint8_t header[0x328];
    build_handoff_header(header, launcher, metadata);
    if (ftruncate(fd, 0x657e14) != 0)
        return false;
    uint8_t *mapping = mmap(NULL, 0x657e14, 3, 1, fd, 0);
    if (mapping == (void *)-1)
        return false;
    memcpy(mapping, header, sizeof(header));
    memcpy(mapping + sizeof(header), (const void *)0x57ce4, 0x657ae0);
    munmap(mapping, 0x657e14);
    (void)fcntl(fd, 1);
    return true;
}

/* 0x4E3A0 -- recovered call sequence and constants. */
void *cv_load_blob_as_temp_dylib(const void *data, size_t size)
{
    char path[/* implementation-owned temporary path */ 128];
    make_uuid_temp_path(path);
    int fd = open(path, /* O_WRONLY|O_CREAT|O_EXCL */ 0x1000601, 0x1d);
    if (fd < 0)
        return NULL;
    if (write(fd, data, size) != (long)size) {
        close(fd);
        unlink(path);
        return NULL;
    }
    (void)fchmod(fd, 0500);
    void *handle = dlopen(path, 1 /* RTLD_LAZY */);
    close(fd);
    unlink(path);
    return handle;
}

/* 0x4E324 -- verified with a modeled non-null dlopen handle. */
void *cv_load_blob_as_temp_dylib_adapter(const void *data, size_t size,
                                         const void *unused)
{
    (void)unused;
    return cv_load_blob_as_temp_dylib(data, size);
}

/* 0x532AC / 0x53850 / native 0x54170 form a safe foreign-image reader:
 * enumerate task VM regions, intersect a requested range with readable
 * regions, and only then copy/validate DOS and NT headers. */
bool cv_collect_vm_regions(void *out_regions);
size_t cv_readable_span_from_regions(const void *base, size_t length,
                                     const void *regions,
                                     void *out_intersections);
bool cv_parse_pe_headers_safely(const void *image, size_t image_size,
                                void *out_dos64, void *out_nt248);

/* 0x53CF0 -- verified with empty, matching and non-matching region vectors.
 * Each collected region record is 0x48 bytes and starts with start/end/size. */
size_t cv_copy_containing_vm_region(const void *address,
                                    const void *regions,
                                    void *out_bytes)
{
    byte_vector_clear(out_bytes);
    for (const region_record *r = regions_begin(regions);
         r != regions_end(regions); ++r) {
        if ((uintptr_t)address >= r->start && (uintptr_t)address < r->end) {
            byte_vector_assign(out_bytes, (const void *)r->start,
                               (const void *)r->end);
            return r->end - r->start;
        }
    }
    return 0;
}

/* Exact source matches: Mbed TLS 2.4.1 library/cipher.c and library/gcm.c. */
int mbedtls_cipher_update(void *ctx, const unsigned char *input, size_t ilen,
                          unsigned char *output, size_t *olen);       /* 0xF820 */
int mbedtls_gcm_starts(void *ctx, int mode, const unsigned char *iv,
                       size_t iv_len, const unsigned char *add,
                       size_t add_len);                              /* 0x20C10 */
int mbedtls_gcm_update(void *ctx, size_t length,
                       const unsigned char *input,
                       unsigned char *output);                       /* 0x210F4 */
int mbedtls_gcm_finish(void *ctx, unsigned char *tag,
                       size_t tag_len);                              /* 0x21420 */

/*
 * Activation pipeline (export a, 0x35E0 -> 0x420C) -- reconstructed from
 * offline Unicorn runs with the REAL Rust EAC files; see activation_flow.md
 * and runs/activation_{parent,child}_realfiles*.json.
 *
 * The configuration paths are built with MIXED separators:
 *   <launcher_dir>/EasyAntiCheat\Certificates\runtime.conf
 *   <launcher_dir>/EasyAntiCheat\Certificates\base.cer
 *
 * Differential outcomes (SOLE predicate is the file SIZE):
 *   runtime.conf >= 1108 B  -> success (callback 1002, fork, child execv);
 *                              a fully RANDOM 1108-byte file produces a
 *                              byte-identical step count -- content is
 *                              decoded by the VM byte-decoder (diffusion
 *                              keystream) but NEVER validated.
 *   runtime.conf < 1108 B   -> ABORT: callback(510, "Validation of the
 *                              anti-cheat configuration failed."), no fork
 *                              (sweep 511..1107 all fail, steps linear in size).
 *   runtime.conf empty/gone -> 0x3D84/0x3FB8 skipped, launch NOT blocked.
 *   base.cer zeroed/gone    -> full chain may run (content read) or be
 *                              skipped; certificate validity is NOT
 *                              load-bearing for the exec decision.
 *   Mbed TLS GCM/cipher     -> 0 executed instructions in every launcher
 *                              activation trace (service-side code only).
 * Decoded plaintext layout (recovered from write-effects): "EAC\0" magic,
 * 254-byte key blob, u32 0x02AB1EDA, 0x300 zero bytes, two u32 flags = 1.
 *
 * int cv_launcher_activate_v2(launcher, args_block)   // 0x420C
 * {
 *     if (!cv_init_anti_debug(bypass_flag)) { callback(510, ...); return 1; }
 *     if (!cv_load_validate_eac_configuration(launcher)) {
 *         callback(510, "Validation of the anti-cheat configuration failed.");
 *         return 1;                    // observed with malformed runtime.conf
 *     }
 *     callback(1002, progress);        // parent-only progress report
 *     if (fork() == 0) {               // 0x4848 child
 *         cv_prepare_child_process();   // unsetenv, close 3..1023, PT_DENY_ATTACH
 *         cv_publish_embedded_image_shm(launcher, metadata);
 *         cv_exec_target_with_args(executable, args);
 *     }
 *     report through callback; return 1;
 * }
 */

/* VM opcode families recovered in four independent dynamic dispatcher copies
 * and (23 more constants) by static extraction -- see vm_isa.md and
 * vm_opcode_table.json for the full 27-opcode inventory. */
uint64_t cv_width_load(uint8_t opcode, const void *address)
{
    switch (opcode) {
    case 0x5e: return *(const uint8_t  *)address;
    case 0xa3: return *(const uint16_t *)address;
    case 0xb9: return *(const uint32_t *)address;
    case 0xfd: return *(const uint64_t *)address;
    default:   return 0; /* not a member of this handler family */
    }
}
