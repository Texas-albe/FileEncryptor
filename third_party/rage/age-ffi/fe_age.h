#ifndef FE_AGE_H
#define FE_AGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * C-ABI interface to the fe_age Rust static library (wrapper around rage/age).
 * All functions are panic-safe; on error they return 1 and (where applicable)
 * write an error message into *err_out. The caller must free any returned
 * string (pub_out, priv_out, *err_out) with fe_age_free_string().
 *
 * Strings are UTF-8. Paths are UTF-8 on every platform (the Rust side opens
 * them with the wide/UTF-8 aware std::fs APIs).
 */

/* Free a string returned by this library. Passing NULL is safe. */
void fe_age_free_string(char* s);

/* Returns the FFI crate version (matches the wrapped `age` version). Caller frees. */
char* fe_age_get_version(void);

/*
 * Generate an X25519 keypair.
 *   *pub_out  <- recipient string  ("age1...")      (freed by caller)
 *   *priv_out <- identity string   ("AGE-SECRET-KEY-...") (freed by caller)
 * Returns 0 on success, 1 on error.
 */
int fe_age_generate_keypair(char** pub_out, char** priv_out);

/*
 * Encrypt in_path -> out_path for the given recipients (hybrid: random file key
 * wrapped to each X25519 recipient). recipients is an array of `recipients_len`
 * NUL-terminated recipient strings (may contain "age1..." or "publickey: age1...").
 * Returns 0 on success, 1 on error (message in *err_out, freed by caller).
 */
int fe_age_encrypt_file(const char* const* recipients,
                        size_t recipients_len,
                        const char* in_path,
                        const char* out_path,
                        char** err_out);

/*
 * Decrypt in_path -> out_path using the given identities. identities is an array
 * of `identities_len` NUL-terminated identity strings ("AGE-SECRET-KEY-..." or
 * "identity: AGE-SECRET-KEY-...").
 * Returns 0 on success, 1 on error (message in *err_out, freed by caller).
 */
int fe_age_decrypt_file(const char* const* identities,
                        size_t identities_len,
                        const char* in_path,
                        const char* out_path,
                        char** err_out);

#ifdef __cplusplus
}
#endif

#endif /* FE_AGE_H */
