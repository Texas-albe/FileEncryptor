// Vault snapshot / verify / restore
// File-level backup: copies .ptd + vault.meta + .feindex.d into a dest
// directory and writes a MANIFEST.sha256 (sha256sum format) that also
// records the source vault path for later restore.
#pragma once

#include <string>

// Snapshot vault_dir into dest_dir. Returns false with err set on failure.
bool vault_snapshot(const std::string& vault_dir, const std::string& dest_dir,
                    std::string& err);

// Verify every entry of MANIFEST.sha256 in snap_dir. Returns false when any
// file is missing or corrupted; err carries a short summary.
bool vault_snapshot_verify(const std::string& snap_dir, std::string& err);

// Restore snapshot at snap_dir back to the recorded source vault dir, or to
// vault_dir_override when non-empty. Never deletes files missing from the
// snapshot; a follow-up --vault-reindex folds orphan .ptd back into the index.
bool vault_snapshot_restore(const std::string& snap_dir,
                            const std::string& vault_dir_override,
                            std::string& err);
