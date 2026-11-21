// Share a vault entry as a standalone .ptd for chosen recipients
// Plaintext never hits disk: pulled blockwise from the vault via vdisk
// random reads and streamed straight into encrypt_file (asym mode).
#pragma once

#include <string>
#include <vector>

// Read vpath from the unlocked vault and re-encrypt to out_ptd for the
// given recipients (X25519/X448/ML-KEM public keys as accepted by CLI).
bool vault_share_file(const std::string& vault_dir, const std::string& vpath,
                      const std::string& out_ptd, const std::string& vault_password,
                      const std::vector<std::string>& recipients, std::string& err);
