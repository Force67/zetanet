// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <cstring>
#include <string>

namespace tx::network {

class ZCryptoContext {
 public:
  ZCryptoContext() {}
  ~ZCryptoContext() {}

  void InitializeKeyExchange() {}

  std::string GetPublicKey() {
    return std::string();
  }

  void ProcessServerKey(const std::string& server_key) {}

  void EncryptPayload(unsigned char* data, size_t size) {}

  void DecryptPayload(unsigned char* data, size_t size) {}

 private:
  void SetAesKey(const unsigned char* key, size_t key_len) {}
};

}  // namespace tx::network
