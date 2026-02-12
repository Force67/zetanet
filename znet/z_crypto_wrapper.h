// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <array>
#include <string>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/arch.h>
#include <base/containers/vector.h>
#include <base/containers/span.h>
#endif

namespace tx::network {

class ZCryptoContext {
 public:
  static constexpr mem_size kNonceSize = 12;
  static constexpr mem_size kAuthTagSize = 32;

  ZCryptoContext();
  ~ZCryptoContext();

  bool InitializeKeyExchange();

  std::string GetPublicKey() const;

  void ProcessServerKey(const std::string& server_key);

  bool EncryptPayload(const base::Span<byte>& plaintext,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& encrypted);

  bool DecryptPayload(const base::Span<byte>& encrypted,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& plaintext);

 private:
  bool EnsureKeyMaterialReady();
  bool DeriveKeyMaterial(const std::string& secret);
  bool EncryptAesCtr(const byte* input,
                     mem_size input_size,
                     const byte* nonce,
                     base::Vector<byte>& output);
  bool DecryptAesCtr(const byte* input,
                     mem_size input_size,
                     const byte* nonce,
                     base::Vector<byte>& output);
  bool ComputeHmac(const byte* data,
                   mem_size size,
                   base::Vector<byte>& out_tag) const;

 private:
  std::array<byte, 32> encryption_key_{};
  std::array<byte, 32> authentication_key_{};
  bool keys_initialized_{false};
  std::string local_public_key_;
  std::string server_public_key_;
};

}  // namespace tx::network
