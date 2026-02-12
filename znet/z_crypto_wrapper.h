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

  ZCryptoContext();
  ~ZCryptoContext();

  bool InitializeKeyExchange();

  std::string GetPublicKey() const;
  std::string GetChallenge() const;

  void ProcessServerKey(const std::string& server_key, const std::string& server_challenge);

  bool VerifyServerResponse(const std::string& server_proof);
  std::string GenerateClientProof();
  std::string GenerateServerProof();
  bool IsAuthenticated() const;

  bool EncryptPayload(const base::Span<byte>& plaintext,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& encrypted);

  bool DecryptPayload(const base::Span<byte>& encrypted,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& plaintext);

 private:
  bool EnsureKeyMaterialReady();
  bool DeriveKeyMaterial(const std::string& secret);

 private:
  std::array<byte, 32> encryption_key_{};
  std::array<byte, 32> authentication_key_{};
  bool keys_initialized_{false};
  bool authenticated_{false};
  std::string local_nonce_;
  std::string local_challenge_;
  std::string server_nonce_;
  std::string server_challenge_;
};

}  // namespace tx::network
