// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <array>
#include <string>

#include <znet/z_crypto_backend.h>

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

  base::String GetPublicKey() const;
  base::String GetChallenge() const;

  void ProcessServerKey(const base::String& server_key, const base::String& server_challenge);

  bool VerifyServerResponse(const base::String& server_proof);
  bool VerifyClientProof(const base::String& client_proof);
  base::String GenerateClientProof();
  base::String GenerateServerProof();
  bool IsAuthenticated() const;

  bool EncryptPayload(const base::Span<byte>& plaintext,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& encrypted);

  bool DecryptPayload(const base::Span<byte>& encrypted,
                      const base::Span<byte>& aad,
                      base::Vector<byte>& plaintext);

 private:
  bool EnsureKeyMaterialReady();
  bool DeriveKeyMaterial(const base::String& secret);
  bool DeriveSessionKeys();

 private:
  base::Array<byte, 32> encryption_key_{};
  base::Array<byte, 32> authentication_key_{};
  bool keys_initialized_{false};
  bool authenticated_{false};
  base::String local_nonce_;
  base::String local_challenge_;
  base::String server_nonce_;
  base::String server_challenge_;
};

}  // namespace tx::network
