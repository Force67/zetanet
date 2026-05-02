// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_crypto_wrapper.h"

#include <cstring>

#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#else
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#endif

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-crypto";

bool Sha256(const byte* data, mem_size size, base::Array<byte, 32>& out_hash) {
#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  const int starts_result = mbedtls_sha256_starts(&ctx, 0);
  const int update_result =
      starts_result == 0 ? mbedtls_sha256_update(&ctx, data, size) : -1;
  const int finish_result =
      update_result == 0 ? mbedtls_sha256_finish(&ctx, out_hash.data()) : -1;
  mbedtls_sha256_free(&ctx);
  return starts_result == 0 && update_result == 0 && finish_result == 0;
#else
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    return false;
  }

  bool success = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                 EVP_DigestUpdate(ctx, data, size) == 1;

  unsigned int hash_len = 0;
  success = success &&
            EVP_DigestFinal_ex(ctx, out_hash.data(), &hash_len) == 1 &&
            hash_len == out_hash.size();
  EVP_MD_CTX_free(ctx);
  return success;
#endif
}

base::String BytesToHex(const byte* data, mem_size size) {
  constexpr char kHex[] = "0123456789abcdef";
  base::String out(size * 2, '0');
  for (mem_size i = 0; i < size; ++i) {
    out[2 * i] = kHex[(data[i] >> 4) & 0x0F];
    out[2 * i + 1] = kHex[data[i] & 0x0F];
  }
  return out;
}

bool HmacSha256(const byte* key, mem_size key_size,
                const byte* data, mem_size data_size,
                base::Array<byte, 32>& out_mac) {
#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) {
    return false;
  }
  return mbedtls_md_hmac(info, key, key_size, data, data_size, out_mac.data()) ==
         0;
#else
  unsigned int mac_len = 0;
  if (!HMAC(EVP_sha256(), key, static_cast<int>(key_size),
            data, data_size, out_mac.data(), &mac_len)) {
    return false;
  }
  return mac_len == out_mac.size();
#endif
}

bool ConstantTimeEquals(const base::String& lhs, const base::String& rhs) {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  unsigned char diff = 0;
  for (mem_size i = 0; i < lhs.size(); ++i) {
    diff |= static_cast<unsigned char>(lhs[i]) ^
            static_cast<unsigned char>(rhs[i]);
  }
  return diff == 0;
}

bool RandomBytes(byte* out, mem_size size) {
#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  constexpr char kPersonalization[] = "znet-crypto";
  int result = mbedtls_ctr_drbg_seed(
      &ctr_drbg, mbedtls_entropy_func, &entropy,
      reinterpret_cast<const byte*>(kPersonalization),
      sizeof(kPersonalization) - 1);
  if (result == 0) {
    result = mbedtls_ctr_drbg_random(&ctr_drbg, out, size);
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return result == 0;
#else
  return RAND_bytes(out, static_cast<int>(size)) == 1;
#endif
}
}  // namespace

ZCryptoContext::ZCryptoContext() = default;
ZCryptoContext::~ZCryptoContext() = default;

void ZCryptoContext::SetPreSharedKey(const base::StringRef& secret) {
  if (secret.empty()) {
    pre_shared_key_.clear();
  } else {
    pre_shared_key_.assign(secret.data(), secret.size());
  }
  keys_initialized_ = false;
  authenticated_ = false;
}

bool ZCryptoContext::InitializeKeyExchange() {
  if (keys_initialized_) {
    return true;
  }

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  byte local_nonce[32]{};
  if (!RandomBytes(local_nonce, sizeof(local_nonce))) {
    BASE_LOGE(kLogTag, "Failed to generate local key exchange nonce");
    return false;
  }
  local_nonce_ = BytesToHex(local_nonce, sizeof(local_nonce));
  
  byte local_challenge[16]{};
  if (!RandomBytes(local_challenge, sizeof(local_challenge))) {
    BASE_LOGE(kLogTag, "Failed to generate local challenge");
    return false;
  }
  local_challenge_ = BytesToHex(local_challenge, sizeof(local_challenge));

  // Seed nonce domain for any early encryption before the full handshake.
  u32 initial_prefix = 0;
  if (!RandomBytes(reinterpret_cast<byte*>(&initial_prefix),
                   sizeof(initial_prefix))) {
    BASE_LOGE(kLogTag, "Failed to initialize nonce prefix");
    return false;
  }
  if (initial_prefix == 0) {
    initial_prefix = 1;
  }
  nonce_prefix_.store(initial_prefix, std::memory_order_relaxed);
  nonce_counter_.store(0, std::memory_order_relaxed);
  
  return true;
}

base::String ZCryptoContext::GetPublicKey() const {
  return local_nonce_;
}

base::String ZCryptoContext::GetChallenge() const {
  return local_challenge_;
}

void ZCryptoContext::ProcessServerKey(const base::String& server_key, const base::String& server_challenge) {
  server_nonce_ = server_key;
  server_challenge_ = server_challenge;
  DeriveSessionKeys();
}

bool ZCryptoContext::VerifyServerResponse(const base::String& server_proof) {
  if (server_nonce_.empty() || server_challenge_.empty() || local_nonce_.empty() || local_challenge_.empty()) {
    BASE_LOGE(kLogTag, "Key exchange not completed");
    return false;
  }
  
  base::String verify_data = local_nonce_ + server_nonce_ + local_challenge_ + server_challenge_;
  base::Array<byte, 32> expected_proof{};
  if (!HmacSha256(encryption_key_.data(), encryption_key_.size(),
                  reinterpret_cast<const byte*>(verify_data.data()), verify_data.size(),
                  expected_proof)) {
    BASE_LOGE(kLogTag, "Failed to compute expected proof");
    return false;
  }
  
  base::String expected_proof_hex = BytesToHex(expected_proof.data(), expected_proof.size());
  if (!ConstantTimeEquals(expected_proof_hex, server_proof)) {
    BASE_LOGE(kLogTag, "Server proof verification failed");
    return false;
  }
  
  authenticated_ = true;
  return true;
}

base::String ZCryptoContext::GenerateClientProof() {
  if (server_nonce_.empty() || server_challenge_.empty() || local_nonce_.empty() || local_challenge_.empty()) {
    BASE_LOGE(kLogTag, "Key exchange not completed");
    return "";
  }
  
  base::String verify_data = server_nonce_ + local_nonce_ + server_challenge_ + local_challenge_;
  base::Array<byte, 32> proof{};
  if (!HmacSha256(encryption_key_.data(), encryption_key_.size(),
                  reinterpret_cast<const byte*>(verify_data.data()), verify_data.size(),
                  proof)) {
    BASE_LOGE(kLogTag, "Failed to generate client proof");
    return "";
  }
  
  return BytesToHex(proof.data(), proof.size());
}

bool ZCryptoContext::EncryptPayload(const base::Span<byte>& plaintext,
                                    const base::Span<byte>& aad,
                                    base::Vector<byte>& encrypted) {
  encrypted.clear();

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  // Use a per-session/domain prefix + packet counter for fast unique nonces.
  byte nonce[12]{};
  const u32 nonce_prefix = nonce_prefix_.load(std::memory_order_relaxed);
  u64 counter = nonce_counter_.fetch_add(1, std::memory_order_relaxed);
  std::memcpy(nonce, &nonce_prefix, sizeof(nonce_prefix));
  std::memcpy(nonce + sizeof(nonce_prefix), &counter, sizeof(counter));

  const mem_size tag_size = kGcmTagSize;
  const mem_size ciphertext_size = plaintext.size();

  encrypted.resize(sizeof(nonce) + ciphertext_size + tag_size);
  std::memcpy(encrypted.data(), nonce, sizeof(nonce));

  if (plaintext.empty()) {
    encrypted.clear();
    BASE_LOGE(kLogTag, "Empty plaintext");
    return false;
  }

#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int result = mbedtls_gcm_setkey(
      &gcm, MBEDTLS_CIPHER_ID_AES, encryption_key_.data(),
      static_cast<unsigned int>(encryption_key_.size() * 8));
  if (result == 0) {
    result = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), nonce, sizeof(nonce),
        aad.data(), aad.size(), plaintext.data(), encrypted.data() + sizeof(nonce),
        tag_size, encrypted.data() + sizeof(nonce) + ciphertext_size);
  }
  mbedtls_gcm_free(&gcm);

  if (result != 0) {
    encrypted.clear();
    BASE_LOGE(kLogTag, "AES-GCM encryption failed ({})", result);
    return false;
  }
#else
  // Reuse a thread-local EVP context to avoid per-packet allocation.
  // Wrapped in a struct so the destructor frees it on thread exit.
  struct TlEvpCtx {
    EVP_CIPHER_CTX* ctx = nullptr;
    TlEvpCtx() { ctx = EVP_CIPHER_CTX_new(); }
    ~TlEvpCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
  };
  static thread_local TlEvpCtx tl;
  if (!tl.ctx) {
    encrypted.clear();
    return false;
  }
  EVP_CIPHER_CTX* ctx = tl.ctx;

  int out_len = 0;
  int final_len = 0;

  bool success =
      EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr) ==
          1 &&
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), nonce) ==
          1;

  if (success && !aad.empty()) {
    success = EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(),
                                static_cast<int>(aad.size())) == 1;
  }

  if (success) {
    success = EVP_EncryptUpdate(ctx, encrypted.data() + sizeof(nonce), &out_len,
                                plaintext.data(),
                                static_cast<int>(plaintext.size())) == 1;
  }

  if (success) {
    success = EVP_EncryptFinal_ex(ctx, encrypted.data() + sizeof(nonce) + out_len,
                                  &final_len) == 1;
  }

  if (success) {
    success = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size,
                                  encrypted.data() + sizeof(nonce) +
                                      ciphertext_size) == 1;
  }

  if (!success) {
    encrypted.clear();
    BASE_LOGE(kLogTag, "AES-GCM encryption failed");
    return false;
  }
#endif

  return true;
}

bool ZCryptoContext::DecryptPayload(const base::Span<byte>& encrypted_data,
                                    const base::Span<byte>& aad,
                                    base::Vector<byte>& plaintext) {
  plaintext.clear();

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  const mem_size nonce_size = 12;
  const mem_size tag_size = kGcmTagSize;
  
  if (encrypted_data.size() < nonce_size + tag_size) {
    BASE_LOGE(kLogTag, "Encrypted payload too short");
    return false;
  }
  
  const byte* nonce = encrypted_data.data();
  const mem_size ciphertext_size = encrypted_data.size() - nonce_size - tag_size;
  const byte* ciphertext = encrypted_data.data() + nonce_size;
  const byte* tag = encrypted_data.data() + nonce_size + ciphertext_size;
  
  if (ciphertext_size == 0) {
    BASE_LOGE(kLogTag, "Empty ciphertext");
    return false;
  }
  
  plaintext.resize(ciphertext_size);

#if defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int result = mbedtls_gcm_setkey(
      &gcm, MBEDTLS_CIPHER_ID_AES, encryption_key_.data(),
      static_cast<unsigned int>(encryption_key_.size() * 8));
  if (result == 0) {
    result = mbedtls_gcm_auth_decrypt(
        &gcm, ciphertext_size, nonce, nonce_size, aad.data(), aad.size(), tag,
        tag_size, ciphertext, plaintext.data());
  }
  mbedtls_gcm_free(&gcm);

  if (result != 0) {
    plaintext.clear();
    BASE_LOGE(kLogTag, "AES-GCM decryption/authentication failed ({})", result);
    return false;
  }
#else
  // Reuse a thread-local EVP context to avoid per-packet allocation.
  // Wrapped in a struct so the destructor frees it on thread exit.
  struct TlEvpCtx {
    EVP_CIPHER_CTX* ctx = nullptr;
    TlEvpCtx() { ctx = EVP_CIPHER_CTX_new(); }
    ~TlEvpCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
  };
  static thread_local TlEvpCtx tl;
  if (!tl.ctx) {
    plaintext.clear();
    return false;
  }
  EVP_CIPHER_CTX* ctx = tl.ctx;

  bool success =
      EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) == 1 &&
      EVP_DecryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), nonce) ==
          1;

  int aad_len = 0;
  if (success && !aad.empty()) {
    success = EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad.data(),
                                static_cast<int>(aad.size())) == 1;
  }

  int out_len = 0;
  if (success) {
    success = EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext,
                                static_cast<int>(ciphertext_size)) == 1;
  }

  if (success) {
    success = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size,
                                  const_cast<byte*>(tag)) == 1;
  }

  int final_len = 0;
  if (success) {
    success = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) ==
              1;
  }

  if (!success) {
    plaintext.clear();
    BASE_LOGE(kLogTag, "AES-GCM decryption/authentication failed");
    return false;
  }

  plaintext.resize(static_cast<mem_size>(out_len + final_len));
#endif

  return true;
}

bool ZCryptoContext::IsAuthenticated() const {
  return authenticated_;
}

base::String ZCryptoContext::GenerateServerProof() {
  if (server_nonce_.empty() || server_challenge_.empty() || local_nonce_.empty() || local_challenge_.empty()) {
    BASE_LOGE(kLogTag, "Key exchange not completed");
    return "";
  }
  
  base::String verify_data = server_nonce_ + local_nonce_ + server_challenge_ + local_challenge_;
  base::Array<byte, 32> proof{};
  if (!HmacSha256(encryption_key_.data(), encryption_key_.size(),
                  reinterpret_cast<const byte*>(verify_data.data()), verify_data.size(),
                  proof)) {
    BASE_LOGE(kLogTag, "Failed to generate server proof");
    return "";
  }
  
  return BytesToHex(proof.data(), proof.size());
}

bool ZCryptoContext::VerifyClientProof(const base::String& client_proof) {
  if (server_nonce_.empty() || local_nonce_.empty()) {
    BASE_LOGE(kLogTag, "Key exchange not completed");
    return false;
  }

  // Client computes proof as: HMAC(server_nonce + local_nonce + server_challenge + local_challenge)
  // From the server's perspective, server_nonce_ is the client's nonce, local_nonce_ is the server's nonce
  // The client's GenerateClientProof uses: server_nonce_ + local_nonce_ + server_challenge_ + local_challenge_
  // From the server's perspective (where ProcessServerKey stored client data into server_nonce_/server_challenge_):
  //   client's server_nonce_ = our local_nonce_
  //   client's local_nonce_ = our server_nonce_
  //   client's server_challenge_ = our local_challenge_
  //   client's local_challenge_ = our server_challenge_
  // So expected: local_nonce_ + server_nonce_ + local_challenge_ + server_challenge_
  base::String verify_data = local_nonce_ + server_nonce_ + local_challenge_ + server_challenge_;
  base::Array<byte, 32> expected_proof{};
  if (!HmacSha256(encryption_key_.data(), encryption_key_.size(),
                  reinterpret_cast<const byte*>(verify_data.data()), verify_data.size(),
                  expected_proof)) {
    BASE_LOGE(kLogTag, "Failed to compute expected client proof");
    return false;
  }

  base::String expected_proof_hex = BytesToHex(expected_proof.data(), expected_proof.size());
  if (!ConstantTimeEquals(expected_proof_hex, client_proof)) {
    BASE_LOGE(kLogTag, "Client proof verification failed");
    return false;
  }

  authenticated_ = true;
  return true;
}

bool ZCryptoContext::DeriveSessionKeys() {
  if (local_nonce_.empty() || server_nonce_.empty()) {
    return false;
  }

  // Sort nonces lexicographically so both sides derive the same keys
  base::String first_nonce, second_nonce;
  if (local_nonce_ < server_nonce_) {
    first_nonce = local_nonce_;
    second_nonce = server_nonce_;
  } else {
    first_nonce = server_nonce_;
    second_nonce = local_nonce_;
  }

  // Derive new encryption key: SHA-256(current_enc_key + sorted_nonces)
  base::String enc_input(reinterpret_cast<const char*>(encryption_key_.data()),
                        encryption_key_.size());
  enc_input += first_nonce + second_nonce + "session-enc";
  base::Array<byte, 32> new_enc_key{};
  if (!Sha256(reinterpret_cast<const byte*>(enc_input.data()), enc_input.size(),
              new_enc_key)) {
    return false;
  }

  // Derive new authentication key: SHA-256(current_auth_key + sorted_nonces)
  base::String auth_input(reinterpret_cast<const char*>(authentication_key_.data()),
                         authentication_key_.size());
  auth_input += first_nonce + second_nonce + "session-auth";
  base::Array<byte, 32> new_auth_key{};
  if (!Sha256(reinterpret_cast<const byte*>(auth_input.data()), auth_input.size(),
              new_auth_key)) {
    return false;
  }

  // Derive per-direction nonce prefix so peers using the same session key
  // never reuse the same GCM nonce space.
  base::String nonce_input = first_nonce + second_nonce + "session-nonce-domain";
  base::Array<byte, 32> nonce_hash{};
  if (!Sha256(reinterpret_cast<const byte*>(nonce_input.data()),
              nonce_input.size(), nonce_hash)) {
    return false;
  }
  u32 nonce_prefix = 0;
  std::memcpy(&nonce_prefix, nonce_hash.data(), sizeof(nonce_prefix));
  const bool local_first =
      (local_nonce_ < server_nonce_) ||
      (local_nonce_ == server_nonce_ && local_challenge_ < server_challenge_);
  const u32 direction_tag = local_first ? 0xA5A5A5A5u : 0x5A5A5A5Au;
  nonce_prefix ^= direction_tag;
  if (nonce_prefix == 0) {
    nonce_prefix = direction_tag;
  }

  encryption_key_ = new_enc_key;
  authentication_key_ = new_auth_key;
  nonce_prefix_.store(nonce_prefix, std::memory_order_relaxed);
  nonce_counter_.store(0, std::memory_order_relaxed);
  return true;
}

bool ZCryptoContext::EnsureKeyMaterialReady() {
  if (keys_initialized_) {
    return true;
  }

  if (pre_shared_key_.empty()) {
    BASE_LOGE(kLogTag,
              "A pre-shared key is required when encryption is enabled");
    return false;
  }
  if (pre_shared_key_.size() < 16) {
    BASE_LOGE(kLogTag, "Pre-shared key must be at least 16 characters");
    return false;
  }
  if (!DeriveKeyMaterial(pre_shared_key_)) {
    BASE_LOGE(kLogTag, "Failed to derive encryption and auth key material");
    return false;
  }
  keys_initialized_ = true;
  return true;
}

bool ZCryptoContext::DeriveKeyMaterial(const base::String& secret) {
  base::Array<byte, 32> master_key{};
  if (!Sha256(reinterpret_cast<const byte*>(secret.data()), secret.size(),
              master_key)) {
    return false;
  }

  base::Vector<byte> enc_seed(3 + master_key.size());
  enc_seed[0] = 'e';
  enc_seed[1] = 'n';
  enc_seed[2] = 'c';
  std::memcpy(enc_seed.data() + 3, master_key.data(), master_key.size());
  if (!Sha256(enc_seed.data(), enc_seed.size(), encryption_key_)) {
    return false;
  }

  base::Vector<byte> auth_seed(4 + master_key.size());
  auth_seed[0] = 'a';
  auth_seed[1] = 'u';
  auth_seed[2] = 't';
  auth_seed[3] = 'h';
  std::memcpy(auth_seed.data() + 4, master_key.data(), master_key.size());
  return Sha256(auth_seed.data(), auth_seed.size(), authentication_key_);
}

}  // namespace tx::network
