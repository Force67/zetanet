// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_crypto_wrapper.h"

#include <cstring>
#include <cstdlib>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-crypto";

bool Sha256(const byte* data, mem_size size, base::Array<byte, 32>& out_hash) {
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
  unsigned int mac_len = 0;
  if (!HMAC(EVP_sha256(), key, static_cast<int>(key_size),
            data, data_size, out_mac.data(), &mac_len)) {
    return false;
  }
  return mac_len == out_mac.size();
}
}  // namespace

ZCryptoContext::ZCryptoContext() = default;
ZCryptoContext::~ZCryptoContext() = default;

bool ZCryptoContext::InitializeKeyExchange() {
  if (keys_initialized_) {
    return true;
  }

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  byte local_nonce[32]{};
  if (RAND_bytes(local_nonce, sizeof(local_nonce)) != 1) {
    BASE_LOGE(kLogTag, "Failed to generate local key exchange nonce");
    return false;
  }
  local_nonce_ = BytesToHex(local_nonce, sizeof(local_nonce));
  
  byte local_challenge[16]{};
  if (RAND_bytes(local_challenge, sizeof(local_challenge)) != 1) {
    BASE_LOGE(kLogTag, "Failed to generate local challenge");
    return false;
  }
  local_challenge_ = BytesToHex(local_challenge, sizeof(local_challenge));
  
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
  if (expected_proof_hex != server_proof) {
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

  byte nonce[12]{};
  if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
    BASE_LOGE(kLogTag, "Failed to generate encryption nonce");
    return false;
  }

  const mem_size tag_size = 16;
  const mem_size ciphertext_size = plaintext.size();
  
  encrypted.resize(sizeof(nonce) + ciphertext_size + tag_size);
  std::memcpy(encrypted.data(), nonce, sizeof(nonce));
  
  if (plaintext.empty()) {
    encrypted.clear();
    BASE_LOGE(kLogTag, "Empty plaintext");
    return false;
  }
  
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    encrypted.clear();
    return false;
  }
  
  int out_len = 0;
  int final_len = 0;
  
  bool success = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr) == 1 &&
                EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), nonce) == 1;
  
  if (success && !aad.empty()) {
    success = EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) == 1;
  }
  
  if (success) {
    success = EVP_EncryptUpdate(ctx, encrypted.data() + sizeof(nonce), &out_len, 
                                plaintext.data(), static_cast<int>(plaintext.size())) == 1;
  }
  
  if (success) {
    success = EVP_EncryptFinal_ex(ctx, encrypted.data() + sizeof(nonce) + out_len, &final_len) == 1;
  }
  
  if (success) {
    success = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, 
                                  encrypted.data() + sizeof(nonce) + ciphertext_size) == 1;
  }
  
  EVP_CIPHER_CTX_free(ctx);
  
  if (!success) {
    encrypted.clear();
    BASE_LOGE(kLogTag, "AES-GCM encryption failed");
    return false;
  }
  
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
  const mem_size tag_size = 16;
  
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
  
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    plaintext.clear();
    return false;
  }
  
  bool success = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_size, nullptr) == 1 &&
                EVP_DecryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), nonce) == 1;
  
  int aad_len = 0;
  if (success && !aad.empty()) {
    success = EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad.data(), static_cast<int>(aad.size())) == 1;
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
    success = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) == 1;
  }
  
  EVP_CIPHER_CTX_free(ctx);
  
  if (!success) {
    plaintext.clear();
    BASE_LOGE(kLogTag, "AES-GCM decryption/authentication failed");
    return false;
  }
  
  plaintext.resize(static_cast<mem_size>(out_len + final_len));
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
  if (expected_proof_hex != client_proof) {
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

  encryption_key_ = new_enc_key;
  authentication_key_ = new_auth_key;
  return true;
}

bool ZCryptoContext::EnsureKeyMaterialReady() {
  if (keys_initialized_) {
    return true;
  }

  const char* psk_env = std::getenv("ZNET_PSK");
  if (!psk_env || psk_env[0] == '\0') {
    BASE_LOGE(kLogTag, "ZNET_PSK is required when encryption is enabled");
    return false;
  }
  const base::String secret(psk_env);
  if (secret.size() < 16) {
    BASE_LOGE(kLogTag, "ZNET_PSK must be at least 16 characters");
    return false;
  }
  if (!DeriveKeyMaterial(secret)) {
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
