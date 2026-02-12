// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_crypto_wrapper.h"

#include <cstring>
#include <cstdlib>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

namespace tx::network {
namespace {
constexpr char kLogTag[] = "z-crypto";

bool Sha256(const byte* data, mem_size size, std::array<byte, 32>& out_hash) {
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

std::string BytesToHex(const byte* data, mem_size size) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out(size * 2, '0');
  for (mem_size i = 0; i < size; ++i) {
    out[2 * i] = kHex[(data[i] >> 4) & 0x0F];
    out[2 * i + 1] = kHex[data[i] & 0x0F];
  }
  return out;
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

  byte local_nonce[16]{};
  if (RAND_bytes(local_nonce, sizeof(local_nonce)) != 1) {
    BASE_LOGE(kLogTag, "Failed to generate local key exchange nonce");
    return false;
  }
  local_public_key_ = BytesToHex(local_nonce, sizeof(local_nonce));
  return true;
}

std::string ZCryptoContext::GetPublicKey() const {
  return local_public_key_;
}

void ZCryptoContext::ProcessServerKey(const std::string& server_key) {
  server_public_key_ = server_key;
}

bool ZCryptoContext::EncryptPayload(const base::Span<byte>& plaintext,
                                    const base::Span<byte>& aad,
                                    base::Vector<byte>& encrypted) {
  encrypted.clear();

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  byte nonce[kNonceSize]{};
  if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
    BASE_LOGE(kLogTag, "Failed to generate encryption nonce");
    return false;
  }

  base::Vector<byte> ciphertext;
  if (!EncryptAesCtr(plaintext.data(), plaintext.size(), nonce, ciphertext)) {
    BASE_LOGE(kLogTag, "Payload encryption failed");
    return false;
  }

  base::Vector<byte> mac_input(kNonceSize + ciphertext.size() + aad.size());
  std::memcpy(mac_input.data(), nonce, kNonceSize);
  if (!ciphertext.empty()) {
    std::memcpy(mac_input.data() + kNonceSize, ciphertext.data(),
                ciphertext.size());
  }
  if (!aad.empty()) {
    std::memcpy(mac_input.data() + kNonceSize + ciphertext.size(), aad.data(),
                aad.size());
  }

  base::Vector<byte> auth_tag;
  if (!ComputeHmac(mac_input.data(), mac_input.size(), auth_tag) ||
      auth_tag.size() != kAuthTagSize) {
    BASE_LOGE(kLogTag, "Failed to generate payload auth tag");
    return false;
  }

  encrypted.resize(kNonceSize + ciphertext.size() + kAuthTagSize);
  std::memcpy(encrypted.data(), nonce, kNonceSize);
  if (!ciphertext.empty()) {
    std::memcpy(encrypted.data() + kNonceSize, ciphertext.data(),
                ciphertext.size());
  }
  std::memcpy(encrypted.data() + kNonceSize + ciphertext.size(), auth_tag.data(),
              kAuthTagSize);
  return true;
}

bool ZCryptoContext::DecryptPayload(const base::Span<byte>& encrypted,
                                    const base::Span<byte>& aad,
                                    base::Vector<byte>& plaintext) {
  plaintext.clear();

  if (!EnsureKeyMaterialReady()) {
    return false;
  }

  const mem_size minimum_size = kNonceSize + kAuthTagSize;
  if (encrypted.size() < minimum_size) {
    BASE_LOGE(kLogTag, "Encrypted payload is too short");
    return false;
  }

  const byte* nonce = encrypted.data();
  const mem_size ciphertext_size = encrypted.size() - minimum_size;
  const byte* ciphertext = encrypted.data() + kNonceSize;
  const byte* incoming_tag = ciphertext + ciphertext_size;

  base::Vector<byte> mac_input(kNonceSize + ciphertext_size + aad.size());
  std::memcpy(mac_input.data(), nonce, kNonceSize);
  if (ciphertext_size > 0) {
    std::memcpy(mac_input.data() + kNonceSize, ciphertext, ciphertext_size);
  }
  if (!aad.empty()) {
    std::memcpy(mac_input.data() + kNonceSize + ciphertext_size, aad.data(),
                aad.size());
  }

  base::Vector<byte> expected_tag;
  if (!ComputeHmac(mac_input.data(), mac_input.size(), expected_tag) ||
      expected_tag.size() != kAuthTagSize) {
    BASE_LOGE(kLogTag, "Failed to verify payload auth tag");
    return false;
  }
  if (CRYPTO_memcmp(expected_tag.data(), incoming_tag, kAuthTagSize) != 0) {
    BASE_LOGE(kLogTag, "Payload authentication failed");
    return false;
  }

  if (!DecryptAesCtr(ciphertext, ciphertext_size, nonce, plaintext)) {
    BASE_LOGE(kLogTag, "Payload decryption failed");
    return false;
  }
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
  const std::string secret(psk_env);
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

bool ZCryptoContext::DeriveKeyMaterial(const std::string& secret) {
  std::array<byte, 32> master_key{};
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

bool ZCryptoContext::EncryptAesCtr(const byte* input,
                                   mem_size input_size,
                                   const byte* nonce,
                                   base::Vector<byte>& output) {
  output.clear();
  output.resize(input_size);

  byte iv[16]{};
  std::memcpy(iv, nonce, kNonceSize);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }

  int written = 0;
  int finalized = 0;
  bool success =
      EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, encryption_key_.data(),
                         iv) == 1 &&
      EVP_EncryptUpdate(ctx, output.data(), &written, input,
                        static_cast<int>(input_size)) == 1 &&
      EVP_EncryptFinal_ex(ctx, output.data() + written, &finalized) == 1;
  EVP_CIPHER_CTX_free(ctx);

  if (!success || written < 0 || finalized < 0) {
    output.clear();
    return false;
  }
  output.resize(static_cast<mem_size>(written + finalized));
  return true;
}

bool ZCryptoContext::DecryptAesCtr(const byte* input,
                                   mem_size input_size,
                                   const byte* nonce,
                                   base::Vector<byte>& output) {
  output.clear();
  output.resize(input_size);

  byte iv[16]{};
  std::memcpy(iv, nonce, kNonceSize);

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }

  int written = 0;
  int finalized = 0;
  bool success =
      EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, encryption_key_.data(),
                         iv) == 1 &&
      EVP_DecryptUpdate(ctx, output.data(), &written, input,
                        static_cast<int>(input_size)) == 1 &&
      EVP_DecryptFinal_ex(ctx, output.data() + written, &finalized) == 1;
  EVP_CIPHER_CTX_free(ctx);

  if (!success || written < 0 || finalized < 0) {
    output.clear();
    return false;
  }
  output.resize(static_cast<mem_size>(written + finalized));
  return true;
}

bool ZCryptoContext::ComputeHmac(const byte* data,
                                 mem_size size,
                                 base::Vector<byte>& out_tag) const {
  out_tag.clear();
  out_tag.resize(EVP_MAX_MD_SIZE);

  unsigned int tag_size = 0;
  if (!HMAC(EVP_sha256(), authentication_key_.data(),
            static_cast<int>(authentication_key_.size()), data, size,
            out_tag.data(), &tag_size)) {
    out_tag.clear();
    return false;
  }
  out_tag.resize(tag_size);
  return true;
}

}  // namespace tx::network
