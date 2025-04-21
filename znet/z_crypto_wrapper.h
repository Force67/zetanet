// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#if 0
#include <mbedtls/aes.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ctr_drbg.h>
#include <base/arch.h>
#endif

#include <cstring>
#include <string>

namespace tx::network {

class ZCryptoContext {
 public:
  ZCryptoContext() {
      #if 0
    mbedtls_aes_init(&aes);
    mbedtls_dhm_init(&dhm);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char* pers = "dhm_example";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const byte*)pers, strlen(pers));
    #endif
  }

  ~ZCryptoContext() {
      #if 0
    mbedtls_aes_free(&aes);
    mbedtls_dhm_free(&dhm);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    #endif
  }

  void InitializeKeyExchange() {
#if 0

    static const byte dhm_P[] MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
    static const byte dhm_G[] MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;

    if (mbedtls_mpi_read_binary(&dhm.P, dhm_P, sizeof(dhm_P)) != 0 ||
        mbedtls_mpi_read_binary(&dhm.G, dhm_G, sizeof(dhm_G)) != 0) {
      // Handle error
      return;
    }

    size_t buf_len = mbedtls_dhm_get_len(&dhm);

    size_t mpi_size = mbedtls_mpi_size(&dhm.P);
    char* buf = new char[buf_len];
    if (mbedtls_dhm_make_public(&dhm, static_cast<int>(mpi_size),
                                reinterpret_cast<unsigned char*>(buf), buf_len,
                                mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      // Handle error
      delete[] buf;
      return;
    }
    delete[] buf;
    #endif
  }

  std::string GetPublicKey() {
      #if 0
    auto buf_len = mbedtls_dhm_get_len(&dhm);
    char* buf = new char[buf_len];
    mbedtls_mpi_write_binary(&dhm.GX, (byte*)buf, buf_len);
    std::string public_key(buf, buf_len);
    delete[] buf;
    return public_key;
    #endif
    return std::string();
  }

  void ProcessServerKey(const std::string& server_key) {
#if 0
    mbedtls_mpi_read_binary(
        &dhm.GY, reinterpret_cast<const unsigned char*>(server_key.data()),
        server_key.size());
    size_t shared_secret_len;

    auto len = mbedtls_dhm_get_len(&dhm);
    byte* shared_secret = new byte[len];

    if (mbedtls_dhm_calc_secret(&dhm, shared_secret, len, &shared_secret_len,
                                mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      // Handle error
    }

    SetAesKey(shared_secret, shared_secret_len);

    delete[] shared_secret;
#endif
  }

  void EncryptPayload(unsigned char* data, size_t size) {
#if 0
    unsigned char iv[16];
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv));
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, size, iv, data, data);
#endif
  }

  void DecryptPayload(unsigned char* data, size_t size) {
#if 0
    unsigned char iv[16];  // Set this to the IV used in encryption
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, size, iv, data, data);
#endif
  }

 private:
#if 0
  mbedtls_aes_context aes;
  mbedtls_dhm_context dhm;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
#endif

  void SetAesKey(const unsigned char* key, size_t key_len) {
#if 0
    mbedtls_aes_setkey_enc(&aes, key, static_cast<u32>(key_len * 8));
    mbedtls_aes_setkey_dec(&aes, key, static_cast<u32>(key_len * 8));
    #endif
  }
};

}  // namespace tx::network