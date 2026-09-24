// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#if defined(ZNET_CRYPTO_BACKEND_OPENSSL) + \
    defined(ZNET_CRYPTO_BACKEND_MBEDTLS) + \
    defined(ZNET_CRYPTO_BACKEND_NONE) > 1
#error "Only one crypto backend can be selected"
#endif

// NONE builds without a crypto library: encryption is refused at start and
// the file transporter cannot sign chunks.
#if !defined(ZNET_CRYPTO_BACKEND_OPENSSL) && \
    !defined(ZNET_CRYPTO_BACKEND_MBEDTLS) && \
    !defined(ZNET_CRYPTO_BACKEND_NONE)
#define ZNET_CRYPTO_BACKEND_OPENSSL 1
#endif

