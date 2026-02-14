// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#if defined(ZNET_CRYPTO_BACKEND_OPENSSL) && \
    defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
#error "Only one crypto backend can be selected"
#endif

#if !defined(ZNET_CRYPTO_BACKEND_OPENSSL) && \
    !defined(ZNET_CRYPTO_BACKEND_MBEDTLS)
#define ZNET_CRYPTO_BACKEND_OPENSSL 1
#endif

