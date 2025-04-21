// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_public_api.h"

#include <base/logging.h>

ZNET_API void *tx::network::ZCreateContext() { return nullptr; }

ZNET_API void tx::network::SetBaseLogHandlerFwd(
    void *user_pointer,
    void (*callback)(void *user_pointer, const char *channel_name, int level,
                     const char *msg)) {
  base::SetLogHandler(reinterpret_cast<base::LogHandler>(callback),
                      user_pointer);
}
