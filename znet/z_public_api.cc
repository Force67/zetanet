// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_public_api.h"

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/logging.h>
#endif

ZNET_API void *tx::network::ZCreateContext() { return nullptr; }

ZNET_API void tx::network::SetBaseLogHandlerFwd(
    void *user_pointer,
    void (*callback)(void *user_pointer, const char *channel_name, int level,
                     const char *msg)) {
#ifdef ZNET_USE_STL
  base::SetLogHandler(callback, user_pointer);
#else
  base::SetLogHandler(reinterpret_cast<base::LogHandler>(callback),
                      user_pointer);
#endif
}
