// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <znet/z_abi.h>

namespace tx::network {

ZNET_API void *ZCreateContext();

ZNET_API void SetBaseLogHandlerFwd(void *user_pointer,
                                   void (*callback)(void *user_pointer,
                                                    const char *channel_name,
                                                    int level,
                                                    const char *msg));
}  // namespace tx::network