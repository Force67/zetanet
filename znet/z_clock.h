// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
// Monotonic time: base::TimeTicks and base::TimeDelta, from equilibrium or,
// under ZNET_USE_STL, from the compat layer's steady_clock stand-ins.
#pragma once

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/time/time.h>
#endif
