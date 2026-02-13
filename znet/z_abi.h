// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#if defined(_WIN32)
#if defined(COMPILE_DLL)
#define ZNET_API __declspec(dllexport)
#else
#define ZNET_API __declspec(dllimport)
#endif
#else
#define ZNET_API
#endif