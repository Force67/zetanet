// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
#pragma once

#include <string>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/filesystem/path.h>
#include <base/memory/unique_pointer.h>
#include <base/arch.h>
#endif

namespace tx::network {

class IFileWriteHandle {
 public:
  virtual ~IFileWriteHandle() = default;

  virtual bool WriteAt(u64 offset, const char* data, size_t size) = 0;
  virtual bool FlushAndClose() = 0;
  virtual void Close() = 0;
};

class IFileWriteFactory {
 public:
  virtual ~IFileWriteFactory() = default;

  virtual base::UniquePointer<IFileWriteHandle> Open(const base::Path& path,
                                                      u64 expected_size) = 0;
};

IFileWriteFactory& GetDefaultFileWriteFactory();
IFileWriteFactory& GetMemoryMappedFileWriteFactory();

}  // namespace tx::network
