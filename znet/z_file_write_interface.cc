// Copyright (C) 2023-2025 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_file_write_interface.h"

#include <utility>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/filesystem/file.h>
#endif

namespace tx::network {
namespace {

class PositionalFileWriteHandle final : public IFileWriteHandle {
 public:
  explicit PositionalFileWriteHandle(base::UniquePointer<base::File> file)
      : file_(std::move(file)) {}

  bool WriteAt(u64 offset, const char* data, size_t size) override {
    if (!file_) {
      return false;
    }
    size_t written = 0;
    while (written < size) {
      const int wrote = file_.Get_UseOnlyIfYouKnowWhatYouareDoing()->Write(
          static_cast<int64_t>(offset + written), data + written, size - written);
      if (wrote <= 0) {
        return false;
      }
      written += static_cast<size_t>(wrote);
    }
    return true;
  }

  bool FlushAndClose() override {
    if (!file_) {
      return true;
    }
    const bool flushed = file_.Get_UseOnlyIfYouKnowWhatYouareDoing()->Flush();
    file_.Reset();
    return flushed;
  }

  void Close() override { file_.Reset(); }

 private:
  base::UniquePointer<base::File> file_;
};

class PositionalFileWriteFactory final : public IFileWriteFactory {
 public:
  base::UniquePointer<IFileWriteHandle> Open(const base::Path& path,
                                             u64 /*expected_size*/) override {
    base::UniquePointer<base::File> file = base::MakeUnique<base::File>(
        path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    if (!file || !file.Get_UseOnlyIfYouKnowWhatYouareDoing()->IsValid()) {
      return {};
    }
    return base::UniquePointer<IFileWriteHandle>(
        new PositionalFileWriteHandle(std::move(file)));
  }
};

}  // namespace

IFileWriteFactory& GetDefaultFileWriteFactory() {
  static PositionalFileWriteFactory factory;
  return factory;
}

}  // namespace tx::network
