// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.

#include "z_file_write_interface.h"
#include "z_file_transporter.h"

#include <cstring>
#include <limits>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tx::network {

#if !defined(_WIN32)
namespace {

class MMapFileWriteHandle final : public IFileWriteHandle {
 public:
  MMapFileWriteHandle(int fd, void* mapping, mem_size mapped_size)
      : fd_(fd), mapping_(mapping), mapped_size_(mapped_size) {}

  ~MMapFileWriteHandle() override { Close(); }

  bool WriteAt(u64 offset, const char* data, mem_size size) override {
    if (size == 0) {
      return true;
    }
    if (!mapping_ || offset > static_cast<u64>(mapped_size_)) {
      return false;
    }
    const u64 remaining = static_cast<u64>(mapped_size_) - offset;
    if (static_cast<u64>(size) > remaining) {
      return false;
    }
    std::memcpy(static_cast<char*>(mapping_) + offset, data, size);
    return true;
  }

  bool FlushAndClose() override {
    bool ok = true;
    if (mapping_ && mapped_size_ > 0) {
      ok = msync(mapping_, mapped_size_, MS_SYNC) == 0;
    }
    Close();
    return ok;
  }

  void Close() override {
    if (mapping_) {
      munmap(mapping_, mapped_size_);
      mapping_ = nullptr;
      mapped_size_ = 0;
    }
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }

 private:
  int fd_{-1};
  void* mapping_{nullptr};
  mem_size mapped_size_{0};
};

class MemoryMappedFileWriteFactory final : public IFileWriteFactory {
 public:
  base::UniquePointer<IFileWriteHandle> Open(const base::Path& path,
                                             u64 expected_size) override {
    if (expected_size > ZFileTransporter::kMaxIncomingFileSize) {
      return {};
    }
    const base::String file_path = path.ToAsciiString();
    const int fd = open(file_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      return {};
    }

    if (expected_size > static_cast<u64>(std::numeric_limits<off_t>::max())) {
      close(fd);
      return {};
    }
    if (ftruncate(fd, static_cast<off_t>(expected_size)) != 0) {
      close(fd);
      return {};
    }

    if (expected_size == 0) {
      return base::UniquePointer<IFileWriteHandle>(
          new MMapFileWriteHandle(fd, nullptr, 0));
    }

    if (expected_size > static_cast<u64>(std::numeric_limits<mem_size>::max())) {
      close(fd);
      return {};
    }
    void* mapping = mmap(nullptr, static_cast<mem_size>(expected_size),
                         PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping == MAP_FAILED) {
      close(fd);
      return {};
    }

    return base::UniquePointer<IFileWriteHandle>(new MMapFileWriteHandle(
        fd, mapping, static_cast<mem_size>(expected_size)));
  }
};

}  // namespace

IFileWriteFactory& GetMemoryMappedFileWriteFactory() {
  static MemoryMappedFileWriteFactory factory;
  return factory;
}

#else

IFileWriteFactory& GetMemoryMappedFileWriteFactory() {
  return GetDefaultFileWriteFactory();
}

#endif

}  // namespace tx::network
