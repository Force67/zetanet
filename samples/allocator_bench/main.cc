#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <znet/z_packets.h>
#include <znet/z_peer.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

namespace {
struct BenchOptions {
  std::size_t iterations = 200000;
  std::size_t payload_bytes = 1024;
  std::size_t copies_per_packet = 3;
  bool mixed_sizes = true;
};

bool ParsePositive(const char* text, std::size_t* out) {
  if (!text || !out) {
    return false;
  }
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text, &end, 10);
  if (!end || *end != '\0') {
    return false;
  }
  *out = static_cast<std::size_t>(value);
  return true;
}

BenchOptions ParseArgs(int argc, char** argv) {
  BenchOptions options;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      std::size_t value = 0;
      if (ParsePositive(argv[++i], &value) && value > 0) {
        options.iterations = value;
      }
    } else if (std::strcmp(argv[i], "--payload-bytes") == 0 && i + 1 < argc) {
      std::size_t value = 0;
      if (ParsePositive(argv[++i], &value) && value > 0) {
        options.payload_bytes = value;
        options.mixed_sizes = false;
      }
    } else if (std::strcmp(argv[i], "--copies") == 0 && i + 1 < argc) {
      std::size_t value = 0;
      if (ParsePositive(argv[++i], &value)) {
        options.copies_per_packet = value;
      }
    } else if (std::strcmp(argv[i], "--fixed") == 0) {
      options.mixed_sizes = false;
    } else if (std::strcmp(argv[i], "--mixed") == 0) {
      options.mixed_sizes = true;
    }
  }
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  const BenchOptions options = ParseArgs(argc, argv);

  tx::network::ZResetPacketAllocatorStats();

  constexpr std::size_t kWarmup = 1000;
  constexpr std::size_t kSinkWindow = 256;
  const std::vector<std::size_t> mixed_sizes = {
      64, 96, 128, 192, 256, 384, 512, 768, 1024, 1400, 4096, 8192};

  std::vector<std::string> payload_cache;
  payload_cache.reserve(mixed_sizes.size());
  for (std::size_t size : mixed_sizes) {
    payload_cache.emplace_back(size, 'x');
  }
  const std::string fixed_payload(options.payload_bytes, 'y');

  std::vector<tx::network::OutgoingPacket> sinks(kSinkWindow);

  const tx::network::PackageFlags flags{.reliable = 1,
                                        .encrypted = 0,
                                        .compressed = 0,
                                        .priority =
                                            static_cast<u8>(tx::network::PacketPriority::Medium),
                                        .acknowledged = 0,
                                        .awaiting_ack = 1,
                                        .reserved = 0};

  const auto run_once = [&](std::size_t idx) {
    const std::string* source = &fixed_payload;
    if (options.mixed_sizes) {
      const std::size_t pick = (idx * 2654435761u) % payload_cache.size();
      source = &payload_cache[pick];
    }

    tx::network::OutgoingPacket base(
        tx::network::ZPeerId::to_server, tx::network::PacketType::Message,
        tx::network::PacketChannelType::Data, flags,
        base::Span<byte>(reinterpret_cast<const byte*>(source->data()), source->size()));

    for (std::size_t copy_idx = 0; copy_idx < options.copies_per_packet; ++copy_idx) {
      tx::network::OutgoingPacket clone = base;
      const std::size_t sink_idx = (idx + copy_idx) % kSinkWindow;
      sinks[sink_idx] = std::move(clone);
    }
  };

  for (std::size_t i = 0; i < kWarmup; ++i) {
    run_once(i);
  }
  tx::network::ZResetPacketAllocatorStats();

  const auto start = std::chrono::steady_clock::now();
  for (std::size_t i = 0; i < options.iterations; ++i) {
    run_once(i);
  }
  const auto end = std::chrono::steady_clock::now();
  const auto elapsed_ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

  sinks.clear();

  tx::network::ZPacketAllocatorStats stats{};
  tx::network::ZGetPacketAllocatorStats(&stats);

  const double elapsed_s = static_cast<double>(elapsed_ns) / 1'000'000'000.0;
  const double packets_per_sec =
      elapsed_s > 0.0 ? static_cast<double>(options.iterations) / elapsed_s : 0.0;

  std::printf("allocator_bench iterations=%zu copies=%zu mixed=%d elapsed=%.3fs ops=%.0f/s\n",
              options.iterations, options.copies_per_packet,
              options.mixed_sizes ? 1 : 0, elapsed_s, packets_per_sec);
  tx::network::ZDumpPacketAllocatorStats();

  return 0;
}
