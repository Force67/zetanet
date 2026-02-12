#include <znet/z_server.h>
#include <znet/z_packets.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {
struct Options {
  int duration_seconds = 0;
  int dump_interval_seconds = 0;
  int summary_interval_seconds = 2;
  bool quiet_data = true;
  int rebroadcast_every_packets = 0;
  int rebroadcast_bytes = 64;
};

Options ParseArgs(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--duration-seconds") == 0 && i + 1 < argc) {
      options.duration_seconds = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--dump-every-seconds") == 0 &&
               i + 1 < argc) {
      options.dump_interval_seconds = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--summary-every-seconds") == 0 &&
               i + 1 < argc) {
      options.summary_interval_seconds = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--quiet-data") == 0) {
      options.quiet_data = true;
    } else if (std::strcmp(argv[i], "--verbose-data") == 0) {
      options.quiet_data = false;
    } else if (std::strcmp(argv[i], "--rebroadcast-every-packets") == 0 &&
               i + 1 < argc) {
      options.rebroadcast_every_packets = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--rebroadcast-bytes") == 0 &&
               i + 1 < argc) {
      options.rebroadcast_bytes = std::atoi(argv[++i]);
    }
  }

  if (options.summary_interval_seconds < 0) {
    options.summary_interval_seconds = 0;
  }
  if (options.duration_seconds < 0) {
    options.duration_seconds = 0;
  }
  if (options.dump_interval_seconds < 0) {
    options.dump_interval_seconds = 0;
  }
  if (options.rebroadcast_every_packets < 0) {
    options.rebroadcast_every_packets = 0;
  }
  if (options.rebroadcast_bytes < 1) {
    options.rebroadcast_bytes = 1;
  }

  return options;
}

void LogHandler(void* user_pointer,
                const char* channel_name,
                int level,
                const char* msg) {
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
               base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
#if defined(_WIN32)
  char buffer[256];
  std::snprintf(buffer, sizeof(buffer), "[%s] %s: %s\n", channel_name,
                base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
  ::OutputDebugStringA(buffer);
  std::cout << buffer;
#endif
}
}  // namespace

int main(int argc, char** argv) {
  const Options options = ParseArgs(argc, argv);

  tx::network::SetBaseLogHandlerFwd(nullptr, LogHandler);
  std::cout << "Log handler set!" << std::endl;

  tx::network::ZServer server;
  if (!server.Begin(1337)) {
    std::cerr << "Failed to start server" << std::endl;
    return -1;
  }
  std::cout << "Server is up on port 1337" << std::endl;

  const auto start_time = std::chrono::steady_clock::now();
  auto next_dump = start_time;
  auto next_summary = start_time;

  std::size_t total_data_packets = 0;
  std::size_t total_data_bytes = 0;
  std::size_t total_system_packets = 0;
  std::size_t total_rebroadcast_packets = 0;
  std::size_t total_rebroadcast_bytes = 0;

  std::size_t window_packets = 0;
  std::size_t window_bytes = 0;

  tx::network::IncomingPacket packet;
  while (true) {
    while (server.Poll(tx::network::PacketChannelType::Data, packet)) {
      if (tx::network::IsSystemMessage(packet.type)) {
        ++total_system_packets;
        continue;
      }

      const std::size_t payload_size = packet.data.size();
      ++total_data_packets;
      total_data_bytes += payload_size;
      ++window_packets;
      window_bytes += payload_size;

      if (!options.quiet_data && (total_data_packets % 50 == 0)) {
        std::cout << "[server] sample data packet size=" << payload_size
                  << " total_packets=" << total_data_packets << std::endl;
      }

      if (options.rebroadcast_every_packets > 0 &&
          (total_data_packets %
           static_cast<std::size_t>(options.rebroadcast_every_packets)) == 0) {
        const std::size_t payload_len =
            static_cast<std::size_t>(options.rebroadcast_bytes);
        std::string rebroadcast_payload(payload_len, 's');
        const tx::network::PackageFlags flags{
            .reliable = 0,
            .encrypted = 0,
            .compressed = 0,
            .priority = static_cast<u8>(tx::network::PacketPriority::Low),
            .acknowledged = 0,
            .awaiting_ack = 0,
            .reserved = 0};
        tx::network::OutgoingPacket out(
            tx::network::ZPeerId::to_all, tx::network::PacketType::Message,
            tx::network::PacketChannelType::Data, flags,
            base::Span<byte>(
                reinterpret_cast<const byte*>(rebroadcast_payload.data()),
                rebroadcast_payload.size()));
        server.Push(std::move(out));
        ++total_rebroadcast_packets;
        total_rebroadcast_bytes += payload_len;
      }
    }

    const auto now = std::chrono::steady_clock::now();

    if (options.summary_interval_seconds > 0 && now >= next_summary) {
      const double mbps =
          (static_cast<double>(window_bytes) * 8.0) /
          (static_cast<double>(options.summary_interval_seconds) *
           1024.0 * 1024.0);
      std::cout << "[server] window packets=" << window_packets
                << " window_bytes=" << window_bytes
                << " approx_mbps=" << mbps
                << " total_packets=" << total_data_packets
                << " system_packets=" << total_system_packets
                << " rebroadcast_packets=" << total_rebroadcast_packets
                << std::endl;
      window_packets = 0;
      window_bytes = 0;
      next_summary = now + std::chrono::seconds(options.summary_interval_seconds);
    }

    if (options.dump_interval_seconds > 0 && now >= next_dump) {
      tx::network::ZDumpPacketAllocatorStats();
      next_dump = now + std::chrono::seconds(options.dump_interval_seconds);
    }

    if (options.duration_seconds > 0) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
      if (elapsed.count() >= options.duration_seconds) {
        std::cout << "Duration reached, exiting server loop." << std::endl;
        break;
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  const auto end_time = std::chrono::steady_clock::now();
  const double total_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(end_time -
                                                                 start_time)
          .count();
  const double packets_per_sec =
      total_seconds > 0.0 ? static_cast<double>(total_data_packets) / total_seconds
                          : 0.0;
  const double mbps =
      total_seconds > 0.0
          ? (static_cast<double>(total_data_bytes) * 8.0) /
                (total_seconds * 1024.0 * 1024.0)
          : 0.0;

  std::cout << "[server] final total_packets=" << total_data_packets
            << " total_bytes=" << total_data_bytes
            << " duration_s=" << total_seconds
            << " avg_pps=" << packets_per_sec
            << " avg_mbps=" << mbps
            << " system_packets=" << total_system_packets
            << " rebroadcast_packets=" << total_rebroadcast_packets
            << " rebroadcast_bytes=" << total_rebroadcast_bytes << std::endl;

  tx::network::ZDumpPacketAllocatorStats();
  server.Deinit();
  return 0;
}
