#include <znet/z_p2p_node.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_set>

namespace {
enum class Role { Host, Client };

struct Options {
  Role role = Role::Host;
  std::string name;
  std::string host_ip = "127.0.0.1";
  int host_port = 14600;
  int local_port = 14601;
  int duration_seconds = 20;
  int send_every_ms = 1000;
  int tick_sleep_ms = 5;
  int become_host_after_seconds = -1;
  bool send_to_all = true;
  bool verbose_logs = false;
  bool show_duplicates = false;
  bool usage_requested = false;
};

struct RuntimeStats {
  int sent_messages = 0;
  int received_data_packets = 0;
  int received_control_packets = 0;
  int received_data_bytes = 0;
  int suppressed_duplicate_packets = 0;
};

void PrintUsage(const char* exe) {
  std::fprintf(stdout,
               "P2PDemo - readable peer-to-peer sample\n\n"
               "Usage:\n"
               "  %s --mode host [options]\n"
               "  %s --mode client [options]\n\n"
               "Core options:\n"
               "  --mode host|client\n"
               "  --name <text>                         (default: host/client)\n"
               "  --host-ip <ip-or-dns>                 (default: 127.0.0.1)\n"
               "  --host-port <port>                    (default: 14600)\n"
               "  --local-port <port>                   (default: 14601 for client)\n"
               "  --duration-seconds <n>                (default: 20)\n"
               "  --send-every-ms <n>                   (default: 1000)\n"
               "  --tick-sleep-ms <n>                   (default: 5)\n"
               "  --send-target all|server              (default: all)\n"
               "  --become-host-after-seconds <n>       (client only; default: disabled)\n"
               "  --verbose-logs                        (enable znet info logs)\n"
               "  --show-duplicates                     (print retransmitted duplicates)\n"
               "  --help\n\n"
               "Quick local test with 3 terminals:\n"
               "  1) %s --mode host --host-port 14600 --name host\n"
               "  2) %s --mode client --host-ip 127.0.0.1 --host-port 14600 "
               "--local-port 14601 --name alice\n"
               "  3) %s --mode client --host-ip 127.0.0.1 --host-port 14600 "
               "--local-port 14602 --name bob --become-host-after-seconds 8\n",
               exe, exe, exe, exe, exe);
}

bool ParseInt(const char* text, int& out) {
  if (!text || !text[0]) {
    return false;
  }
  char* end = nullptr;
  const long value = std::strtol(text, &end, 10);
  if (!end || *end != '\0') {
    return false;
  }
  out = static_cast<int>(value);
  return true;
}

bool ParseArgs(int argc, char** argv, Options& options) {
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (std::strcmp(arg, "--help") == 0) {
      PrintUsage(argv[0]);
      options.usage_requested = true;
      return true;
    }
    if (std::strcmp(arg, "--mode") == 0 && i + 1 < argc) {
      const char* mode = argv[++i];
      if (std::strcmp(mode, "host") == 0) {
        options.role = Role::Host;
      } else if (std::strcmp(mode, "client") == 0) {
        options.role = Role::Client;
      } else {
        std::fprintf(stderr, "Unknown mode '%s'\n", mode);
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--name") == 0 && i + 1 < argc) {
      options.name = argv[++i];
      continue;
    }
    if (std::strcmp(arg, "--host-ip") == 0 && i + 1 < argc) {
      options.host_ip = argv[++i];
      continue;
    }
    if (std::strcmp(arg, "--host-port") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.host_port)) {
        std::fprintf(stderr, "Invalid --host-port value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--local-port") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.local_port)) {
        std::fprintf(stderr, "Invalid --local-port value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--duration-seconds") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.duration_seconds)) {
        std::fprintf(stderr, "Invalid --duration-seconds value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--send-every-ms") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.send_every_ms)) {
        std::fprintf(stderr, "Invalid --send-every-ms value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--tick-sleep-ms") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.tick_sleep_ms)) {
        std::fprintf(stderr, "Invalid --tick-sleep-ms value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--become-host-after-seconds") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.become_host_after_seconds)) {
        std::fprintf(stderr, "Invalid --become-host-after-seconds value\n");
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--send-target") == 0 && i + 1 < argc) {
      const char* value = argv[++i];
      if (std::strcmp(value, "all") == 0) {
        options.send_to_all = true;
      } else if (std::strcmp(value, "server") == 0) {
        options.send_to_all = false;
      } else {
        std::fprintf(stderr, "Unknown --send-target value '%s'\n", value);
        return false;
      }
      continue;
    }
    if (std::strcmp(arg, "--verbose-logs") == 0) {
      options.verbose_logs = true;
      continue;
    }
    if (std::strcmp(arg, "--show-duplicates") == 0) {
      options.show_duplicates = true;
      continue;
    }

    std::fprintf(stderr, "Unknown argument: %s\n", arg);
    return false;
  }

  if (options.host_port <= 0 || options.host_port > 65535) {
    std::fprintf(stderr, "--host-port must be in range 1..65535\n");
    return false;
  }
  if (options.local_port <= 0 || options.local_port > 65535) {
    std::fprintf(stderr, "--local-port must be in range 1..65535\n");
    return false;
  }
  if (options.duration_seconds <= 0) {
    std::fprintf(stderr, "--duration-seconds must be > 0\n");
    return false;
  }
  if (options.send_every_ms <= 0) {
    std::fprintf(stderr, "--send-every-ms must be > 0\n");
    return false;
  }
  if (options.tick_sleep_ms < 0) {
    std::fprintf(stderr, "--tick-sleep-ms must be >= 0\n");
    return false;
  }

  if (options.name.empty()) {
    options.name = options.role == Role::Host ? "host" : "client";
  }

  if (options.role == Role::Host) {
    options.local_port = options.host_port;
    if (options.become_host_after_seconds >= 0) {
      std::fprintf(stderr,
                   "Ignoring --become-host-after-seconds in host mode\n");
    }
  }

  return true;
}

void LogHandler(void*,
                const char* channel_name,
                int level,
                const char* msg) {
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
               base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
}

void QuietLogHandler(void*,
                     const char* channel_name,
                     int level,
                     const char* msg) {
  if (level <= static_cast<int>(base::LogLevel::kInfo)) {
    return;
  }
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
               base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
}

void DrainIncoming(tx::network::ZP2PNode& node,
                   RuntimeStats& stats,
                   bool show_duplicates,
                   std::unordered_set<std::string>& seen_messages) {
  tx::network::IncomingPacket packet;
  while (node.Poll(tx::network::PacketChannelType::Control, packet)) {
    ++stats.received_control_packets;
    std::printf("[control] source=%u type=%u bytes=%zu\n", packet.source_peer_id,
                static_cast<unsigned>(packet.type), packet.data.size());
  }

  while (node.Poll(tx::network::PacketChannelType::Data, packet)) {
    ++stats.received_data_packets;
    stats.received_data_bytes += static_cast<int>(packet.data.size());
    if (!show_duplicates) {
      std::string text(packet.data.c_str(), packet.data.size());
      const std::string key =
          std::to_string(packet.source_peer_id) + "|" + text;
      if (!seen_messages.insert(key).second) {
        ++stats.suppressed_duplicate_packets;
        continue;
      }
    }
    std::printf("[data] source=%u bytes=%zu text=\"%s\"\n", packet.source_peer_id,
                packet.data.size(), packet.data.c_str());
  }
}
}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseArgs(argc, argv, options)) {
    std::fprintf(stderr, "Run with --help for usage.\n");
    return 1;
  }
  if (options.usage_requested) {
    return 0;
  }

  tx::network::SetBaseLogHandlerFwd(
      nullptr, options.verbose_logs ? LogHandler : QuietLogHandler);

  tx::network::ZP2PNode node;
  const bool started =
      options.role == Role::Host
          ? node.Begin(static_cast<u16>(options.host_port))
          : node.Connect(base::StringRef(options.host_ip.data(),
                                         options.host_ip.size()),
                         static_cast<u16>(options.host_port),
                         static_cast<u16>(options.local_port));

  if (!started) {
    std::fprintf(stderr, "Failed to start node.\n");
    return 2;
  }

  std::printf(
      "[demo] role=%s name=%s host=%s:%d local_port=%d duration=%ds\n"
      "[demo] send_target=%s send_every=%dms become_host_after=%ds\n",
      options.role == Role::Host ? "host" : "client", options.name.c_str(),
      options.host_ip.c_str(), options.host_port, options.local_port,
      options.duration_seconds, options.send_to_all ? "all" : "server",
      options.send_every_ms, options.become_host_after_seconds);

  RuntimeStats stats;
  std::unordered_set<std::string> seen_messages;
  bool did_promote = false;
  int send_sequence = 0;

  const auto start_time = std::chrono::steady_clock::now();
  const auto end_time =
      start_time + std::chrono::seconds(options.duration_seconds);
  auto next_send_time = start_time + std::chrono::milliseconds(500);

  while (std::chrono::steady_clock::now() < end_time) {
    node.Update();
    DrainIncoming(node, stats, options.show_duplicates, seen_messages);

    const auto now = std::chrono::steady_clock::now();
    if (options.role == Role::Client && !did_promote &&
        options.become_host_after_seconds >= 0) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
      if (elapsed.count() >= options.become_host_after_seconds) {
        std::printf(
            "[demo] elapsed=%llds triggering BecomeHost() on client '%s'\n",
            static_cast<long long>(elapsed.count()), options.name.c_str());
        node.BecomeHost();
        did_promote = true;
      }
    }

    if (now >= next_send_time) {
      ++send_sequence;
      const auto elapsed_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time)
              .count();
      char msg[256];
      std::snprintf(
          msg, sizeof(msg), "[%s] seq=%d elapsed_ms=%lld role=%s", options.name.c_str(),
          send_sequence, static_cast<long long>(elapsed_ms),
          node.is_host() ? "host" : "client");
      node.SendMessage(tx::network::ZPeerId(options.send_to_all
                                                ? tx::network::ZPeerId::to_all
                                                : tx::network::ZPeerId::to_server),
                       base::String(msg));
      ++stats.sent_messages;
      std::printf("[send] %s\n", msg);
      next_send_time = now + std::chrono::milliseconds(options.send_every_ms);
    }

    if (options.tick_sleep_ms > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(options.tick_sleep_ms));
    }
  }

  std::printf(
      "[summary] role_now=%s sent=%d recv_data_packets=%d recv_data_bytes=%d "
      "suppressed_duplicates=%d "
      "recv_control_packets=%d\n",
      node.is_host() ? "host" : "client", stats.sent_messages,
      stats.received_data_packets, stats.received_data_bytes,
      stats.suppressed_duplicate_packets,
      stats.received_control_packets);
  return 0;
}
