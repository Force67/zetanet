#include <znet/z_client.h>
#include <znet/z_packets.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {
struct Options {
  int messages = 1;
  int payload_bytes = 18;
  int pre_updates = 50;
  int post_updates = 30;
  int sleep_ms = 100;

  bool game_mode = false;
  int duration_seconds = 12;
  int tick_hz = 60;
  int snapshot_bytes = 48;
  int state_bytes = 220;
  int state_every_ticks = 3;
  int event_bytes = 900;
  int event_every_ticks = 60;
  int burst_size = 4;
  int burst_every_ticks = 120;
  int client_id = 0;
};

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
#endif
}

Options ParseArgs(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--messages") == 0 && i + 1 < argc) {
      options.messages = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--payload-bytes") == 0 && i + 1 < argc) {
      options.payload_bytes = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--pre-updates") == 0 && i + 1 < argc) {
      options.pre_updates = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--post-updates") == 0 && i + 1 < argc) {
      options.post_updates = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--sleep-ms") == 0 && i + 1 < argc) {
      options.sleep_ms = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--game-mode") == 0) {
      options.game_mode = true;
    } else if (std::strcmp(argv[i], "--duration-seconds") == 0 &&
               i + 1 < argc) {
      options.duration_seconds = std::atoi(argv[++i]);
      options.game_mode = true;
    } else if (std::strcmp(argv[i], "--tick-hz") == 0 && i + 1 < argc) {
      options.tick_hz = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--snapshot-bytes") == 0 &&
               i + 1 < argc) {
      options.snapshot_bytes = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--state-bytes") == 0 && i + 1 < argc) {
      options.state_bytes = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--state-every-ticks") == 0 &&
               i + 1 < argc) {
      options.state_every_ticks = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--event-bytes") == 0 && i + 1 < argc) {
      options.event_bytes = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--event-every-ticks") == 0 &&
               i + 1 < argc) {
      options.event_every_ticks = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--burst-size") == 0 && i + 1 < argc) {
      options.burst_size = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--burst-every-ticks") == 0 &&
               i + 1 < argc) {
      options.burst_every_ticks = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--client-id") == 0 && i + 1 < argc) {
      options.client_id = std::atoi(argv[++i]);
    }
  }

  options.messages = std::max(1, options.messages);
  options.payload_bytes = std::max(1, options.payload_bytes);
  options.pre_updates = std::max(0, options.pre_updates);
  options.post_updates = std::max(0, options.post_updates);
  options.sleep_ms = std::max(0, options.sleep_ms);

  options.duration_seconds = std::max(1, options.duration_seconds);
  options.tick_hz = std::max(1, options.tick_hz);
  options.snapshot_bytes = std::max(1, options.snapshot_bytes);
  options.state_bytes = std::max(1, options.state_bytes);
  options.state_every_ticks = std::max(1, options.state_every_ticks);
  options.event_bytes = std::max(1, options.event_bytes);
  options.event_every_ticks = std::max(1, options.event_every_ticks);
  options.burst_size = std::max(0, options.burst_size);
  options.burst_every_ticks = std::max(1, options.burst_every_ticks);

  return options;
}

std::string BuildPayload(std::size_t bytes,
                         const char* tag,
                         int client_id,
                         std::size_t tick) {
  std::string payload(bytes, 'x');
  char header[96];
  std::snprintf(header, sizeof(header), "%s cid=%d tick=%zu", tag, client_id,
                tick);
  const std::size_t header_len = std::strlen(header);
  const std::size_t copy_len = std::min(payload.size(), header_len);
  std::memcpy(payload.data(), header, copy_len);
  return payload;
}

void SendPacket(tx::network::ZClient& client,
                const std::string& payload,
                bool reliable,
                tx::network::PacketPriority priority) {
  const tx::network::PackageFlags flags{
      .reliable = static_cast<u8>(reliable ? 1 : 0),
      .encrypted = 0,
      .compressed = 0,
      .priority = static_cast<u8>(priority),
      .acknowledged = 0,
      .awaiting_ack = static_cast<u8>(reliable ? 1 : 0),
      .reserved = 0};

  tx::network::OutgoingPacket packet(
      tx::network::ZPeerId::to_server, tx::network::PacketType::Message,
      tx::network::PacketChannelType::Data, flags,
      base::Span<byte>(reinterpret_cast<const byte*>(payload.data()),
                       payload.size()));
  client.Push(std::move(packet));
}

std::size_t DrainIncoming(tx::network::ZClient& client) {
  std::size_t drained = 0;
  tx::network::IncomingPacket packet;
  while (client.Poll(tx::network::PacketChannelType::Data, packet)) {
    ++drained;
  }
  return drained;
}

}  // namespace

int main(int argc, char** argv) {
  const Options options = ParseArgs(argc, argv);

  tx::network::SetBaseLogHandlerFwd(nullptr, LogHandler);
  tx::network::ZResetPacketAllocatorStats();

  std::cout << "Client starting..." << std::endl;

  tx::network::ZClient client;
  if (!client.Connect("127.0.0.1", 1337)) {
    std::printf("Failed to connect to server\n");
    return 1;
  }

  std::cout << "Connected!" << std::endl;

  if (!options.game_mode) {
    for (int i = 0; i < options.pre_updates; ++i) {
      DrainIncoming(client);
      std::this_thread::sleep_for(std::chrono::milliseconds(options.sleep_ms));
    }

    std::string payload(static_cast<std::size_t>(options.payload_bytes), 'c');
    std::cout << "Sending " << options.messages
              << " message(s), payload_bytes=" << payload.size() << std::endl;
    for (int i = 0; i < options.messages; ++i) {
      client.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                         payload);
      if (options.sleep_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(options.sleep_ms));
      }
    }

    for (int i = 0; i < options.post_updates; ++i) {
      DrainIncoming(client);
      std::this_thread::sleep_for(std::chrono::milliseconds(options.sleep_ms));
    }
  } else {
    std::cout << "Running game mode: duration=" << options.duration_seconds
              << "s tick_hz=" << options.tick_hz
              << " snapshot=" << options.snapshot_bytes
              << " state=" << options.state_bytes
              << " event=" << options.event_bytes << std::endl;

    const auto tick_interval =
        std::chrono::microseconds(1000000 / options.tick_hz);
    const auto start_time = std::chrono::steady_clock::now();
    const auto end_time = start_time +
                          std::chrono::seconds(options.duration_seconds);
    auto next_tick = start_time;

    std::size_t ticks = 0;
    std::size_t snapshots_sent = 0;
    std::size_t states_sent = 0;
    std::size_t events_sent = 0;
    std::size_t bursts_sent = 0;
    std::size_t bytes_sent = 0;
    std::size_t incoming_packets = 0;

    while (std::chrono::steady_clock::now() < end_time) {
      incoming_packets += DrainIncoming(client);

      const auto now = std::chrono::steady_clock::now();
      if (now < next_tick) {
        std::this_thread::sleep_for(std::chrono::microseconds(500));
        continue;
      }

      ++ticks;
      next_tick += tick_interval;

      {
        std::string snapshot =
            BuildPayload(static_cast<std::size_t>(options.snapshot_bytes),
                         "SNAP", options.client_id, ticks);
        SendPacket(client, snapshot, false, tx::network::PacketPriority::Low);
        ++snapshots_sent;
        bytes_sent += snapshot.size();
      }

      if ((ticks % static_cast<std::size_t>(options.state_every_ticks)) == 0) {
        std::string state =
            BuildPayload(static_cast<std::size_t>(options.state_bytes),
                         "STATE", options.client_id, ticks);
        SendPacket(client, state, true, tx::network::PacketPriority::Medium);
        ++states_sent;
        bytes_sent += state.size();
      }

      if ((ticks % static_cast<std::size_t>(options.event_every_ticks)) == 0) {
        std::string event =
            BuildPayload(static_cast<std::size_t>(options.event_bytes),
                         "EVENT", options.client_id, ticks);
        SendPacket(client, event, true, tx::network::PacketPriority::High);
        ++events_sent;
        bytes_sent += event.size();
      }

      if (options.burst_size > 0 &&
          (ticks % static_cast<std::size_t>(options.burst_every_ticks)) == 0) {
        for (int i = 0; i < options.burst_size; ++i) {
          std::string burst =
              BuildPayload(static_cast<std::size_t>(options.snapshot_bytes),
                           "BURST", options.client_id, ticks);
          SendPacket(client, burst, false, tx::network::PacketPriority::Low);
          ++bursts_sent;
          bytes_sent += burst.size();
        }
      }
    }

    for (int i = 0; i < 50; ++i) {
      incoming_packets += DrainIncoming(client);
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(
                             std::chrono::steady_clock::now() - start_time)
                             .count();
    const std::size_t total_packets_sent =
        snapshots_sent + states_sent + events_sent + bursts_sent;
    const double pps = elapsed > 0.0
                           ? static_cast<double>(total_packets_sent) / elapsed
                           : 0.0;
    const double mbps =
        elapsed > 0.0 ? (static_cast<double>(bytes_sent) * 8.0) /
                            (elapsed * 1024.0 * 1024.0)
                      : 0.0;

    std::cout << "[client " << options.client_id << "] ticks=" << ticks
              << " sent_packets=" << total_packets_sent
              << " snapshots=" << snapshots_sent
              << " states=" << states_sent
              << " events=" << events_sent
              << " bursts=" << bursts_sent
              << " sent_bytes=" << bytes_sent
              << " incoming_packets=" << incoming_packets
              << " avg_pps=" << pps
              << " avg_mbps=" << mbps << std::endl;
  }

  tx::network::ZDumpPacketAllocatorStats();
  std::cout << "Client shutting down." << std::endl;
  client.Disconnect();
  return 0;
}
