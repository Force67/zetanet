#include <znet/z_client.h>
#include <znet/z_packets.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/math/value_bounds.h>
#include <base/memory/move.h>
#include <base/strings/xstring.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  fprintf(stderr, "[%s] %s: %s\n", channel_name,
          base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
#if defined(_WIN32)
  char buffer[256];
  snprintf(buffer, sizeof(buffer), "[%s] %s: %s\n", channel_name,
           base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
  ::OutputDebugStringA(buffer);
#endif
}

Options ParseArgs(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--messages") == 0 && i + 1 < argc) {
      options.messages = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--payload-bytes") == 0 && i + 1 < argc) {
      options.payload_bytes = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--pre-updates") == 0 && i + 1 < argc) {
      options.pre_updates = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--post-updates") == 0 && i + 1 < argc) {
      options.post_updates = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--sleep-ms") == 0 && i + 1 < argc) {
      options.sleep_ms = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--game-mode") == 0) {
      options.game_mode = true;
    } else if (strcmp(argv[i], "--duration-seconds") == 0 &&
               i + 1 < argc) {
      options.duration_seconds = atoi(argv[++i]);
      options.game_mode = true;
    } else if (strcmp(argv[i], "--tick-hz") == 0 && i + 1 < argc) {
      options.tick_hz = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--snapshot-bytes") == 0 &&
               i + 1 < argc) {
      options.snapshot_bytes = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--state-bytes") == 0 && i + 1 < argc) {
      options.state_bytes = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--state-every-ticks") == 0 &&
               i + 1 < argc) {
      options.state_every_ticks = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--event-bytes") == 0 && i + 1 < argc) {
      options.event_bytes = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--event-every-ticks") == 0 &&
               i + 1 < argc) {
      options.event_every_ticks = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--burst-size") == 0 && i + 1 < argc) {
      options.burst_size = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--burst-every-ticks") == 0 &&
               i + 1 < argc) {
      options.burst_every_ticks = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--client-id") == 0 && i + 1 < argc) {
      options.client_id = atoi(argv[++i]);
    }
  }

  options.messages = base::Max(1, options.messages);
  options.payload_bytes = base::Max(1, options.payload_bytes);
  options.pre_updates = base::Max(0, options.pre_updates);
  options.post_updates = base::Max(0, options.post_updates);
  options.sleep_ms = base::Max(0, options.sleep_ms);

  options.duration_seconds = base::Max(1, options.duration_seconds);
  options.tick_hz = base::Max(1, options.tick_hz);
  options.snapshot_bytes = base::Max(1, options.snapshot_bytes);
  options.state_bytes = base::Max(1, options.state_bytes);
  options.state_every_ticks = base::Max(1, options.state_every_ticks);
  options.event_bytes = base::Max(1, options.event_bytes);
  options.event_every_ticks = base::Max(1, options.event_every_ticks);
  options.burst_size = base::Max(0, options.burst_size);
  options.burst_every_ticks = base::Max(1, options.burst_every_ticks);

  return options;
}

base::String BuildPayload(size_t bytes,
                         const char* tag,
                         int client_id,
                         size_t tick) {
  base::String payload(bytes, 'x');
  char header[96];
  snprintf(header, sizeof(header), "%s cid=%d tick=%zu", tag, client_id,
           tick);
  const size_t header_len = strlen(header);
  const size_t copy_len =
      base::Min(static_cast<size_t>(payload.size()), header_len);
  memcpy(payload.data(), header, copy_len);
  return payload;
}

void SendPacket(tx::network::ZClient& client,
                const base::String& payload,
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
  client.Push(base::move(packet));
}

size_t DrainIncoming(tx::network::ZClient& client) {
  size_t drained = 0;
  tx::network::IncomingPacket packet;
  while (client.Poll(tx::network::PacketChannelType::Data, packet)) {
    ++drained;
  }
  return drained;
}

}  // namespace

int main(int argc, char** argv) {
  const Options options = ParseArgs(argc, argv);
  // Progress lines interleave with the library's stderr logs; line buffering
  // keeps them in order when stdout is a pipe.
  setvbuf(stdout, nullptr, _IOLBF, 0);

  tx::network::SetBaseLogHandlerFwd(nullptr, LogHandler);
  tx::network::ZResetPacketAllocatorStats();

  printf("Client starting...\n");

  tx::network::ZClient client;
  if (!client.Connect("127.0.0.1", 1337)) {
    printf("Failed to connect to server\n");
    return 1;
  }

  printf("Connected!\n");

  if (!options.game_mode) {
    for (int i = 0; i < options.pre_updates; ++i) {
      DrainIncoming(client);
      base::SleepForMilliseconds(static_cast<u64>(options.sleep_ms));
    }

    base::String payload(static_cast<size_t>(options.payload_bytes), 'c');
    printf("Sending %d message(s), payload_bytes=%zu\n", options.messages,
           static_cast<size_t>(payload.size()));
    for (int i = 0; i < options.messages; ++i) {
      client.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                         payload);
      if (options.sleep_ms > 0) {
        base::SleepForMilliseconds(static_cast<u64>(options.sleep_ms));
      }
    }

    for (int i = 0; i < options.post_updates; ++i) {
      DrainIncoming(client);
      base::SleepForMilliseconds(static_cast<u64>(options.sleep_ms));
    }
  } else {
    printf(
        "Running game mode: duration=%ds tick_hz=%d snapshot=%d state=%d "
        "event=%d\n",
        options.duration_seconds, options.tick_hz, options.snapshot_bytes,
        options.state_bytes, options.event_bytes);

    const base::TimeDelta tick_interval =
        base::Microseconds(1000000 / options.tick_hz);
    const base::TimeTicks start_time = base::TimeTicks::Now();
    const base::TimeTicks end_time =
        start_time + base::Seconds(options.duration_seconds);
    base::TimeTicks next_tick = start_time;

    size_t ticks = 0;
    size_t snapshots_sent = 0;
    size_t states_sent = 0;
    size_t events_sent = 0;
    size_t bursts_sent = 0;
    size_t bytes_sent = 0;
    size_t incoming_packets = 0;

    while (base::TimeTicks::Now() < end_time) {
      incoming_packets += DrainIncoming(client);

      const base::TimeTicks now = base::TimeTicks::Now();
      if (now < next_tick) {
        base::SleepForMicroseconds(500);
        continue;
      }

      ++ticks;
      next_tick = next_tick + tick_interval;

      {
        base::String snapshot =
            BuildPayload(static_cast<size_t>(options.snapshot_bytes),
                         "SNAP", options.client_id, ticks);
        SendPacket(client, snapshot, false, tx::network::PacketPriority::Low);
        ++snapshots_sent;
        bytes_sent += snapshot.size();
      }

      if ((ticks % static_cast<size_t>(options.state_every_ticks)) == 0) {
        base::String state =
            BuildPayload(static_cast<size_t>(options.state_bytes),
                         "STATE", options.client_id, ticks);
        SendPacket(client, state, true, tx::network::PacketPriority::Medium);
        ++states_sent;
        bytes_sent += state.size();
      }

      if ((ticks % static_cast<size_t>(options.event_every_ticks)) == 0) {
        base::String event =
            BuildPayload(static_cast<size_t>(options.event_bytes),
                         "EVENT", options.client_id, ticks);
        SendPacket(client, event, true, tx::network::PacketPriority::High);
        ++events_sent;
        bytes_sent += event.size();
      }

      if (options.burst_size > 0 &&
          (ticks % static_cast<size_t>(options.burst_every_ticks)) == 0) {
        for (int i = 0; i < options.burst_size; ++i) {
          base::String burst =
              BuildPayload(static_cast<size_t>(options.snapshot_bytes),
                           "BURST", options.client_id, ticks);
          SendPacket(client, burst, false, tx::network::PacketPriority::Low);
          ++bursts_sent;
          bytes_sent += burst.size();
        }
      }
    }

    for (int i = 0; i < 50; ++i) {
      incoming_packets += DrainIncoming(client);
      base::SleepForMilliseconds(2);
    }

    const double elapsed = (base::TimeTicks::Now() - start_time).InSecondsF();
    const size_t total_packets_sent =
        snapshots_sent + states_sent + events_sent + bursts_sent;
    const double pps = elapsed > 0.0
                           ? static_cast<double>(total_packets_sent) / elapsed
                           : 0.0;
    const double mbps =
        elapsed > 0.0 ? (static_cast<double>(bytes_sent) * 8.0) /
                            (elapsed * 1024.0 * 1024.0)
                      : 0.0;

    // %g matches the iostream default the output format was written for.
    printf(
        "[client %d] ticks=%zu sent_packets=%zu snapshots=%zu states=%zu "
        "events=%zu bursts=%zu sent_bytes=%zu incoming_packets=%zu "
        "avg_pps=%g avg_mbps=%g\n",
        options.client_id, ticks, total_packets_sent, snapshots_sent,
        states_sent, events_sent, bursts_sent, bytes_sent, incoming_packets,
        pps, mbps);
  }

  tx::network::ZDumpPacketAllocatorStats();
  printf("Client shutting down.\n");
  client.Disconnect();
  return 0;
}
