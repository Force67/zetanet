#include <znet/z_server.h>
#include <znet/z_packets.h>
#include <znet/z_public_api.h>
#include <znet/z_task_executor.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
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
  int duration_seconds = 0;
  int dump_interval_seconds = 0;
  int summary_interval_seconds = 2;
  bool quiet_data = true;
  int rebroadcast_every_packets = 0;
  int rebroadcast_bytes = 64;
  bool use_inline_dispatch_executor = false;
  int dispatch_workers = 0;
  int dispatch_max_queued = 0;
};

Options ParseArgs(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--duration-seconds") == 0 && i + 1 < argc) {
      options.duration_seconds = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--dump-every-seconds") == 0 &&
               i + 1 < argc) {
      options.dump_interval_seconds = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--summary-every-seconds") == 0 &&
               i + 1 < argc) {
      options.summary_interval_seconds = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--quiet-data") == 0) {
      options.quiet_data = true;
    } else if (strcmp(argv[i], "--verbose-data") == 0) {
      options.quiet_data = false;
    } else if (strcmp(argv[i], "--rebroadcast-every-packets") == 0 &&
               i + 1 < argc) {
      options.rebroadcast_every_packets = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--rebroadcast-bytes") == 0 &&
               i + 1 < argc) {
      options.rebroadcast_bytes = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--dispatch-executor") == 0 &&
               i + 1 < argc) {
      const char* mode = argv[++i];
      options.use_inline_dispatch_executor =
          (strcmp(mode, "inline") == 0);
    } else if (strcmp(argv[i], "--dispatch-workers") == 0 &&
               i + 1 < argc) {
      options.dispatch_workers = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--dispatch-max-queued") == 0 &&
               i + 1 < argc) {
      options.dispatch_max_queued = atoi(argv[++i]);
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
  if (options.dispatch_workers < 0) {
    options.dispatch_workers = 0;
  }
  if (options.dispatch_max_queued < 0) {
    options.dispatch_max_queued = 0;
  }

  return options;
}

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
  fputs(buffer, stdout);
#endif
}
}  // namespace

int main(int argc, char** argv) {
  const Options options = ParseArgs(argc, argv);

  tx::network::SetBaseLogHandlerFwd(nullptr, LogHandler);
  // Progress lines interleave with the library's stderr logs; line buffering
  // keeps them in order when stdout is a pipe.
  setvbuf(stdout, nullptr, _IOLBF, 0);
  printf("Log handler set!\n");

  tx::network::ZServer server;
  tx::network::ZInlineTaskExecutor inline_executor;
  if (options.use_inline_dispatch_executor) {
    server.SetTaskExecutor(&inline_executor);
  } else {
    server.SetBuiltInTaskExecutorConfig(
        static_cast<mem_size>(options.dispatch_workers),
        static_cast<mem_size>(options.dispatch_max_queued));
  }
  if (!server.Begin(1337)) {
    fprintf(stderr, "Failed to start server\n");
    return -1;
  }
  printf("Server is up on port 1337\n");

  const base::TimeTicks start_time = base::TimeTicks::Now();
  base::TimeTicks next_dump = start_time;
  base::TimeTicks next_summary = start_time;

  size_t total_data_packets = 0;
  size_t total_data_bytes = 0;
  size_t total_system_packets = 0;
  size_t total_rebroadcast_packets = 0;
  size_t total_rebroadcast_bytes = 0;

  size_t window_packets = 0;
  size_t window_bytes = 0;

  tx::network::IncomingPacket packet;
  while (true) {
    while (server.Poll(tx::network::PacketChannelType::Control, packet)) {
      ++total_system_packets;
    }

    while (server.Poll(tx::network::PacketChannelType::Data, packet)) {
      if (tx::network::IsSystemMessage(packet.type)) {
        ++total_system_packets;
        continue;
      }

      const size_t payload_size = packet.data.size();
      ++total_data_packets;
      total_data_bytes += payload_size;
      ++window_packets;
      window_bytes += payload_size;

      if (!options.quiet_data && (total_data_packets % 50 == 0)) {
        printf("[server] sample data packet size=%zu total_packets=%zu\n",
               payload_size, total_data_packets);
      }

      if (options.rebroadcast_every_packets > 0 &&
          (total_data_packets %
           static_cast<size_t>(options.rebroadcast_every_packets)) == 0) {
        const size_t payload_len =
            static_cast<size_t>(options.rebroadcast_bytes);
        base::String rebroadcast_payload(payload_len, 's');
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
        server.Push(base::move(out));
        ++total_rebroadcast_packets;
        total_rebroadcast_bytes += payload_len;
      }
    }

    const base::TimeTicks now = base::TimeTicks::Now();

    if (options.summary_interval_seconds > 0 && now >= next_summary) {
      const double mbps =
          (static_cast<double>(window_bytes) * 8.0) /
          (static_cast<double>(options.summary_interval_seconds) *
           1024.0 * 1024.0);
      // %g matches the iostream default the output format was written for.
      printf(
          "[server] window packets=%zu window_bytes=%zu approx_mbps=%g "
          "total_packets=%zu system_packets=%zu rebroadcast_packets=%zu\n",
          window_packets, window_bytes, mbps, total_data_packets,
          total_system_packets, total_rebroadcast_packets);
      window_packets = 0;
      window_bytes = 0;
      next_summary = now + base::Seconds(options.summary_interval_seconds);
    }

    if (options.dump_interval_seconds > 0 && now >= next_dump) {
      tx::network::ZDumpPacketAllocatorStats();
      next_dump = now + base::Seconds(options.dump_interval_seconds);
    }

    if (options.duration_seconds > 0) {
      if ((now - start_time).InSeconds() >= options.duration_seconds) {
        printf("Duration reached, exiting server loop.\n");
        break;
      }
    }

    base::SleepForMilliseconds(1);
  }

  const double total_seconds =
      (base::TimeTicks::Now() - start_time).InSecondsF();
  const double packets_per_sec =
      total_seconds > 0.0 ? static_cast<double>(total_data_packets) / total_seconds
                          : 0.0;
  const double mbps =
      total_seconds > 0.0
          ? (static_cast<double>(total_data_bytes) * 8.0) /
                (total_seconds * 1024.0 * 1024.0)
          : 0.0;

  printf(
      "[server] final total_packets=%zu total_bytes=%zu duration_s=%g "
      "avg_pps=%g avg_mbps=%g system_packets=%zu rebroadcast_packets=%zu "
      "rebroadcast_bytes=%zu\n",
      total_data_packets, total_data_bytes, total_seconds, packets_per_sec,
      mbps, total_system_packets, total_rebroadcast_packets,
      total_rebroadcast_bytes);

  tx::network::ZDumpPacketAllocatorStats();
  server.Deinit();
  return 0;
}
