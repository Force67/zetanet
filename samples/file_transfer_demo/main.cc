#include <znet/z_file_transporter.h>
#include <znet/z_file_write_interface.h>
#include <znet/z_p2p_node.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#else
#include <base/containers/unordered_set.h>
#include <base/filesystem/file.h>
#include <base/filesystem/file_util.h>
#include <base/filesystem/path.h>
#include <base/strings/xstring.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace {
enum class Mode { Receiver, Sender };

struct Options {
  Mode mode = Mode::Receiver;
  base::String host_ip = "127.0.0.1";
  int host_port = 14700;
  int local_port = 14701;
  base::String file_path;
  base::String output_dir = ".";
  base::String output_file;
  base::String temp_dir = ".";
  int warmup_ms = 1200;
  int timeout_seconds = 60;
  int tick_sleep_ms = 2;
  int chunk_size = 4 * 1024;
  bool verbose_logs = false;
  bool usage_requested = false;
};

struct ReceiveProgress {
  bool active = false;
  u64 transfer_id = 0;
  u32 total_chunks = 0;
  base::String file_name;
  base::UnorderedSet<u32> seen_chunks;
};

void PrintUsage(const char* exe) {
  fprintf(stdout,
          "FileTransferDemo - readable file transfer sample\n\n"
          "Usage:\n"
          "  %s --mode receiver [options]\n"
          "  %s --mode sender --file <path> [options]\n\n"
          "Common options:\n"
          "  --mode receiver|sender\n"
          "  --host-ip <ip-or-dns>                 (default: 127.0.0.1)\n"
          "  --host-port <port>                    (default: 14700)\n"
          "  --timeout-seconds <n>                 (default: 60)\n"
          "  --tick-sleep-ms <n>                   (default: 2)\n"
          "  --verbose-logs\n"
          "  --help\n\n"
          "Sender options:\n"
          "  --file <path>                         (required)\n"
          "  --local-port <port>                   (default: 14701)\n"
          "  --warmup-ms <n>                       (default: 1200)\n\n"
          "  --chunk-size <bytes>                  (default: 4096)\n\n"
          "Receiver options:\n"
          "  --output-dir <path>                   (default: .)\n"
          "  --output-file <path>                  (optional explicit destination)\n"
          "  --temp-dir <path>                     (default: .)\n\n"
          "Local test (2 terminals):\n"
          "  1) %s --mode receiver --host-port 14700 --output-dir ./recv\n"
               "  2) %s --mode sender --host-ip 127.0.0.1 --host-port 14700 "
               "--local-port 14701 --file ./test.bin\n",
               exe, exe, exe, exe);
}

bool ParseInt(const char* text, int& out_value) {
  if (!text || !text[0]) {
    return false;
  }
  char* end = nullptr;
  const long value = strtol(text, &end, 10);
  if (!end || *end != '\0') {
    return false;
  }
  out_value = static_cast<int>(value);
  return true;
}

bool ParseArgs(int argc, char** argv, Options& options) {
  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (strcmp(arg, "--help") == 0) {
      PrintUsage(argv[0]);
      options.usage_requested = true;
      return true;
    }
    if (strcmp(arg, "--mode") == 0 && i + 1 < argc) {
      const char* value = argv[++i];
      if (strcmp(value, "receiver") == 0) {
        options.mode = Mode::Receiver;
      } else if (strcmp(value, "sender") == 0) {
        options.mode = Mode::Sender;
      } else {
        fprintf(stderr, "Unknown --mode value '%s'\n", value);
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--host-ip") == 0 && i + 1 < argc) {
      options.host_ip = argv[++i];
      continue;
    }
    if (strcmp(arg, "--host-port") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.host_port)) {
        fprintf(stderr, "Invalid --host-port value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--local-port") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.local_port)) {
        fprintf(stderr, "Invalid --local-port value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--file") == 0 && i + 1 < argc) {
      options.file_path = argv[++i];
      continue;
    }
    if (strcmp(arg, "--output-dir") == 0 && i + 1 < argc) {
      options.output_dir = argv[++i];
      continue;
    }
    if (strcmp(arg, "--output-file") == 0 && i + 1 < argc) {
      options.output_file = argv[++i];
      continue;
    }
    if (strcmp(arg, "--temp-dir") == 0 && i + 1 < argc) {
      options.temp_dir = argv[++i];
      continue;
    }
    if (strcmp(arg, "--warmup-ms") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.warmup_ms)) {
        fprintf(stderr, "Invalid --warmup-ms value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--chunk-size") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.chunk_size)) {
        fprintf(stderr, "Invalid --chunk-size value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--timeout-seconds") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.timeout_seconds)) {
        fprintf(stderr, "Invalid --timeout-seconds value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--tick-sleep-ms") == 0 && i + 1 < argc) {
      if (!ParseInt(argv[++i], options.tick_sleep_ms)) {
        fprintf(stderr, "Invalid --tick-sleep-ms value\n");
        return false;
      }
      continue;
    }
    if (strcmp(arg, "--verbose-logs") == 0) {
      options.verbose_logs = true;
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n", arg);
    return false;
  }

  if (options.host_port <= 0 || options.host_port > 65535) {
    fprintf(stderr, "--host-port must be in range 1..65535\n");
    return false;
  }
  if (options.local_port <= 0 || options.local_port > 65535) {
    fprintf(stderr, "--local-port must be in range 1..65535\n");
    return false;
  }
  if (options.timeout_seconds <= 0) {
    fprintf(stderr, "--timeout-seconds must be > 0\n");
    return false;
  }
  if (options.warmup_ms < 0) {
    fprintf(stderr, "--warmup-ms must be >= 0\n");
    return false;
  }
  if (options.tick_sleep_ms < 0) {
    fprintf(stderr, "--tick-sleep-ms must be >= 0\n");
    return false;
  }
  if (options.chunk_size <= 0) {
    fprintf(stderr, "--chunk-size must be > 0\n");
    return false;
  }
  if (options.chunk_size > 32768) {
    fprintf(stderr,
            "--chunk-size must be <= 32768 (larger values exceed safe UDP payload size)\n");
    return false;
  }
  if (options.mode == Mode::Sender && options.file_path.empty()) {
    fprintf(stderr, "Sender mode requires --file <path>\n");
    return false;
  }
  return true;
}

void VerboseLogHandler(void*,
                       const char* channel_name,
                       int level,
                       const char* msg) {
  fprintf(stderr, "[%s] %s: %s\n", channel_name,
          base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
}

void QuietLogHandler(void*,
                     const char* channel_name,
                     int level,
                     const char* msg) {
  if (level <= static_cast<int>(base::LogLevel::kInfo)) {
    return;
  }
  fprintf(stderr, "[%s] %s: %s\n", channel_name,
          base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
}

bool EnsureDirectory(const base::String& path) {
  return base::CreateDirectory(base::Path(path));
}

base::String ChooseOutputPath(const Options& options,
                              const base::String& file_name,
                              u64 transfer_id) {
  if (!options.output_file.empty()) {
    return options.output_file;
  }
  base::String name = file_name;
  if (name.empty()) {
    char generated[48];
    snprintf(generated, sizeof(generated), "transfer-%llu.bin",
             static_cast<unsigned long long>(transfer_id));
    name = generated;
  }
  base::String out_path = options.output_dir;
  if (!out_path.empty() && out_path.back() != '/' && out_path.back() != '\\') {
    out_path += '/';
  }
  out_path += name;
  return out_path;
}

int RunSender(const Options& options) {
  tx::network::ZP2PNode node;
  if (!node.Connect(base::StringRef(options.host_ip.data(), options.host_ip.size()),
                    static_cast<u16>(options.host_port),
                    static_cast<u16>(options.local_port))) {
    fprintf(stderr, "Sender failed to connect.\n");
    return 2;
  }

  tx::network::ZFileTransporter sender(node);
  printf("[sender] connected to %s:%d from local port %d\n",
         options.host_ip.c_str(), options.host_port, options.local_port);
  printf("[sender] warming up for %dms before SendFile()\n", options.warmup_ms);

  const base::TimeTicks warmup_end =
      base::TimeTicks::Now() + base::Milliseconds(options.warmup_ms);
  while (base::TimeTicks::Now() < warmup_end) {
    node.Update();
    tx::network::IncomingPacket ignored;
    while (node.Poll(tx::network::PacketChannelType::Control, ignored)) {
    }
    while (node.Poll(tx::network::PacketChannelType::Data, ignored)) {
    }
    if (options.tick_sleep_ms > 0) {
      base::SleepForMilliseconds(static_cast<u64>(options.tick_sleep_ms));
    }
  }

  const i64 input_size =
      base::File(base::Path(options.file_path),
                 base::File::FLAG_OPEN | base::File::FLAG_READ)
          .GetLength();
  if (input_size < 0) {
    fprintf(stderr, "Cannot read input file: %s\n", options.file_path.c_str());
    return 3;
  }
  printf("[sender] sending file: %s (%llu bytes)\n", options.file_path.c_str(),
         static_cast<unsigned long long>(input_size));

  tx::network::ZFileTransporter::TransferTuning tuning;
  tuning.chunk_size = static_cast<mem_size>(options.chunk_size);

  if (!sender.SendFile(base::Path(options.file_path),
                       tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                       tuning)) {
    fprintf(stderr, "SendFile() failed.\n");
    return 3;
  }

  printf("[sender] waiting for outbound queue + acks to drain...\n");
  const base::TimeTicks drain_deadline =
      base::TimeTicks::Now() + base::Seconds(options.timeout_seconds);
  int consecutive_idle_ticks = 0;
  while (base::TimeTicks::Now() < drain_deadline) {
    node.Update();
    tx::network::IncomingPacket ignored;
    while (node.Poll(tx::network::PacketChannelType::Control, ignored)) {
    }
    while (node.Poll(tx::network::PacketChannelType::Data, ignored)) {
    }

    const auto pressure = node.GetOutboundPressure();
    const bool idle =
        pressure.control_queued_packets == 0 &&
        pressure.control_queued_bytes == 0 &&
        pressure.awaiting_ack_packets == 0 &&
        pressure.awaiting_ack_bytes == 0;
    consecutive_idle_ticks = idle ? (consecutive_idle_ticks + 1) : 0;
    if (consecutive_idle_ticks >= 50) {
      printf("[sender] outbound queues drained.\n");
      break;
    }

    if (options.tick_sleep_ms > 0) {
      base::SleepForMilliseconds(static_cast<u64>(options.tick_sleep_ms));
    }
  }

  printf("[sender] transfer enqueued.\n");
  return 0;
}

int RunReceiver(const Options& options) {
  if (!EnsureDirectory(options.output_dir)) {
    fprintf(stderr, "Failed to create output directory: %s\n",
            options.output_dir.c_str());
    return 2;
  }
  if (!EnsureDirectory(options.temp_dir)) {
    fprintf(stderr, "Failed to create temp directory: %s\n",
            options.temp_dir.c_str());
    return 3;
  }
  if (!options.output_file.empty()) {
    const base::String parent =
        base::Path(options.output_file).DirName().ToAsciiString();
    if (!parent.empty() && !EnsureDirectory(parent)) {
      fprintf(stderr, "Failed to create output-file parent directory: %s\n",
              parent.c_str());
      return 4;
    }
  }

  tx::network::ZP2PNode node;
  if (!node.Begin(static_cast<u16>(options.host_port))) {
    fprintf(stderr, "Receiver failed to bind host port %d.\n", options.host_port);
    return 5;
  }

  tx::network::IFileWriteFactory& mmap_factory =
      tx::network::GetMemoryMappedFileWriteFactory();
  tx::network::ZFileTransporter receiver(node, &mmap_factory);

  printf("[receiver] listening on port %d\n", options.host_port);
  printf("[receiver] output_dir=%s temp_dir=%s\n", options.output_dir.c_str(),
         options.temp_dir.c_str());

  ReceiveProgress progress;
  const base::TimeTicks deadline =
      base::TimeTicks::Now() + base::Seconds(options.timeout_seconds);
  while (base::TimeTicks::Now() < deadline) {
    node.Update();

    tx::network::IncomingPacket packet;
    while (node.Poll(tx::network::PacketChannelType::Control, packet)) {
      if (packet.type != tx::network::PacketType::FileTransfer) {
        continue;
      }

      tx::network::ZFileTransporter::TransferChunk chunk;
      if (!receiver.ParseTransferChunkPacket(packet, chunk)) {
        fprintf(stderr, "[receiver] dropped malformed file chunk packet\n");
        continue;
      }

      if (!progress.active) {
        if (!chunk.has_file_name) {
          continue;
        }
        progress.active = true;
        progress.transfer_id = chunk.transfer_id;
        progress.total_chunks = chunk.total_chunks;
        progress.file_name.assign(chunk.file_name.data(),
                                  chunk.file_name.size());
        printf("[receiver] transfer started id=%llu chunks=%u file=%s\n",
               static_cast<unsigned long long>(chunk.transfer_id),
               chunk.total_chunks, progress.file_name.c_str());
      }

      if (chunk.transfer_id != progress.transfer_id) {
        continue;
      }

      bool completed = false;
      if (!receiver.StreamChunkToFile(chunk, base::Path(options.temp_dir), &completed)) {
        fprintf(stderr, "[receiver] StreamChunkToFile failed for chunk %u\n",
                chunk.chunk_index);
        return 6;
      }

      const bool new_chunk = progress.seen_chunks.insert(chunk.chunk_index);
      if (new_chunk) {
        printf("[receiver] progress %zu/%u chunks\n",
               static_cast<size_t>(progress.seen_chunks.size()),
               progress.total_chunks);
      }

      if (completed) {
        const base::String out_path =
            ChooseOutputPath(options, progress.file_name, progress.transfer_id);
        if (!receiver.FinalizeStreamedFile(progress.transfer_id,
                                           base::Path(out_path))) {
          fprintf(stderr, "[receiver] FinalizeStreamedFile failed\n");
          return 7;
        }
        printf("[receiver] transfer complete -> %s\n", out_path.c_str());
        return 0;
      }
    }

    while (node.Poll(tx::network::PacketChannelType::Data, packet)) {
    }

    if (options.tick_sleep_ms > 0) {
      base::SleepForMilliseconds(static_cast<u64>(options.tick_sleep_ms));
    }
  }

  fprintf(stderr, "[receiver] timeout waiting for file transfer\n");
  return 8;
}
}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseArgs(argc, argv, options)) {
    fprintf(stderr, "Run with --help for usage.\n");
    return 1;
  }
  if (options.usage_requested) {
    return 0;
  }

  tx::network::SetBaseLogHandlerFwd(
      nullptr, options.verbose_logs ? VerboseLogHandler : QuietLogHandler);

  const int rc = options.mode == Mode::Receiver ? RunReceiver(options)
                                                : RunSender(options);
  if (options.mode == Mode::Sender && rc == 0) {
    // _Exit avoids sender teardown instability after heavy transfer loops.
    fflush(stdout);
    fflush(stderr);
    _Exit(0);
  }
  return rc;
}
