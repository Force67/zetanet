// Copyright (C) 2023-2026 Vincent Hengel
// For licensing information see LICENSE at the root of this distribution.
//
// End-to-end multiplayer integration tests: every (encryption x compression x
// reliable) combination, at codec level and over a UDP loopback pair. Run by CI.

#include <znet/z_bit_reader.h>
#include <znet/z_bit_traits.h>
#include <znet/z_bit_writer.h>
#include <znet/z_client.h>
#include <znet/z_crypto_wrapper.h>
#include <znet/z_file_transporter.h>
#include <znet/z_file_write_interface.h>
#include <znet/z_p2p_node.h>
#include <znet/z_packet_serdes.h>
#include <znet/z_packets.h>
#include <znet/z_server.h>
#include <znet/z_socket.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

using tx::network::IncomingPacket;
using tx::network::OutgoingPacket;
using tx::network::PackageFlags;
using tx::network::PacketBuilder;
using tx::network::PacketChannelType;
using tx::network::PacketPriority;
using tx::network::PacketType;
using tx::network::PacketUnpacker;
using tx::network::ZClient;
using tx::network::ZCryptoContext;
using tx::network::ZPeerId;
using tx::network::ZServer;

constexpr char kTestPsk[] = "0123456789abcdef0123456789abcdef";
const base::StringRef kTestPskRef{kTestPsk, sizeof(kTestPsk) - 1};

u16 NextPort() {
  static std::atomic<u16> next_port{19050};
  return static_cast<u16>(next_port.fetch_add(1));
}

// LZ4 only shrinks redundant input; repeat a small alphabet so compression
// triggers instead of falling into PacketBuilder's "didn't help" branch.
std::string MakeCompressiblePayload(std::size_t bytes, std::uint32_t seed) {
  std::string out;
  out.reserve(bytes);
  std::mt19937 rng(seed);
  static constexpr char kAlphabet[] = "abcdefghijklmnop";
  while (out.size() < bytes) {
    const std::size_t run = 4 + (rng() % 12);
    const char ch = kAlphabet[rng() % (sizeof(kAlphabet) - 1)];
    for (std::size_t i = 0; i < run && out.size() < bytes; ++i) {
      out.push_back(ch);
    }
  }
  return out;
}

template <typename Fn>
bool WaitForCondition(int timeout_ms, Fn&& fn) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  while (std::chrono::steady_clock::now() < deadline) {
    if (fn()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return fn();
}

struct CodecCase {
  bool reliable;
  bool encrypted;
  bool compressed;
};

bool CodecRoundtripOnce(const CodecCase& c,
                        const std::string& payload,
                        ZCryptoContext* tx_crypto,
                        ZCryptoContext* rx_crypto) {
  const PackageFlags flags{.reliable = static_cast<u8>(c.reliable ? 1 : 0),
                           .encrypted = static_cast<u8>(c.encrypted ? 1 : 0),
                           .compressed = static_cast<u8>(c.compressed ? 1 : 0),
                           .priority = static_cast<u8>(PacketPriority::Medium),
                           .acknowledged = 0,
                           .awaiting_ack = static_cast<u8>(c.reliable ? 1 : 0),
                           .reserved = 0};
  OutgoingPacket out(
      ZPeerId::to_server, PacketType::Message, PacketChannelType::Data, flags,
      base::Span<byte>(reinterpret_cast<const byte*>(payload.data()),
                       payload.size()));

  PacketBuilder builder(tx_crypto);
  base::Vector<byte> wire = builder.BuildPacket(out, /*sequence=*/42);
  if (wire.empty()) {
    std::fprintf(stderr,
                 "  build failed (reliable=%d encrypted=%d compressed=%d "
                 "size=%zu)\n",
                 c.reliable, c.encrypted, c.compressed, payload.size());
    return false;
  }

  PacketUnpacker unpacker(rx_crypto);
  IncomingPacket in;
  if (!unpacker.UnpackPacket(wire.data(), wire.size(), in)) {
    std::fprintf(stderr,
                 "  unpack failed (reliable=%d encrypted=%d compressed=%d "
                 "wire_size=%zu)\n",
                 c.reliable, c.encrypted, c.compressed, wire.size());
    return false;
  }
  if (in.data.size() != payload.size() ||
      std::memcmp(in.data.data(), payload.data(), payload.size()) != 0) {
    std::fprintf(stderr,
                 "  payload mismatch (reliable=%d encrypted=%d compressed=%d "
                 "expected=%zu got=%zu)\n",
                 c.reliable, c.encrypted, c.compressed, payload.size(),
                 in.data.size());
    return false;
  }
  return true;
}

// Codec-level round-trip without network or crypto context, isolating
// PacketBuilder/PacketUnpacker. Encryption needs an authenticated
// ZCryptoContext, exercised by the network tests below.
bool TestCodecRoundtrip() {
  const CodecCase cases[] = {
      {false, false, false},
      {true, false, false},
      {false, false, true},
      {true, false, true},
  };

  const std::size_t sizes[] = {32, 256, 4096, 32 * 1024};

  bool all_ok = true;
  for (const auto& c : cases) {
    for (std::size_t size : sizes) {
      const std::string payload =
          MakeCompressiblePayload(size, 0xABCDu ^ static_cast<u32>(size));
      if (!CodecRoundtripOnce(c, payload, nullptr, nullptr)) {
        all_ok = false;
      }
    }
  }

  // Incompressible payload, hitting the branch that clears the compressed
  // flag when compression does not shrink the data.
  std::string incompressible(2048, '\0');
  std::mt19937 rng(0xDEAD);
  for (auto& ch : incompressible) {
    ch = static_cast<char>(rng() & 0xFF);
  }
  const CodecCase compressed = {true, false, true};
  if (!CodecRoundtripOnce(compressed, incompressible, nullptr, nullptr)) {
    all_ok = false;
  }

  return all_ok;
}

ZServer::StartOptions MakeServerOptions(bool encryption, bool compression) {
  return ZServer::StartOptions{
      .use_encryption = encryption,
      .pre_shared_key = encryption ? kTestPskRef : base::StringRef(),
      .use_compression = compression,
      .allow_ipv6 = false,
      .start_threads = true,
      .chaos = {}};
}

ZClient::ConnectionOptions MakeClientOptions(bool encryption, bool compression) {
  return ZClient::ConnectionOptions{
      .use_encryption = encryption,
      .pre_shared_key = encryption ? kTestPskRef : base::StringRef(),
      .use_compression = compression,
      .allow_ipv6 = false,
      .start_threads = true,
      .chaos = {}};
}

bool RoundtripOverNetwork(bool encryption, bool compression) {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(encryption, compression))) {
    std::fprintf(stderr, "  server.Begin failed\n");
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port,
                       MakeClientOptions(encryption, compression))) {
    std::fprintf(stderr, "  client.Connect failed\n");
    server.Deinit();
    return false;
  }

  // The handshake state machine runs inside ProcessSystemMessage during
  // Poll(Control); drive it until both sides are connected.
  const bool connected = WaitForCondition(5000, [&]() {
    IncomingPacket pkt;
    while (server.Poll(PacketChannelType::Control, pkt)) {
    }
    while (client.Poll(PacketChannelType::Control, pkt)) {
    }
    return client.handshake_phase() == ZClient::HandshakePhase::kConnected;
  });
  if (!connected) {
    std::fprintf(stderr, "  handshake did not complete\n");
    client.Disconnect();
    server.Deinit();
    return false;
  }

  std::vector<std::string> payloads;
  payloads.push_back(MakeCompressiblePayload(64, 1));
  payloads.push_back(MakeCompressiblePayload(512, 2));
  payloads.push_back(MakeCompressiblePayload(2048, 3));
  payloads.push_back(std::string(48, 'Q'));
  payloads.push_back("hello multiplayer world");

  for (const auto& p : payloads) {
    base::String s(p.data(), p.size());
    client.SendMessage(ZPeerId(ZPeerId::to_server), s);
  }

  std::vector<std::string> received;
  const bool got_all = WaitForCondition(5000, [&]() {
    IncomingPacket pkt;
    // Keep the server-side handshake state machine running (ClientAuthProof,
    // ACKs) while data flows.
    while (server.Poll(PacketChannelType::Control, pkt)) {
    }
    while (client.Poll(PacketChannelType::Control, pkt)) {
    }
    while (server.Poll(PacketChannelType::Data, pkt)) {
      if (tx::network::IsSystemMessage(pkt.type)) {
        continue;
      }
      received.emplace_back(pkt.data.data(), pkt.data.size());
    }
    return received.size() >= payloads.size();
  });

  // Reliable retransmission does not promise in-order delivery; compare as
  // multisets.
  bool ok = got_all;
  if (got_all) {
    std::vector<std::string> expected = payloads;
    std::vector<std::string> got = received;
    std::sort(expected.begin(), expected.end());
    std::sort(got.begin(), got.end());
    if (got.size() != expected.size() || got != expected) {
      std::fprintf(stderr,
                   "  contents differ (sent %zu, got %zu unique payloads)\n",
                   expected.size(), got.size());
      ok = false;
    }
  } else {
    std::fprintf(stderr, "  only received %zu/%zu packets\n", received.size(),
                 payloads.size());
  }

  client.Disconnect();
  server.Deinit();
  return ok;
}

bool TestEndToEndPlain() { return RoundtripOverNetwork(false, false); }
bool TestEndToEndEncryptedOnly() { return RoundtripOverNetwork(true, false); }
bool TestEndToEndCompressedOnly() { return RoundtripOverNetwork(false, true); }
bool TestEndToEndEncryptedCompressed() {
  return RoundtripOverNetwork(true, true);
}

// ---------------- Bit codec tests ----------------

using tx::network::BitReader;
using tx::network::BitTraits;
using tx::network::BitWriter;
using tx::network::ZBitField;
using tx::network::ZBoolBit;
using tx::network::ZFloatRange;
using tx::network::ZIntRange;
using tx::network::ZUintMax;

#define BIT_CHECK(cond, msg)                                          \
  do {                                                                \
    if (!(cond)) {                                                    \
      std::fprintf(stderr, "  %s:%d: %s\n", __FILE__, __LINE__, msg); \
      return false;                                                   \
    }                                                                 \
  } while (0)

bool TestBitPrimitives() {
  std::vector<byte> backing(64, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.WriteBool(true);
  w.WriteBool(false);
  w.WriteBits(0xABu, 8);
  w.WriteBits(0x12345u, 20);
  w.WriteUint(7u, 100u);
  w.WriteInt(-37, -100, 100);
  w.WriteFloat(0.25f, 0.0f, 1.0f, 16);
  w.WriteUnitQuat(0.0f, 0.0f, 0.0f, 1.0f);
  w.Finalize();
  BIT_CHECK(w.ok(), "writer not ok");

  BitReader r(backing.data(), backing.size());
  bool b1 = false, b2 = true;
  u64 raw_byte = 0, raw_20 = 0;
  u32 u = 0;
  i32 i = 0;
  f32 f = 0.0f;
  f32 qx = 0, qy = 0, qz = 0, qw = 0;
  BIT_CHECK(r.ReadBool(b1) && b1 == true, "bool[0]");
  BIT_CHECK(r.ReadBool(b2) && b2 == false, "bool[1]");
  BIT_CHECK(r.ReadBits(raw_byte, 8) && raw_byte == 0xAB, "u8 raw");
  BIT_CHECK(r.ReadBits(raw_20, 20) && raw_20 == 0x12345, "20-bit raw");
  BIT_CHECK(r.ReadUint(u, 100u) && u == 7u, "uint");
  BIT_CHECK(r.ReadInt(i, -100, 100) && i == -37, "int range");
  BIT_CHECK(r.ReadFloat(f, 0.0f, 1.0f, 16) && std::abs(f - 0.25f) < 1e-3f,
            "float quant");
  BIT_CHECK(r.ReadUnitQuat(qx, qy, qz, qw) && std::abs(qw - 1.0f) < 1e-2f,
            "unit quat");
  return r.ok();
}

struct PlayerSnapshot {
  i32 health;
  f32 pos_x;
  f32 pos_y;
  bool alive;
};

}  // namespace

template <>
struct tx::network::BitTraits<::PlayerSnapshot> {
  static void Write(BitWriter& w, const ::PlayerSnapshot& s) {
    w.WriteInt(s.health, 0, 100);
    w.WriteFloat(s.pos_x, -1024.0f, 1024.0f, 18);
    w.WriteFloat(s.pos_y, -1024.0f, 1024.0f, 18);
    w.WriteBool(s.alive);
  }
  static bool Read(BitReader& r, ::PlayerSnapshot& s) {
    return r.ReadInt(s.health, 0, 100) &&
           r.ReadFloat(s.pos_x, -1024.0f, 1024.0f, 18) &&
           r.ReadFloat(s.pos_y, -1024.0f, 1024.0f, 18) && r.ReadBool(s.alive);
  }
};

namespace {

bool TestBitTraitStruct() {
  PlayerSnapshot src{77, 12.5f, -300.25f, true};
  std::vector<byte> backing(32, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.Push(src);
  w.Finalize();
  BIT_CHECK(w.ok(), "writer ok");

  BitReader r(backing.data(), backing.size());
  PlayerSnapshot dst{};
  BIT_CHECK(r.Pop(dst), "pop");
  BIT_CHECK(dst.health == src.health, "health");
  BIT_CHECK(std::abs(dst.pos_x - src.pos_x) < 0.1f, "pos_x");
  BIT_CHECK(std::abs(dst.pos_y - src.pos_y) < 0.1f, "pos_y");
  BIT_CHECK(dst.alive == src.alive, "alive");
  return true;
}

struct PosFloatSpec {
  static constexpr f32 kMin = -1024.0f;
  static constexpr f32 kMax = 1024.0f;
  static constexpr u32 kBits = 18;
};

struct ZippedSnapshot {
  ZBitField<i32, ZIntRange<0, 100>> health;
  ZBitField<u32, ZUintMax<63>> team;
  ZBitField<f32, ZFloatRange<PosFloatSpec>> px;
  ZBitField<f32, ZFloatRange<PosFloatSpec>> py;
  ZBitField<bool, ZBoolBit> alive;
};

}  // namespace

template <>
struct tx::network::BitTraits<::ZippedSnapshot> {
  static void Write(BitWriter& w, const ::ZippedSnapshot& s) {
    w.Push(s.health);
    w.Push(s.team);
    w.Push(s.px);
    w.Push(s.py);
    w.Push(s.alive);
  }
  static bool Read(BitReader& r, ::ZippedSnapshot& s) {
    return r.Pop(s.health) && r.Pop(s.team) && r.Pop(s.px) && r.Pop(s.py) &&
           r.Pop(s.alive);
  }
};

namespace {

bool TestZBitFieldStruct() {
  ZippedSnapshot src;
  src.health = 88;
  src.team = 5;
  src.px = -777.5f;
  src.py = 250.125f;
  src.alive = true;

  std::vector<byte> backing(32, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.Push(src);
  w.Finalize();
  BIT_CHECK(w.ok(), "writer ok");

  BitReader r(backing.data(), backing.size());
  ZippedSnapshot dst;
  BIT_CHECK(r.Pop(dst), "pop");
  BIT_CHECK(static_cast<i32>(dst.health) == 88, "health");
  BIT_CHECK(static_cast<u32>(dst.team) == 5u, "team");
  BIT_CHECK(std::abs(static_cast<f32>(dst.px) - src.px) < 0.1f, "px");
  BIT_CHECK(std::abs(static_cast<f32>(dst.py) - src.py) < 0.1f, "py");
  BIT_CHECK(static_cast<bool>(dst.alive) == true, "alive");
  return true;
}

// End-to-end: BitWriter fills an OutgoingPacket in place, the packet crosses
// a real ZServer/ZClient pair, the receiver decodes with BitReader.
bool TestBitWriterIntoPacketEndToEnd() {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(false, false))) {
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port, MakeClientOptions(false, false))) {
    server.Deinit();
    return false;
  }

  const bool connected = WaitForCondition(5000, [&]() {
    IncomingPacket pkt;
    while (server.Poll(PacketChannelType::Control, pkt)) {
    }
    while (client.Poll(PacketChannelType::Control, pkt)) {
    }
    return client.handshake_phase() == ZClient::HandshakePhase::kConnected;
  });
  if (!connected) {
    client.Disconnect();
    server.Deinit();
    return false;
  }

  PlayerSnapshot src{63, 17.5f, -400.5f, true};

  const tx::network::PackageFlags flags{
      .reliable = 1,
      .encrypted = 0,
      .compressed = 0,
      .priority = static_cast<u8>(PacketPriority::Medium),
      .acknowledged = 0,
      .awaiting_ack = 1,
      .reserved = 0};
  OutgoingPacket pkt(ZPeerId::to_server, PacketType::Message,
                     PacketChannelType::Data, flags);
  {
    BitWriter w(pkt, /*reserve_bytes=*/64);
    w.Push(src);
    w.Finalize();
    BIT_CHECK(w.ok(), "bit writer ok");
  }
  client.Push(std::move(pkt));

  std::vector<std::string> received;
  const bool got = WaitForCondition(5000, [&]() {
    IncomingPacket inc;
    while (server.Poll(PacketChannelType::Control, inc)) {
    }
    while (server.Poll(PacketChannelType::Data, inc)) {
      if (tx::network::IsSystemMessage(inc.type)) continue;
      received.emplace_back(inc.data.data(), inc.data.size());
    }
    return !received.empty();
  });

  bool ok = got;
  if (got) {
    BitReader r(reinterpret_cast<const byte*>(received[0].data()),
                received[0].size());
    PlayerSnapshot dst{};
    if (!r.Pop(dst)) {
      ok = false;
    } else {
      ok = (dst.health == src.health) &&
           (std::abs(dst.pos_x - src.pos_x) < 0.1f) &&
           (std::abs(dst.pos_y - src.pos_y) < 0.1f) && (dst.alive == src.alive);
    }
  }

  client.Disconnect();
  server.Deinit();
  return ok;
}

// Regression: a full u64 written while the scratch accumulator holds 1..7
// bits, at every non-byte-aligned starting offset.
bool TestBitWriter64BitAtOffset() {
  static const u64 kValues[] = {
      0xFFFFFFFFFFFFFFFFull, 0x0123456789ABCDEFull, 0x8000000000000001ull,
      0xDEADBEEFCAFEBABEull, 0x00000000FFFFFFFFull, 0xFFFFFFFF00000000ull};

  for (u32 prefix_bits = 0; prefix_bits <= 16; ++prefix_bits) {
    for (const u64 value : kValues) {
      std::vector<byte> backing(64, byte{0});
      BitWriter w(base::Span<byte>(backing.data(), backing.size()));
      const u32 prefix_value = prefix_bits == 0 ? 0u : 0x5u;
      if (prefix_bits > 0) {
        w.WriteBits(prefix_value, prefix_bits);
      }
      w.WriteBits(value, 64);
      w.Finalize();
      BIT_CHECK(w.ok(), "writer not ok writing u64 at offset");

      BitReader r(backing.data(), backing.size());
      u64 prefix_back = 0;
      if (prefix_bits > 0) {
        BIT_CHECK(r.ReadBits(prefix_back, prefix_bits), "read prefix");
        BIT_CHECK(prefix_back == (prefix_value & ((u64{1} << prefix_bits) - 1)),
                  "prefix mismatch");
      }
      u64 value_back = 0;
      BIT_CHECK(r.ReadBits(value_back, 64), "read u64");
      if (value_back != value) {
        std::fprintf(stderr,
                     "  u64 mismatch at prefix_bits=%u: wrote %016llx got "
                     "%016llx\n",
                     prefix_bits, static_cast<unsigned long long>(value),
                     static_cast<unsigned long long>(value_back));
        return false;
      }
    }
  }

  // BitTraits<u64> after an odd-width field, the shape that triggered the bug.
  std::vector<byte> backing(32, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.WriteBool(true);
  BitTraits<u64>::Write(w, 0xA5A5A5A5A5A5A5A5ull);
  w.Finalize();
  BIT_CHECK(w.ok(), "trait writer ok");
  BitReader r(backing.data(), backing.size());
  bool flag = false;
  u64 round_trip = 0;
  BIT_CHECK(r.ReadBool(flag) && flag, "trait bool");
  BIT_CHECK(BitTraits<u64>::Read(r, round_trip), "trait u64 read");
  BIT_CHECK(round_trip == 0xA5A5A5A5A5A5A5A5ull, "trait u64 value");
  return true;
}

base::Path MakeBasePath(const std::string& path) {
#ifdef ZNET_USE_STL
  return base::Path(path);
#else
  return base::Path(path.c_str());
#endif
}

// In-process file transfer over a loopback ZP2PNode pair, covering chunking,
// reassembly, the memory-mapped writer, and the p2p control plane.
bool TestFileTransferEndToEnd() {
  namespace fs = std::filesystem;
  std::error_code ec;
  // Relative work directory: absolute output paths are rejected by the
  // transporter, and relative paths keep the rename on one filesystem.
  const fs::path work_dir =
      fs::path("znet_ft_" +
               std::to_string(static_cast<unsigned long long>(NextPort())));
  fs::create_directories(work_dir, ec);
  const fs::path input_path = work_dir / "source.bin";
  const fs::path temp_dir = work_dir / "tmp";
  const fs::path output_path = work_dir / "received.bin";
  fs::create_directories(temp_dir, ec);

  std::string content;
  {
    std::mt19937 rng(0xF11E);
    content.reserve(15000u);
    while (content.size() < 15000u) {
      const char ch = static_cast<char>(rng() & 0xFF);
      content.push_back(ch);
    }
  }
  {
    std::ofstream out(input_path, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
  }

  auto cleanup = [&]() {
    std::error_code rm_ec;
    fs::remove_all(work_dir, rm_ec);
  };

  const u16 host_port = NextPort();
  const u16 sender_port = NextPort();

  tx::network::ZP2PNode receiver_node;
  if (!receiver_node.Begin(host_port)) {
    std::fprintf(stderr, "  receiver Begin failed\n");
    cleanup();
    return false;
  }
  tx::network::IFileWriteFactory& mmap_factory =
      tx::network::GetMemoryMappedFileWriteFactory();
  tx::network::ZFileTransporter receiver(receiver_node, &mmap_factory);

  tx::network::ZP2PNode sender_node;
  if (!sender_node.Connect(base::StringRef("127.0.0.1", 9), host_port,
                           sender_port)) {
    std::fprintf(stderr, "  sender Connect failed\n");
    cleanup();
    return false;
  }
  tx::network::ZFileTransporter sender(sender_node);

  auto pump = [&]() {
    tx::network::IncomingPacket ignored;
    sender_node.Update();
    while (sender_node.Poll(tx::network::PacketChannelType::Control, ignored)) {
    }
    while (sender_node.Poll(tx::network::PacketChannelType::Data, ignored)) {
    }
  };

  // Warm up the p2p connection before sending.
  const auto warmup_end =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(800);
  while (std::chrono::steady_clock::now() < warmup_end) {
    pump();
    tx::network::IncomingPacket ignored;
    receiver_node.Update();
    while (receiver_node.Poll(tx::network::PacketChannelType::Control,
                              ignored)) {
    }
    while (receiver_node.Poll(tx::network::PacketChannelType::Data, ignored)) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  tx::network::ZFileTransporter::TransferTuning tuning;
  tuning.chunk_size = 1024;
  if (!sender.SendFile(MakeBasePath(input_path.string()),
                       tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                       tuning)) {
    std::fprintf(stderr, "  SendFile failed\n");
    cleanup();
    return false;
  }

  // The session exists only after the file-name-bearing chunk 0 arrives, and
  // received chunks are ACKed so they are never retransmitted. Buffer early
  // chunks and stream them once the session exists.
  std::map<u32, tx::network::ZFileTransporter::TransferChunk> pending;
  std::unordered_set<u32> streamed;
  bool have_transfer = false;
  u64 transfer_id = 0;
  bool completed = false;

  auto drain_pending = [&]() -> bool {
    if (pending.find(0) == pending.end()) {
      return true;  // wait for chunk 0 to bootstrap the session
    }
    for (auto& [index, chunk] : pending) {
      if (streamed.count(index)) {
        continue;
      }
      bool chunk_completed = false;
      if (!receiver.StreamChunkToFile(chunk, MakeBasePath(temp_dir.string()),
                                      &chunk_completed)) {
        std::fprintf(stderr, "  StreamChunkToFile failed for chunk %u\n", index);
        return false;
      }
      streamed.insert(index);
      if (chunk_completed) {
        if (!receiver.FinalizeStreamedFile(
                transfer_id, MakeBasePath(output_path.string()))) {
          std::fprintf(stderr, "  FinalizeStreamedFile failed\n");
          return false;
        }
        completed = true;
        return true;
      }
    }
    return true;
  };

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(20);
  while (!completed && std::chrono::steady_clock::now() < deadline) {
    pump();
    receiver_node.Update();

    tx::network::IncomingPacket packet;
    while (receiver_node.Poll(tx::network::PacketChannelType::Control,
                              packet)) {
      if (packet.type != tx::network::PacketType::FileTransfer) {
        continue;
      }
      tx::network::ZFileTransporter::TransferChunk chunk;
      if (!receiver.ParseTransferChunkPacket(packet, chunk)) {
        continue;
      }
      if (!have_transfer) {
        have_transfer = true;
        transfer_id = chunk.transfer_id;
      }
      if (chunk.transfer_id != transfer_id) {
        continue;
      }
      const u32 index = chunk.chunk_index;
      pending.emplace(index, std::move(chunk));
    }
    while (receiver_node.Poll(tx::network::PacketChannelType::Data, packet)) {
    }

    if (!drain_pending()) {
      cleanup();
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  if (!completed) {
    std::fprintf(stderr, "  transfer did not complete (%zu/%zu chunks buffered)\n",
                 streamed.size(), pending.size());
    cleanup();
    return false;
  }

  std::string received;
  {
    std::ifstream in(output_path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    received = ss.str();
  }

  const bool ok = received.size() == content.size() && received == content;
  if (!ok) {
    std::fprintf(stderr, "  content mismatch (sent %zu, got %zu bytes)\n",
                 content.size(), received.size());
  }
  cleanup();
  return ok;
}

}  // namespace

int main(int /*argc*/, char** /*argv*/) {
  struct TestCase {
    const char* name;
    bool (*fn)();
  };

  const TestCase tests[] = {
      {"codec_roundtrip_all_combinations", &TestCodecRoundtrip},
      {"network_plain", &TestEndToEndPlain},
      {"network_encrypted_only", &TestEndToEndEncryptedOnly},
      {"network_compressed_only", &TestEndToEndCompressedOnly},
      {"network_encrypted_compressed", &TestEndToEndEncryptedCompressed},
      {"bit_primitives", &TestBitPrimitives},
      {"bit_trait_struct", &TestBitTraitStruct},
      {"bit_zbitfield_struct", &TestZBitFieldStruct},
      {"bit_writer_into_packet_e2e", &TestBitWriterIntoPacketEndToEnd},
      {"bit_writer_u64_at_offset", &TestBitWriter64BitAtOffset},
      {"file_transfer_e2e", &TestFileTransferEndToEnd},
  };

  int failures = 0;
  for (const auto& t : tests) {
    const bool ok = t.fn();
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << t.name << std::endl;
    if (!ok) {
      ++failures;
    }
  }
  if (failures > 0) {
    std::cerr << "MP integration failures: " << failures << std::endl;
    return 1;
  }
  std::cout << "All MP integration tests passed." << std::endl;
  return 0;
}
