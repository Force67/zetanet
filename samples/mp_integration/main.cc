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
#else
#include <base/algorithm.h>
#include <base/atomic.h>
#include <base/containers/map.h>
#include <base/containers/unordered_set.h>
#include <base/containers/vector.h>
#include <base/filesystem/file.h>
#include <base/filesystem/file_util.h>
#include <base/filesystem/path.h>
#include <base/memory/move.h>
#include <base/strings/xstring.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#endif

#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

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
  static base::Atomic<u16> next_port{19050};
  return static_cast<u16>(next_port.fetch_add(1));
}

// xorshift32: the tests need arbitrary data, reproducible from a seed, and
// nothing about its distribution.
class TestRng {
 public:
  explicit TestRng(u32 seed) : state_(seed != 0 ? seed : 1u) {}

  u32 operator()() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 17;
    state_ ^= state_ << 5;
    return state_;
  }

 private:
  u32 state_;
};

// LZ4 only shrinks redundant input; repeat a small alphabet so compression
// triggers instead of falling into PacketBuilder's "didn't help" branch.
base::String MakeCompressiblePayload(mem_size bytes, u32 seed) {
  base::String out;
  out.reserve(bytes);
  TestRng rng(seed);
  static constexpr char kAlphabet[] = "abcdefghijklmnop";
  while (out.size() < bytes) {
    const mem_size run = 4 + (rng() % 12);
    const char ch = kAlphabet[rng() % (sizeof(kAlphabet) - 1)];
    for (mem_size i = 0; i < run && out.size() < bytes; ++i) {
      out.push_back(ch);
    }
  }
  return out;
}

template <typename Fn>
bool WaitForCondition(int timeout_ms, Fn&& fn) {
  const base::TimeTicks deadline =
      base::TimeTicks::Now() + base::Milliseconds(timeout_ms);
  while (base::TimeTicks::Now() < deadline) {
    if (fn()) {
      return true;
    }
    base::SleepForMilliseconds(1);
  }
  return fn();
}

struct CodecCase {
  bool reliable;
  bool encrypted;
  bool compressed;
};

bool CodecRoundtripOnce(const CodecCase& c,
                        const base::String& payload,
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
    fprintf(stderr,
            "  build failed (reliable=%d encrypted=%d compressed=%d "
            "size=%zu)\n",
            c.reliable, c.encrypted, c.compressed,
            static_cast<size_t>(payload.size()));
    return false;
  }

  PacketUnpacker unpacker(rx_crypto);
  IncomingPacket in;
  if (!unpacker.UnpackPacket(wire.data(), wire.size(), in)) {
    fprintf(stderr,
            "  unpack failed (reliable=%d encrypted=%d compressed=%d "
            "wire_size=%zu)\n",
            c.reliable, c.encrypted, c.compressed,
            static_cast<size_t>(wire.size()));
    return false;
  }
  if (in.data.size() != payload.size() ||
      memcmp(in.data.data(), payload.data(), payload.size()) != 0) {
    fprintf(stderr,
            "  payload mismatch (reliable=%d encrypted=%d compressed=%d "
            "expected=%zu got=%zu)\n",
            c.reliable, c.encrypted, c.compressed,
            static_cast<size_t>(payload.size()),
            static_cast<size_t>(in.data.size()));
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

  const mem_size sizes[] = {32, 256, 4096, 32 * 1024};

  bool all_ok = true;
  for (const auto& c : cases) {
    for (mem_size size : sizes) {
      const base::String payload =
          MakeCompressiblePayload(size, 0xABCDu ^ static_cast<u32>(size));
      if (!CodecRoundtripOnce(c, payload, nullptr, nullptr)) {
        all_ok = false;
      }
    }
  }

  // Incompressible payload, hitting the branch that clears the compressed
  // flag when compression does not shrink the data.
  base::String incompressible(2048, '\0');
  TestRng rng(0xDEAD);
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
    fprintf(stderr, "  server.Begin failed\n");
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port,
                       MakeClientOptions(encryption, compression))) {
    fprintf(stderr, "  client.Connect failed\n");
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
    fprintf(stderr, "  handshake did not complete\n");
    client.Disconnect();
    server.Deinit();
    return false;
  }

  base::Vector<base::String> payloads;
  payloads.push_back(MakeCompressiblePayload(64, 1));
  payloads.push_back(MakeCompressiblePayload(512, 2));
  payloads.push_back(MakeCompressiblePayload(2048, 3));
  payloads.push_back(base::String(48, 'Q'));
  payloads.push_back("hello multiplayer world");

  for (const auto& p : payloads) {
    client.SendMessage(ZPeerId(ZPeerId::to_server), p);
  }

  base::Vector<base::String> received;
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
    base::Vector<base::String> expected = payloads;
    base::Vector<base::String> got = received;
    base::Sort(expected.data(), expected.data() + expected.size());
    base::Sort(got.data(), got.data() + got.size());
    if (got.size() != expected.size() || got != expected) {
      fprintf(stderr,
              "  contents differ (sent %zu, got %zu unique payloads)\n",
              static_cast<size_t>(expected.size()),
              static_cast<size_t>(got.size()));
      ok = false;
    }
  } else {
    fprintf(stderr, "  only received %zu/%zu packets\n",
            static_cast<size_t>(received.size()),
            static_cast<size_t>(payloads.size()));
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
      fprintf(stderr, "  %s:%d: %s\n", __FILE__, __LINE__, msg);      \
      return false;                                                   \
    }                                                                 \
  } while (0)

bool TestBitPrimitives() {
  base::Vector<byte> backing(64, byte{0});
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
  BIT_CHECK(r.ReadFloat(f, 0.0f, 1.0f, 16) && fabsf(f - 0.25f) < 1e-3f,
            "float quant");
  BIT_CHECK(r.ReadUnitQuat(qx, qy, qz, qw) && fabsf(qw - 1.0f) < 1e-2f,
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
  base::Vector<byte> backing(32, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.Push(src);
  w.Finalize();
  BIT_CHECK(w.ok(), "writer ok");

  BitReader r(backing.data(), backing.size());
  PlayerSnapshot dst{};
  BIT_CHECK(r.Pop(dst), "pop");
  BIT_CHECK(dst.health == src.health, "health");
  BIT_CHECK(fabsf(dst.pos_x - src.pos_x) < 0.1f, "pos_x");
  BIT_CHECK(fabsf(dst.pos_y - src.pos_y) < 0.1f, "pos_y");
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

  base::Vector<byte> backing(32, byte{0});
  BitWriter w(base::Span<byte>(backing.data(), backing.size()));
  w.Push(src);
  w.Finalize();
  BIT_CHECK(w.ok(), "writer ok");

  BitReader r(backing.data(), backing.size());
  ZippedSnapshot dst;
  BIT_CHECK(r.Pop(dst), "pop");
  BIT_CHECK(static_cast<i32>(dst.health) == 88, "health");
  BIT_CHECK(static_cast<u32>(dst.team) == 5u, "team");
  BIT_CHECK(fabsf(static_cast<f32>(dst.px) - src.px) < 0.1f, "px");
  BIT_CHECK(fabsf(static_cast<f32>(dst.py) - src.py) < 0.1f, "py");
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
  client.Push(base::move(pkt));

  base::Vector<base::String> received;
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
           (fabsf(dst.pos_x - src.pos_x) < 0.1f) &&
           (fabsf(dst.pos_y - src.pos_y) < 0.1f) && (dst.alive == src.alive);
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
      base::Vector<byte> backing(64, byte{0});
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
        fprintf(stderr,
                "  u64 mismatch at prefix_bits=%u: wrote %016llx got "
                "%016llx\n",
                prefix_bits, static_cast<unsigned long long>(value),
                static_cast<unsigned long long>(value_back));
        return false;
      }
    }
  }

  // BitTraits<u64> after an odd-width field, the shape that triggered the bug.
  base::Vector<byte> backing(32, byte{0});
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

// In-process file transfer over a loopback ZP2PNode pair, covering chunking,
// reassembly, the memory-mapped writer, and the p2p control plane.
bool TestFileTransferEndToEnd() {
  // Relative work directory: absolute output paths are rejected by the
  // transporter, and relative paths keep the rename on one filesystem.
  char work_dir_name[32];
  snprintf(work_dir_name, sizeof(work_dir_name), "znet_ft_%u",
           static_cast<unsigned>(NextPort()));
  const base::String work_dir(work_dir_name);
  const base::String input_path = work_dir + "/source.bin";
  const base::String temp_dir = work_dir + "/tmp";
  const base::String output_path = work_dir + "/received.bin";
  base::CreateDirectory(base::Path(temp_dir));

  auto cleanup = [&]() { base::DeletePathRecursively(base::Path(work_dir)); };

  base::String content;
  {
    TestRng rng(0xF11E);
    content.reserve(15000u);
    while (content.size() < 15000u) {
      const char ch = static_cast<char>(rng() & 0xFF);
      content.push_back(ch);
    }
  }
  {
    base::File out(base::Path(input_path),
                   base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    if (!out.IsValid() ||
        out.Write(0, content.data(), content.size()) !=
            static_cast<int>(content.size())) {
      fprintf(stderr, "  writing %s failed\n", input_path.c_str());
      cleanup();
      return false;
    }
  }

  const u16 host_port = NextPort();
  const u16 sender_port = NextPort();

  tx::network::ZP2PNode receiver_node;
  if (!receiver_node.Begin(host_port)) {
    fprintf(stderr, "  receiver Begin failed\n");
    cleanup();
    return false;
  }
  tx::network::IFileWriteFactory& mmap_factory =
      tx::network::GetMemoryMappedFileWriteFactory();
  tx::network::ZFileTransporter receiver(receiver_node, &mmap_factory);

  tx::network::ZP2PNode sender_node;
  if (!sender_node.Connect(base::StringRef("127.0.0.1", 9), host_port,
                           sender_port)) {
    fprintf(stderr, "  sender Connect failed\n");
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
  const base::TimeTicks warmup_end =
      base::TimeTicks::Now() + base::Milliseconds(800);
  while (base::TimeTicks::Now() < warmup_end) {
    pump();
    tx::network::IncomingPacket ignored;
    receiver_node.Update();
    while (receiver_node.Poll(tx::network::PacketChannelType::Control,
                              ignored)) {
    }
    while (receiver_node.Poll(tx::network::PacketChannelType::Data, ignored)) {
    }
    base::SleepForMilliseconds(1);
  }

  tx::network::ZFileTransporter::TransferTuning tuning;
  tuning.chunk_size = 1024;
  if (!sender.SendFile(base::Path(input_path),
                       tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                       tuning)) {
    fprintf(stderr, "  SendFile failed\n");
    cleanup();
    return false;
  }

  // The session exists only after the file-name-bearing chunk 0 arrives, and
  // received chunks are ACKed so they are never retransmitted. Buffer early
  // chunks and stream them once the session exists.
  base::Map<u32, tx::network::ZFileTransporter::TransferChunk> pending;
  base::UnorderedSet<u32> streamed;
  bool have_transfer = false;
  u64 transfer_id = 0;
  bool completed = false;

  auto drain_pending = [&]() -> bool {
    if (!pending.contains(0)) {
      return true;  // wait for chunk 0 to bootstrap the session
    }
    for (auto& entry : pending) {
      const u32 index = entry.first;
      if (streamed.contains(index)) {
        continue;
      }
      bool chunk_completed = false;
      if (!receiver.StreamChunkToFile(entry.second, base::Path(temp_dir),
                                      &chunk_completed)) {
        fprintf(stderr, "  StreamChunkToFile failed for chunk %u\n", index);
        return false;
      }
      streamed.insert(index);
      if (chunk_completed) {
        if (!receiver.FinalizeStreamedFile(
                transfer_id, base::Path(output_path))) {
          fprintf(stderr, "  FinalizeStreamedFile failed\n");
          return false;
        }
        completed = true;
        return true;
      }
    }
    return true;
  };

  const base::TimeTicks deadline = base::TimeTicks::Now() + base::Seconds(20);
  while (!completed && base::TimeTicks::Now() < deadline) {
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
      pending.emplace(index, base::move(chunk));
    }
    while (receiver_node.Poll(tx::network::PacketChannelType::Data, packet)) {
    }

    if (!drain_pending()) {
      cleanup();
      return false;
    }
    base::SleepForMilliseconds(1);
  }

  if (!completed) {
    fprintf(stderr, "  transfer did not complete (%zu/%zu chunks buffered)\n",
            static_cast<size_t>(streamed.size()),
            static_cast<size_t>(pending.size()));
    cleanup();
    return false;
  }

  // A missing or short output file leaves |received| short of |content|.
  base::String received;
  {
    base::File in(base::Path(output_path),
                  base::File::FLAG_OPEN | base::File::FLAG_READ);
    const i64 length = in.IsValid() ? in.GetLength() : 0;
    if (length > 0) {
      received.resize(static_cast<mem_size>(length));
      const int read = in.Read(0, received.data(), static_cast<int>(length));
      received.resize(read > 0 ? static_cast<mem_size>(read) : 0u);
    }
  }

  const bool ok = received.size() == content.size() && received == content;
  if (!ok) {
    fprintf(stderr, "  content mismatch (sent %zu, got %zu bytes)\n",
            static_cast<size_t>(content.size()),
            static_cast<size_t>(received.size()));
  }
  cleanup();
  return ok;
}

}  // namespace

int main(int /*argc*/, char** /*argv*/) {
  // Results interleave with the library's stderr logs; line buffering keeps
  // them in order when stdout is a pipe.
  setvbuf(stdout, nullptr, _IOLBF, 0);

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
    printf("%s%s\n", ok ? "[PASS] " : "[FAIL] ", t.name);
    if (!ok) {
      ++failures;
    }
  }
  if (failures > 0) {
    fprintf(stderr, "MP integration failures: %d\n", failures);
    return 1;
  }
  printf("All MP integration tests passed.\n");
  return 0;
}
