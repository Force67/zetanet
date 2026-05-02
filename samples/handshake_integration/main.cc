#include <znet/z_client.h>
#include <znet/z_packet_serdes.h>
#include <znet/z_server.h>
#include <znet/z_socket.h>
#include <znet/z_system_command.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {

using tx::network::IncomingPacket;
using tx::network::OutgoingPacket;
using tx::network::PacketBuilder;
using tx::network::PacketChannelType;
using tx::network::PacketPriority;
using tx::network::PacketReader;
using tx::network::PacketType;
using tx::network::PacketUnpacker;
using tx::network::PackageFlags;
using tx::network::ZClient;
using tx::network::ZServer;
using tx::network::ZSocket;
namespace sys = tx::network::system_commands;

constexpr char kTestPsk[] = "0123456789abcdef0123456789abcdef";
const base::StringRef kTestPskRef{kTestPsk, sizeof(kTestPsk) - 1};

u16 NextPort() {
  static std::atomic<u16> next_port{18050};
  return static_cast<u16>(next_port.fetch_add(1));
}

struct ChaosSettings {
  u32 drop_percent{0};
  u32 reorder_percent{0};
  u32 jitter_ms{0};
  u32 seed{1};

  bool enabled() const {
    return drop_percent > 0 || reorder_percent > 0 || jitter_ms > 0;
  }
};

ChaosSettings g_chaos{};

ZSocket::ChaosOptions ToSocketChaosOptions() {
  return ZSocket::ChaosOptions{
      .drop_percent = g_chaos.drop_percent,
      .reorder_percent = g_chaos.reorder_percent,
      .jitter_ms = g_chaos.jitter_ms,
      .seed = g_chaos.seed == 0 ? 1 : g_chaos.seed,
  };
}

ZServer::StartOptions MakeServerOptions(
    bool encryption,
    bool compression,
    const base::StringRef pre_shared_key = base::StringRef()) {
  return ZServer::StartOptions{
      .use_encryption = encryption,
      .pre_shared_key = pre_shared_key,
      .use_compression = compression,
      .allow_ipv6 = false,
      .start_threads = false,
      .chaos = ToSocketChaosOptions()};
}

ZClient::ConnectionOptions MakeClientOptions(
    bool encryption,
    bool compression,
    const base::StringRef pre_shared_key = base::StringRef()) {
  return ZClient::ConnectionOptions{
      .use_encryption = encryption,
      .pre_shared_key = pre_shared_key,
      .use_compression = compression,
      .allow_ipv6 = false,
      .start_threads = false,
      .chaos = ToSocketChaosOptions()};
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

bool BuildAndSend(ZSocket& socket, OutgoingPacket& packet, u32 sequence_number) {
  PacketBuilder builder(nullptr);
  base::Vector<byte> bytes = builder.BuildPacket(packet, sequence_number);
  if (bytes.empty()) {
    return false;
  }
  return socket.SendtoServer(base::Span<byte>(bytes.data(), bytes.size())) > 0;
}

bool ParseGoodbyeReason(const IncomingPacket& packet,
                        sys::HandshakeRejectReason& reason_out) {
  if (packet.type != PacketType::ServerGoodbye) {
    return false;
  }
  PacketReader reader(reinterpret_cast<const byte*>(packet.data.data()),
                      packet.data.size());
  return reader.Read(reason_out);
}

template <typename PumpFn>
bool WaitForGoodbyeReason(ZSocket& socket,
                          PumpFn&& pump_fn,
                          sys::HandshakeRejectReason expected_reason,
                          int timeout_ms) {
  PacketUnpacker unpacker(nullptr);
  base::Vector<byte> recv_buffer(65507);
  ZSocket::Address sender{};

  return WaitForCondition(timeout_ms, [&]() {
    pump_fn();
    const i32 received = socket.Receive(
        sender, reinterpret_cast<char*>(recv_buffer.data()), recv_buffer.size());
    if (received <= 0) {
      return false;
    }
    IncomingPacket incoming;
    if (!unpacker.UnpackPacket(recv_buffer.data(), static_cast<mem_size>(received),
                               incoming)) {
      return false;
    }
    sys::HandshakeRejectReason actual_reason = sys::HandshakeRejectReason::None;
    if (!ParseGoodbyeReason(incoming, actual_reason)) {
      return false;
    }
    return actual_reason == expected_reason;
  });
}

template <typename PumpFn>
bool WaitForPacketType(ZSocket& socket,
                       PumpFn&& pump_fn,
                       PacketType expected_type,
                       int timeout_ms) {
  PacketUnpacker unpacker(nullptr);
  base::Vector<byte> recv_buffer(65507);
  ZSocket::Address sender{};

  return WaitForCondition(timeout_ms, [&]() {
    pump_fn();
    const i32 received = socket.Receive(
        sender, reinterpret_cast<char*>(recv_buffer.data()), recv_buffer.size());
    if (received <= 0) {
      return false;
    }
    IncomingPacket incoming;
    if (!unpacker.UnpackPacket(recv_buffer.data(), static_cast<mem_size>(received),
                               incoming)) {
      return false;
    }
    return incoming.type == expected_type;
  });
}

class RejectingServer {
 public:
  RejectingServer() : recv_buffer_(65507) {}

  bool Start(u16 port) { return socket_.CreateServer(port, false); }

  void Stop() { socket_.DestroySocket(); }

  void Pump(sys::HandshakeRejectReason reason) {
    ZSocket::Address sender{};
    const i32 received = socket_.Receive(
        sender, reinterpret_cast<char*>(recv_buffer_.data()), recv_buffer_.size());
    if (received <= 0) {
      return;
    }
    IncomingPacket incoming;
    if (!unpacker_.UnpackPacket(recv_buffer_.data(),
                                static_cast<mem_size>(received), incoming)) {
      return;
    }
    if (incoming.type != PacketType::ClientHello) {
      return;
    }

    tx::network::PacketWriter writer;
    sys::ServerGoodbye goodbye{.reason = reason};
    sys::ServerGoodbye::Build(writer, goodbye);

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(0, PacketType::ServerGoodbye, PacketChannelType::Control,
                       flags, writer.data());

    PacketBuilder builder(nullptr);
    base::Vector<byte> bytes = builder.BuildPacket(out, next_sequence_++);
    if (!bytes.empty()) {
      socket_.Send(sender, base::Span<byte>(bytes.data(), bytes.size()));
    }
  }

 private:
  ZSocket socket_{};
  PacketUnpacker unpacker_{nullptr};
  base::Vector<byte> recv_buffer_{};
  u32 next_sequence_{1};
};

class SilentServer {
 public:
  SilentServer() : recv_buffer_(65507) {}

  bool Start(u16 port) { return socket_.CreateServer(port, false); }

  void Stop() { socket_.DestroySocket(); }

  void Pump() {
    ZSocket::Address sender{};
    (void)socket_.Receive(sender, reinterpret_cast<char*>(recv_buffer_.data()),
                          recv_buffer_.size());
  }

 private:
  ZSocket socket_{};
  base::Vector<byte> recv_buffer_{};
};

bool TestHandshakeSuccess() {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(false, false))) {
    std::cerr << "TestHandshakeSuccess: failed to start server\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port, MakeClientOptions(false, false))) {
    std::cerr << "TestHandshakeSuccess: failed to connect client\n";
    server.Deinit();
    return false;
  }

  const bool connected = WaitForCondition(3000, [&]() {
    server.Update();
    client.Update();
    return client.state() == tx::network::ZAsyncTransportLayer::State::kConnected &&
           client.handshake_phase() == ZClient::HandshakePhase::kConnected &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kNone &&
           client.negotiated_protocol_version() == sys::kProtocolVersionCurrent;
  });

  client.Disconnect();
  server.Deinit();
  return connected;
}

bool TestProtocolVersionMismatchReject() {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(false, false))) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  tx::network::PacketWriter writer;
  sys::ClientHello hello{
      .protocol_version = static_cast<u16>(sys::kProtocolVersionCurrent + 1),
      .feature_flags = sys::kFeatureClockSync,
      .encryption_algo_list_len = 0,
      .compression_algo_list_len = 0,
      .pub_key_list_len = 0,
      .challenge_len = 0};
  sys::ClientHello::Build(writer, hello);

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::Critical),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                     PacketChannelType::Control, flags, writer.data());
  if (!BuildAndSend(raw_client, out, 1)) {
    std::cerr << "TestProtocolVersionMismatchReject: failed to send ClientHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::ProtocolVersionMismatch, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestFeatureMismatchReject() {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(true, false, kTestPskRef))) {
    std::cerr << "TestFeatureMismatchReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestFeatureMismatchReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  tx::network::PacketWriter writer;
  sys::ClientHello hello{
      .protocol_version = sys::kProtocolVersionCurrent,
      .feature_flags = sys::kFeatureClockSync,  // encryption intentionally omitted
      .encryption_algo_list_len = 0,
      .compression_algo_list_len = 0,
      .pub_key_list_len = 0,
      .challenge_len = 0};
  sys::ClientHello::Build(writer, hello);

  const PackageFlags flags{.reliable = 1,
                           .encrypted = 0,
                           .compressed = 0,
                           .priority = static_cast<u8>(PacketPriority::Critical),
                           .acknowledged = 0,
                           .awaiting_ack = 1,
                           .reserved = 0};
  OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                     PacketChannelType::Control, flags, writer.data());
  if (!BuildAndSend(raw_client, out, 1)) {
    std::cerr << "TestFeatureMismatchReject: failed to send ClientHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::FeatureMismatch, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestClientHandshakeTimeout() {
  const u16 port = NextPort();
  SilentServer silent_server;
  if (!silent_server.Start(port)) {
    std::cerr << "TestClientHandshakeTimeout: failed to start silent server\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port, MakeClientOptions(false, false))) {
    std::cerr << "TestClientHandshakeTimeout: failed to connect client\n";
    silent_server.Stop();
    return false;
  }

  const bool timed_out = WaitForCondition(9500, [&]() {
    silent_server.Pump();
    client.Update();
    return client.handshake_phase() == ZClient::HandshakePhase::kFailed &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kTimeout &&
           client.state() == tx::network::ZAsyncTransportLayer::State::kDisconnected;
  });

  client.Disconnect();
  silent_server.Stop();
  return timed_out;
}

bool TestAuthenticationFailureReject() {
  const u16 port = NextPort();
  ZServer server;
  server.DisableAdaptiveThreading();
  if (!server.Begin(port, MakeServerOptions(true, false, kTestPskRef))) {
    std::cerr << "TestAuthenticationFailureReject: failed to start server\n";
    return false;
  }

  ZSocket raw_client;
  if (!raw_client.CreateClient("127.0.0.1", port, false, 0)) {
    std::cerr << "TestAuthenticationFailureReject: failed to create raw client\n";
    server.Deinit();
    return false;
  }

  {
    tx::network::PacketWriter writer;
    const std::string client_key = "dummy-client-nonce";
    const std::string client_challenge = "dummy-client-challenge";
    sys::ClientHello hello{
        .protocol_version = sys::kProtocolVersionCurrent,
        .feature_flags = static_cast<u32>(sys::kFeatureClockSync |
                                          sys::kFeatureEncryption),
        .encryption_algo_list_len = 0,
        .compression_algo_list_len = 0,
        .pub_key_list_len = 1,
        .challenge_len = static_cast<u8>(client_challenge.size())};
    sys::ClientHello::Build(writer, hello);
    writer.PutList(base::Span<byte>(
        reinterpret_cast<const byte*>(client_key.data()), client_key.size()));
    writer.PutList(base::Span<byte>(
        reinterpret_cast<const byte*>(client_challenge.data()),
        client_challenge.size()));

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(tx::network::ZPeerId::to_server, PacketType::ClientHello,
                       PacketChannelType::Control, flags, writer.data());
    if (!BuildAndSend(raw_client, out, 1)) {
      std::cerr << "TestAuthenticationFailureReject: failed to send ClientHello\n";
      raw_client.DestroySocket();
      server.Deinit();
      return false;
    }
  }

  const bool saw_server_hello =
      WaitForPacketType(raw_client, [&]() { server.Update(); },
                        PacketType::ServerHello, 3000);
  if (!saw_server_hello) {
    std::cerr << "TestAuthenticationFailureReject: did not receive ServerHello\n";
    raw_client.DestroySocket();
    server.Deinit();
    return false;
  }

  {
    tx::network::PacketWriter writer;
    const std::string bogus_proof = "invalid-proof";
    sys::ClientAuthProof proof_hdr{.proof_len = static_cast<u8>(bogus_proof.size())};
    writer.Put(proof_hdr);
    writer.PutList(base::Span<byte>(
        reinterpret_cast<const byte*>(bogus_proof.data()), bogus_proof.size()));

    const PackageFlags flags{.reliable = 1,
                             .encrypted = 0,
                             .compressed = 0,
                             .priority = static_cast<u8>(PacketPriority::Critical),
                             .acknowledged = 0,
                             .awaiting_ack = 1,
                             .reserved = 0};
    OutgoingPacket out(tx::network::ZPeerId::to_server,
                       PacketType::ClientAuthProof, PacketChannelType::Control,
                       flags, writer.data());
    if (!BuildAndSend(raw_client, out, 2)) {
      std::cerr << "TestAuthenticationFailureReject: failed to send ClientAuthProof\n";
      raw_client.DestroySocket();
      server.Deinit();
      return false;
    }
  }

  const bool got_expected = WaitForGoodbyeReason(
      raw_client, [&]() { server.Update(); },
      sys::HandshakeRejectReason::AuthenticationFailed, 3000);

  raw_client.DestroySocket();
  server.Deinit();
  return got_expected;
}

bool TestClientMapsServerGoodbyeReason() {
  const u16 port = NextPort();
  RejectingServer rejector;
  if (!rejector.Start(port)) {
    std::cerr << "TestClientMapsServerGoodbyeReason: failed to start rejector\n";
    return false;
  }

  ZClient client;
  client.DisableAdaptiveThreading();
  if (!client.Connect("127.0.0.1", port, MakeClientOptions(false, false))) {
    std::cerr << "TestClientMapsServerGoodbyeReason: failed to connect client\n";
    rejector.Stop();
    return false;
  }

  const bool failed_with_expected_reason = WaitForCondition(3000, [&]() {
    rejector.Pump(sys::HandshakeRejectReason::ProtocolVersionMismatch);
    client.Update();
    return client.handshake_phase() == ZClient::HandshakePhase::kFailed &&
           client.handshake_failure_reason() ==
               ZClient::HandshakeFailureReason::kProtocolVersionMismatch;
  });

  client.Disconnect();
  rejector.Stop();
  return failed_with_expected_reason;
}

}  // namespace

int main(int argc, char** argv) {
  struct TestCase {
    const char* name;
    bool (*fn)();
  };

  const TestCase full_tests[] = {
      {"handshake_success", &TestHandshakeSuccess},
      {"protocol_version_mismatch_reject", &TestProtocolVersionMismatchReject},
      {"feature_mismatch_reject", &TestFeatureMismatchReject},
      {"client_handshake_timeout", &TestClientHandshakeTimeout},
      {"authentication_failure_reject", &TestAuthenticationFailureReject},
      {"client_maps_server_goodbye_reason", &TestClientMapsServerGoodbyeReason},
  };
  const TestCase chaos_tests[] = {
      {"handshake_success", &TestHandshakeSuccess},
  };

  for (int i = 1; i < argc; ++i) {
    const char* arg = argv[i];
    if (std::strcmp(arg, "--chaos-drop") == 0 && i + 1 < argc) {
      g_chaos.drop_percent = static_cast<u32>(std::strtoul(argv[++i], nullptr, 10));
      continue;
    }
    if (std::strcmp(arg, "--chaos-reorder") == 0 && i + 1 < argc) {
      g_chaos.reorder_percent =
          static_cast<u32>(std::strtoul(argv[++i], nullptr, 10));
      continue;
    }
    if (std::strcmp(arg, "--chaos-jitter") == 0 && i + 1 < argc) {
      g_chaos.jitter_ms = static_cast<u32>(std::strtoul(argv[++i], nullptr, 10));
      continue;
    }
    if (std::strcmp(arg, "--chaos-seed") == 0 && i + 1 < argc) {
      g_chaos.seed = static_cast<u32>(std::strtoul(argv[++i], nullptr, 10));
      continue;
    }
    if (std::strcmp(arg, "--help") == 0) {
      std::cout << "HandshakeIntegration options:\n"
                << "  --chaos-drop <0..100>\n"
                << "  --chaos-reorder <0..100>\n"
                << "  --chaos-jitter <ms>\n"
                << "  --chaos-seed <value>\n";
      return 0;
    }
    std::cerr << "Unknown argument: " << arg << std::endl;
    return 2;
  }
  if (g_chaos.seed == 0) {
    g_chaos.seed = 1;
  }
  if (g_chaos.drop_percent > 100) {
    g_chaos.drop_percent = 100;
  }
  if (g_chaos.reorder_percent > 100) {
    g_chaos.reorder_percent = 100;
  }

  const bool chaos_enabled = g_chaos.enabled();

  const TestCase* tests = chaos_enabled ? chaos_tests : full_tests;
  const size_t test_count = chaos_enabled ? _countof(chaos_tests) : _countof(full_tests);

  int failures = 0;
  for (size_t i = 0; i < test_count; ++i) {
    const TestCase& test = tests[i];
    const bool ok = test.fn();
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << test.name << std::endl;
    if (!ok) {
      ++failures;
    }
  }

  if (failures > 0) {
    std::cerr << "Handshake integration failures: " << failures << std::endl;
    return 1;
  }
  std::cout << "All handshake integration tests passed." << std::endl;
  return 0;
}
