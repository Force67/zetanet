#include <znet/z_p2p_node.h>
#include <znet/z_public_api.h>

#ifdef ZNET_USE_STL
#include <znet/z_stl_compat.h>
#endif

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

namespace {
constexpr u16 kHostPort = 14600;
constexpr u16 kNode1Port = 14601;
constexpr u16 kNode2Port = 14602;

void LogHandler(void* user_pointer,
                const char* channel_name,
                int level,
                const char* msg) {
  std::fprintf(stderr, "[%s] %s: %s\n", channel_name,
               base::LogLevelToName(static_cast<base::LogLevel>(level)), msg);
}

void TickAll(tx::network::ZP2PNode& a,
             tx::network::ZP2PNode& b,
             tx::network::ZP2PNode& c,
             int ticks,
             int sleep_ms) {
  for (int i = 0; i < ticks; ++i) {
    a.Update();
    b.Update();
    c.Update();
    if (sleep_ms > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
  }
}

bool DrainContains(tx::network::ZP2PNode& node,
                   tx::network::PacketChannelType channel,
                   const char* needle) {
  tx::network::IncomingPacket packet;
  bool found = false;
  while (node.Poll(channel, packet)) {
    if (packet.data.find(needle) != std::string::npos) {
      found = true;
    }
  }
  return found;
}
}  // namespace

int main() {
  tx::network::SetBaseLogHandlerFwd(nullptr, LogHandler);

  tx::network::ZP2PNode host;
  tx::network::ZP2PNode node1;
  tx::network::ZP2PNode node2;

  if (!host.Begin(kHostPort)) {
    std::fprintf(stderr, "smoke: host begin failed\n");
    return 1;
  }
  if (!node1.Connect("127.0.0.1", kHostPort, kNode1Port)) {
    std::fprintf(stderr, "smoke: node1 connect failed\n");
    return 1;
  }
  if (!node2.Connect("127.0.0.1", kHostPort, kNode2Port)) {
    std::fprintf(stderr, "smoke: node2 connect failed\n");
    return 1;
  }

  TickAll(host, node1, node2, 500, 2);

  node1.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_all),
                    "mesh-pre-transition");
  TickAll(host, node1, node2, 300, 2);

  const bool node2_got_pre =
      DrainContains(node2, tx::network::PacketChannelType::Data,
                    "mesh-pre-transition");
  if (!node2_got_pre) {
    std::fprintf(stderr, "smoke: node2 did not receive pre-transition mesh data\n");
    return 2;
  }

  node1.BecomeHost();
  TickAll(host, node1, node2, 700, 2);

  if (!node1.is_host()) {
    std::fprintf(stderr, "smoke: node1 did not become host\n");
    return 3;
  }
  if (host.is_host()) {
    std::fprintf(stderr, "smoke: original host did not step down\n");
    return 4;
  }

  host.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_server),
                   "after-transition-to-new-host");
  TickAll(host, node1, node2, 300, 2);

  const bool node1_got_server_msg =
      DrainContains(node1, tx::network::PacketChannelType::Data,
                    "after-transition-to-new-host");
  if (!node1_got_server_msg) {
    std::fprintf(stderr,
                 "smoke: new host did not receive data from old host client mode\n");
    return 5;
  }

  node2.SendMessage(tx::network::ZPeerId(tx::network::ZPeerId::to_all),
                    "mesh-post-transition");
  TickAll(host, node1, node2, 300, 2);

  const bool old_host_got_post =
      DrainContains(host, tx::network::PacketChannelType::Data,
                    "mesh-post-transition");
  if (!old_host_got_post) {
    std::fprintf(stderr,
                 "smoke: old host did not receive post-transition mesh data\n");
    return 6;
  }

  std::fprintf(stdout, "P2P smoke test passed (mesh + host transition).\n");
  return 0;
}
