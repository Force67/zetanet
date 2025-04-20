
#include "z_p2p_node.h"

namespace tx::network {

bool ZP2PNode::Begin(u16 port) {
  return true;
  // return transport_layer_.Begin(port);
}

bool ZP2PNode::Update() {
  return true;
  // return transport_layer_.Update();
}

void ZP2PNode::SendMessage(ZPeerId id, const std::string& data) {
  // transport_layer_.SendMessage(id, data);
}

}  // namespace tx::network