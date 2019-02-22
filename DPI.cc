#include "DPI.h"

#include <algorithm>
#include <tuple>

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/http_parser.h"
#include "../utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;

const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000;  // 10 seconds

const Commands DPI::cmds = {
    {"get_initial_arg", "EmptyArg", MODULE_CMD_FUNC(&DPI::GetInitialArg),
     Command::THREAD_SAFE},
    {"get_runtime_config", "EmptyArg",
     MODULE_CMD_FUNC(&DPI::GetRuntimeConfig), Command::THREAD_SAFE},
    {"set_runtime_config", "DPIConfig",
     MODULE_CMD_FUNC(&DPI::SetRuntimeConfig), Command::THREAD_UNSAFE},
    {"add", "DPIArg", MODULE_CMD_FUNC(&DPI::CommandAdd),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&DPI::CommandClear),
     Command::THREAD_UNSAFE}};

// Template for generating TCP packets without data
struct[[gnu::packed]] PacketTemplate {
  Ethernet eth;
  Ipv4 ip;
  Tcp tcp;

  PacketTemplate() {
    eth.dst_addr = Ethernet::Address();  // To fill in
    eth.src_addr = Ethernet::Address();  // To fill in
    eth.ether_type = be16_t(Ethernet::Type::kIpv4);
    ip.version = 4;
    ip.header_length = 5;
    ip.type_of_service = 0;
    ip.length = be16_t(40);
    ip.id = be16_t(0);  // To fill in
    ip.fragment_offset = be16_t(0);
    ip.ttl = 0x40;
    ip.protocol = Ipv4::Proto::kTcp;
    ip.checksum = 0;           // To fill in
    ip.src = be32_t(0);        // To fill in
    ip.dst = be32_t(0);        // To fill in
    tcp.src_port = be16_t(0);  // To fill in
    tcp.dst_port = be16_t(0);  // To fill in
    tcp.seq_num = be32_t(0);   // To fill in
    tcp.ack_num = be32_t(0);   // To fill in
    tcp.reserved = 0;
    tcp.offset = 5;
    tcp.flags = Tcp::Flag::kAck | Tcp::Flag::kRst;
    tcp.window = be16_t(0);
    tcp.checksum = 0;  // To fill in
    tcp.urgent_ptr = be16_t(0);
  }
};

static const char HTTP_HEADER_HOST[] = "Host";
static const char HTTP_403_BODY[] =
    "HTTP/1.1 403 Bad Forbidden\r\nConnection: Closed\r\n\r\n";

static PacketTemplate rst_template;

// Generate an HTTP 403 packet
inline static bess::Packet *Generate403Packet(const Ethernet::Address &src_eth,
                                              const Ethernet::Address &dst_eth,
                                              be32_t src_ip, be32_t dst_ip,
                                              be16_t src_port, be16_t dst_port,
                                              be32_t seq, be32_t ack) {
  bess::Packet *pkt = current_worker.packet_pool()->Alloc();
  char *ptr = static_cast<char *>(pkt->buffer()) + SNBUF_HEADROOM;
  pkt->set_data_off(SNBUF_HEADROOM);

  constexpr size_t len = sizeof(HTTP_403_BODY) - 1;
  pkt->set_total_len(sizeof(rst_template) + len);
  pkt->set_data_len(sizeof(rst_template) + len);

  bess::utils::Copy(ptr, &rst_template, sizeof(rst_template));
  bess::utils::Copy(ptr + sizeof(rst_template), HTTP_403_BODY, len);

  Ethernet *eth = reinterpret_cast<Ethernet *>(ptr);
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  // We know there is no IP option
  Tcp *tcp = reinterpret_cast<Tcp *>(ip + 1);

  eth->dst_addr = dst_eth;
  eth->src_addr = src_eth;
  ip->id = be16_t(1);  // assumes the SYN packet used ID 0
  ip->src = src_ip;
  ip->dst = dst_ip;
  ip->length = be16_t(40 + len);
  tcp->src_port = src_port;
  tcp->dst_port = dst_port;
  tcp->seq_num = seq;
  tcp->ack_num = ack;
  tcp->flags = Tcp::Flag::kAck;

  tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*tcp, src_ip, dst_ip,
                                                        sizeof(*tcp) + len);
  ip->checksum = bess::utils::CalculateIpv4NoOptChecksum(*ip);

  return pkt;
}

// Generate a TCP RST packet
inline static bess::Packet *GenerateResetPacket(
    const Ethernet::Address &src_eth, const Ethernet::Address &dst_eth,
    be32_t src_ip, be32_t dst_ip, be16_t src_port, be16_t dst_port, be32_t seq,
    be32_t ack) {
  bess::Packet *pkt = current_worker.packet_pool()->Alloc();
  char *ptr = static_cast<char *>(pkt->buffer()) + SNBUF_HEADROOM;
  pkt->set_data_off(SNBUF_HEADROOM);
  pkt->set_total_len(sizeof(rst_template));
  pkt->set_data_len(sizeof(rst_template));

  bess::utils::Copy(ptr, &rst_template, sizeof(rst_template));

  Ethernet *eth = reinterpret_cast<Ethernet *>(ptr);
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  // We know there is no IP option
  Tcp *tcp = reinterpret_cast<Tcp *>(ip + 1);

  eth->dst_addr = dst_eth;
  eth->src_addr = src_eth;
  ip->id = be16_t(2);  // assumes the 403 used ID 1
  ip->src = src_ip;
  ip->dst = dst_ip;
  tcp->src_port = src_port;
  tcp->dst_port = dst_port;
  tcp->seq_num = seq;
  tcp->ack_num = ack;

  tcp->checksum =
      bess::utils::CalculateIpv4TcpChecksum(*tcp, src_ip, dst_ip, sizeof(*tcp));
  ip->checksum = bess::utils::CalculateIpv4NoOptChecksum(*ip);

  return pkt;
}

CommandResponse DPI::Init(const bess::pb::DPIArg &arg) {
  for (const auto &url : arg.blacklist()) {
    blacklist_[url.host()].Insert(url.path(), {});
  }
  return CommandSuccess();
}

CommandResponse DPI::CommandAdd(const bess::pb::DPIArg &arg) {
  Init(arg);
  return CommandSuccess();
}

CommandResponse DPI::CommandClear(const bess::pb::EmptyArg &) {
  blacklist_.clear();
  return CommandSuccess();
}

// Retrieves an argument that would re-create this module in
// such a way that SetRuntimeConfig would build the same one.
CommandResponse DPI::GetInitialArg(const bess::pb::EmptyArg &) {
  bess::pb::DPIArg resp;
  // Our return value is empty since we return
  // the current blacklist as the runtime config.
  return CommandSuccess(resp);
}

// Retrieves a configuration that will restore this module.
CommandResponse DPI::GetRuntimeConfig(const bess::pb::EmptyArg &) {
  bess::pb::DPIConfig resp;
  using rule_t = bess::pb::DPIArg_Url;
  for (const auto &it : blacklist_) {
    auto entries = it.second.Dump();
    for (auto entry : entries) {
      rule_t *hp = resp.add_blacklist();
      hp->set_host(it.first);
      hp->set_path(std::get<0>(entry));
      // For now, ignore get<1> and get<2>, which are
      // the tuple and the prefix boolean, respectively.
      // The tuple is (currently) always empty and the boolean
      // is (currently) always false -- see the .Insert() above.
    }
  }
  // Dump() is sorted, but blacklist_ is not: we use a
  // stable sort to just sort by the host as the outer key.
  std::stable_sort(
      resp.mutable_blacklist()->begin(), resp.mutable_blacklist()->end(),
      [](const rule_t &a, const rule_t &b) { return a.host() < b.host(); });
  return CommandSuccess(resp);
}

// Restores the module's configuration.
CommandResponse DPI::SetRuntimeConfig(
    const bess::pb::DPIConfig &arg) {
  blacklist_.clear();
  for (const auto &url : arg.blacklist()) {
    blacklist_[url.host()].Insert(url.path(), {});
  }
  return CommandSuccess();
}

void DPI::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t igate = ctx->current_igate;

  // Pass reverse traffic
  if (igate == 1) {
    RunChooseModule(ctx, 1, batch);
    return;
  }

  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    std::cout << "This is my dpi module";
    std::ostringstream dump;
    printf("----------------------------------------\n");
    size_t j, ofs;
    ofs = 0;
    size_t len = pkt->total_len();
    const char *data = reinterpret_cast<const char *>(pkt->head_data());
    for (j = 0; (ofs < len) && (j < 100); j++, ofs++) {
      char c = data[ofs];
      if ((c < ' ') || (c > '~')) {
        c = '.';
      }
      dump << c;
    }
    dump << std::endl;

    //Print the packet payload
    std::cout << dump.str();

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    int ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    uint64_t now = ctx->current_ns;

    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRecord, FlowHash>::iterator it =
        flow_cache_.find(flow);

    if (it != flow_cache_.end()) {
      if (now >= it->second.ExpiryTime()) {
        // Discard old flow and start over.
        flow_cache_.erase(it);
        it = flow_cache_.end();
      } else if (it->second.IsAnalyzed()) {
        // Once we're finished analyzing, we only record *blocked* flows.
        // Continue blocking this flow for TIME_OUT_NS more ns.
        it->second.SetExpiryTime(now + TIME_OUT_NS);
        DropPacket(ctx, pkt);
        continue;
      }
    }

    if (it == flow_cache_.end()) {
      // Don't have a flow, or threw an aged one out.  If there's no
      // SYN in this packet the reconstruct code will fail.  This is
      // a common case (for any flow that got analyzed and allowed);
      // skip a pointless emplace/erase pair for such packets.
      if (tcp->flags & Tcp::Flag::kSyn) {
        std::tie(it, std::ignore) = flow_cache_.emplace(
            std::piecewise_construct, std::make_tuple(flow), std::make_tuple());
      } else {
        EmitPacket(ctx, pkt, 0);
        continue;
      }
    }

    FlowRecord &record = it->second;
    TcpFlowReconstruct &buffer = record.GetBuffer();

    // If the reconstruct code indicates failure, treat this
    // as a flow to pass.  Note: we only get failure if there is
    // something seriously wrong; we get success if there are holes
    // in the data (in which case the contiguous_len() below is short).
    bool success = buffer.InsertPacket(pkt);
    if (!success) {
      VLOG(1) << "Reconstruction failure";
      flow_cache_.erase(it);
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    // Have something on this flow; keep it alive for a while longer.
    record.SetExpiryTime(now + TIME_OUT_NS);

    // We are by definition still analyzing.  See if we can determine
    // the final disposition of this flow.
    bool matched = false;
    struct phr_header headers[16];
    size_t num_headers = 16, method_len, path_len;
    int minor_version;
    const char *method, *path;
    int parse_result = phr_parse_request(
        buffer.buf(), buffer.contiguous_len(), &method, &method_len, &path,
        &path_len, &minor_version, headers, &num_headers, 0);

    // -2 means incomplete
    if (parse_result > 0 || parse_result == -2) {
      const std::string path_str(path, path_len);

      // Look for the Host header
      for (size_t j = 0; j < num_headers && !matched; ++j) {
        if (strncmp(headers[j].name, HTTP_HEADER_HOST, headers[j].name_len) ==
            0) {
          const std::string host(headers[j].value, headers[j].value_len);
          const auto rule_iterator = blacklist_.find(host);
          matched = rule_iterator != blacklist_.end() &&
                    rule_iterator->second.Match(path_str);
        }
      }
    }

    if (!matched) {
      EmitPacket(ctx, pkt, 0);

      // Once FIN is observed, or we've seen all the headers and decided
      // to pass the flow, there is no more need to reconstruct the flow.
      // NOTE: if FIN is lost on its way to destination, this will simply pass
      // the retransmitted packet.
      if (parse_result != -2 || (tcp->flags & Tcp::Flag::kFin)) {
        flow_cache_.erase(it);
      }
    } else {
      // No need to keep reconstructing, just mark it as analyzed
      // (and hence blocked).
      it->second.SetAnalyzed();

      // Inject RST to destination
      EmitPacket(ctx, GenerateResetPacket(eth->src_addr, eth->dst_addr, ip->src,
                                          ip->dst, tcp->src_port, tcp->dst_port,
                                          tcp->seq_num, tcp->ack_num),
                 0);

      // Inject 403 to source. 403 should arrive earlier than RST.
      EmitPacket(ctx, Generate403Packet(eth->dst_addr, eth->src_addr, ip->dst,
                                        ip->src, tcp->dst_port, tcp->src_port,
                                        tcp->ack_num, tcp->seq_num),
                 1);

      // Inject RST to source
      EmitPacket(ctx, GenerateResetPacket(
                          eth->dst_addr, eth->src_addr, ip->dst, ip->src,
                          tcp->dst_port, tcp->src_port,
                          be32_t(tcp->ack_num.value() + strlen(HTTP_403_BODY)),
                          tcp->seq_num),
                 1);

      // Drop the data packet
      DropPacket(ctx, pkt);
    }
  }
}

std::string DPI::GetDesc() const {
  return bess::utils::Format("%zu hosts", blacklist_.size());
}

ADD_MODULE(DPI, "dpi", "Filter HTTP connection")
