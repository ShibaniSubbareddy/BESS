#ifndef BESS_MODULES_DPI_H_
#define BESS_MODULES_DPI_H_

#include <rte_config.h>
#include <rte_hash_crc.h>

#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "../module.h"
#include "../packet.h"
#include "../pb/module_msg.pb.h"
#include "../utils/tcp_flow_reconstruct.h"
#include "../utils/trie.h"

using bess::utils::TcpFlowReconstruct;
using bess::utils::Trie;
using bess::utils::be16_t;
using bess::utils::be32_t;

// A helper class that defines a TCP flow
class alignas(16) Flow {
 public:
  be32_t src_ip;
  be32_t dst_ip;
  be16_t src_port;
  be16_t dst_port;
  uint32_t padding;

  Flow() : padding(0) {}

  bool operator==(const Flow &other) const {
    return memcmp(this, &other, sizeof(*this)) == 0;
  }
};

static_assert(sizeof(Flow) == 16, "Flow must be 16 bytes.");

// Hash function for std::unordered_map
struct FlowHash {
  std::size_t operator()(const Flow &f) const {
    uint32_t init_val = 0;

#if __x86_64
    const union {
      Flow flow;
      uint64_t u64[2];
    } &bytes = {.flow = f};

    init_val = crc32c_sse42_u64(bytes.u64[0], init_val);
    init_val = crc32c_sse42_u64(bytes.u64[1], init_val);
#else
    init_val = rte_hash_crc(&f, sizeof(Flow), init_val);
#endif

    return init_val;
  }
};
