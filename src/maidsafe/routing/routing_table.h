/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ROUTING_ROUTING_TABLE_H_
#define MAIDSAFE_ROUTING_ROUTING_TABLE_H_

#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

#include "boost/optional.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/routing/node_info.h"
#include "maidsafe/routing/types.h"

namespace maidsafe {

namespace routing {

struct NodeInfo;

class RoutingTable {
 public:
  static size_t BucketSize() { return 1; }
  static size_t Parallelism() { return 4; }
  static size_t OptimalSize() { return 64; }
  explicit RoutingTable(Address our_id);
  RoutingTable(const RoutingTable&) = delete;
  RoutingTable(RoutingTable&&) = delete;
  RoutingTable& operator=(const RoutingTable&) = delete;
  RoutingTable& operator=(RoutingTable&&) MAIDSAFE_NOEXCEPT = delete;
  ~RoutingTable() = default;
  std::pair<bool, boost::optional<NodeInfo>> AddNode(NodeInfo their_info);
  bool CheckNode(const Address& their_id) const;
  void DropNode(const Address& node_to_drop);
  // our close group or at least as much of it as we currently know
  std::vector<NodeInfo> OurCloseGroup() const;
  // If more than 1 node returned then we are in close group so send to all
  std::vector<NodeInfo> TargetNodes(const Address& their_id) const;
  Address OurId() const { return our_id_; }
  size_t Size() const;

 private:
  class Comparison {
   public:
    explicit Comparison(Address our_id) : our_id_(std::move(our_id)) {}
    bool operator()(const NodeInfo& lhs, const NodeInfo& rhs) const {
      return Address::CloserToTarget(lhs.id, rhs.id, our_id_);
    }

   private:
    const Address our_id_;
  };
  int32_t BucketIndex(const Address& node_id) const;
  bool HaveNode(const NodeInfo& their_info) const;
  bool NewNodeIsBetterThanExisting(const Address& their_id,
                                   std::vector<NodeInfo>::const_iterator removal_candidate) const;
  void PushBackThenSort(NodeInfo&& their_info);
  std::vector<NodeInfo>::const_iterator FindCandidateForRemoval() const;
  unsigned int NetworkStatus(size_t size) const;

  const Address our_id_;
  const Comparison comparison_;
  mutable std::mutex mutex_;
  std::vector<NodeInfo> nodes_;
};

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_ROUTING_TABLE_H_
