/*  Copyright 2012 MaidSafe.net limited

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

#ifndef MAIDSAFE_ROUTING_NODE_INFO_H_
#define MAIDSAFE_ROUTING_NODE_INFO_H_

#include <cstdint>
#include "maidsafe/routing/types.h"
#include "maidsafe/common/config.h"
#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace routing {

struct NodeInfo {
  NodeInfo() = default;
  NodeInfo(const NodeInfo&) = default;
  NodeInfo(NodeInfo&& other) MAIDSAFE_NOEXCEPT : id(std::move(other.id)),
                                                 public_key(std::move(other.public_key)),
                                                 rank(std::move(other.rank)),
                                                 connected(std::move(other.connected)) {}
  NodeInfo& operator=(NodeInfo const&) = default;
  NodeInfo& operator=(NodeInfo&& other) MAIDSAFE_NOEXCEPT {
    id = std::move(other.id);
    public_key = std::move(other.public_key);
    rank = std::move(other.rank);
    connected = std::move(other.connected);
    return *this;
  }

  bool operator==(const NodeInfo& other) const { return id == other.id; }
  bool operator!=(const NodeInfo& other) const { return !operator==(other); }
  bool operator<(const NodeInfo& other) const { return id < other.id; }
  bool operator>(const NodeInfo& other) const { return id > other.id; }
  bool operator<=(const NodeInfo& other) const { return !operator>(other); }
  bool operator>=(const NodeInfo& other) const { return !operator<(other); }

  NonEmptyString serialise() const;

  Address id{};
  asymm::PublicKey public_key{};
  int32_t rank{0};
  bool connected{false};
};

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_NODE_INFO_H_
