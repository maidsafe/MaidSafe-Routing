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

#include <bitset>
#include <memory>
#include <vector>

#include "maidsafe/common/node_id.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/routing/routing_table.h"
#include "maidsafe/routing/types.h"
#include "maidsafe/routing/tests/main/test_utils.h"


namespace maidsafe {

namespace routing {

namespace test {

TEST(routing_table_test, FUNC_add_multiple_nodes) {
  auto routing_tables(routing_table_network(1000));
  // iterate and try to add each node to each other node
  for (const auto& node : routing_tables) {
    for (const auto& node_to_add : routing_tables) {
      node_info node_info_to_add;
      node_info_to_add.id = node_to_add->our_id();
      EXPECT_FALSE(node->add_node(node_info_to_add));
      node_info_to_add.public_key = node_to_add->our_public_key();
      if (node->size() < default_routing_table_size && node->our_id() != node_info_to_add.id)
        EXPECT_TRUE(node->check_node(node_info_to_add));
      if (node->our_id() == node_info_to_add.id)
        EXPECT_FALSE(node->add_node(node_info_to_add));
    }
  }
}

}  // namespace test

}  // namespace routing

}  // namespace maidsafe