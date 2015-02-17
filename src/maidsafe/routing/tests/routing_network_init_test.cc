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


#include <chrono>

#include "asio/use_future.hpp"
#include "asio/ip/udp.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/node_id.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/data_types/immutable_data.h"
#include "maidsafe/common/sqlite3_wrapper.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/routing/routing_node.h"
#include "maidsafe/routing/bootstrap_handler.h"
#include "maidsafe/routing/types.h"
#include "maidsafe/routing/tests/utils/test_utils.h"

namespace maidsafe {

namespace routing {

namespace test {

struct MultiHandler {
  virtual void Shutdown() = 0;

  void HandleMessage(GetData, MessageHeader) {
    std::cout << "HandleMessage\n";
  }
  void HandleConnectionAdded(NodeId) {
    std::cout << "HandleConnectionAdded\n";
    Shutdown();
  }
};

TEST(NetworkInitTest, FUNC_TwoNodes) {
  RoutingNode<MultiHandler> n1;
  RoutingNode<MultiHandler> n2;

  unsigned short port = 8080;

  n1.StartAccepting(port);
  n2.AddContact(asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), port));

  std::cout << "aaaaaaaaaaaaaaaaaaaaa 1\n";
  n1.Join();
  n2.Join();
  std::cout << "aaaaaaaaaaaaaaaaaaaaa 2\n";
  //auto value = NonEmptyString(RandomAlphaNumericString(65));
  //Identity key{Identity(crypto::Hash<crypto::SHA512>(value))};
  //MutableData a{MutableData::Name(key), value};
  //ImmutableData b{value};

  //Address from(Address(RandomString(Address::kSize)));
  //Address to(Address(RandomString(Address::kSize)));
}


}  // namespace test

}  // namespace routing

}  // namespace maidsafe