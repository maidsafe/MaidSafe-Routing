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

#ifndef MAIDSAFE_ROUTING_TYPES_H_
#define MAIDSAFE_ROUTING_TYPES_H_

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "asio/async_result.hpp"
#include "asio/handler_type.hpp"
#include "asio/ip/udp.hpp"
#include "boost/expected/expected.hpp"
#include "boost/optional/optional.hpp"
#include "boost/variant/variant.hpp"

#include "maidsafe/common/bounded_string.h"
#include "maidsafe/common/identity.h"
#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/routing/contact.h"
#include "maidsafe/routing/endpoint_pair.h"

namespace maidsafe {

namespace routing {

static const size_t GroupSize = 23;
static const size_t QuorumSize = 19;

enum class FromType : int32_t {
  client_manager,
  nae_manager,
  node_manager,
  managed_client,
  remote_client,
  managed_node,
  node
};

enum class Authority : int32_t {
  client_manager,
  nae_manager,
  node_manager,
  managed_node,
  node,
  client
};

using Address = Identity;
using MessageId = uint32_t;
using Destination = TaggedValue<Address, struct DestinationTag>;
using ReplyToAddress = TaggedValue<Address, struct ReplytoTag>;
using DestinationAddress = std::pair<Destination, boost::optional<ReplyToAddress>>;
using NodeAddress = TaggedValue<Address, struct NodeTag>;
using GroupAddress = TaggedValue<Address, struct GroupTag>;

using SendGetClientKey = std::function<void(Address)>;
using SendGetGroupKey = std::function<void(GroupAddress)>;

template <class Archive>
void serialize(Archive& archive, DestinationAddress& address) {
  archive(address.first, address.second);
}

using FilterType = std::pair<NodeAddress, MessageId>;
using HandleGetReturn =
    boost::expected<boost::variant<std::vector<DestinationAddress>, std::vector<byte>>,
                    maidsafe_error>;
using HandlePutPostReturn = boost::expected<std::vector<DestinationAddress>, maidsafe_error>;
using HandlePostReturn =
    boost::expected<std::pair<std::vector<DestinationAddress>, std::vector<byte>>,
                    maidsafe_error>;

using Endpoint = asio::ip::udp::endpoint;
using Port = uint16_t;
using SerialisedMessage = std::vector<byte>;
using CloseGroupDifference = std::pair<std::vector<Address>, std::vector<Address>>;

template <typename CompletionToken>
using BootstrapHandlerHandler =
    typename asio::handler_type<CompletionToken, void(asio::error_code, Contact)>::type;

template <typename CompletionToken>
using BootstrapReturn = typename asio::async_result<BootstrapHandlerHandler<CompletionToken>>::type;

template <typename CompletionToken>
using PostHandler = typename asio::handler_type<CompletionToken, void(asio::error_code)>::type;

template <typename CompletionToken>
using PostReturn = typename asio::async_result<PostHandler<CompletionToken>>::type;

template <typename CompletionToken>
using PutHandler = typename asio::handler_type<CompletionToken, void(asio::error_code)>::type;

template <typename CompletionToken>
using PutReturn = typename asio::async_result<PutHandler<CompletionToken>>::type;

template <typename CompletionToken>
using GetHandler =
    typename asio::handler_type<CompletionToken, void(asio::error_code, SerialisedMessage)>::type;

template <typename CompletionToken>
using GetReturn = typename asio::async_result<GetHandler<CompletionToken>>::type;

template <typename CompletionToken>
using RequestHandler =
    typename asio::handler_type<CompletionToken, void(asio::error_code, SerialisedMessage)>::type;

template <typename CompletionToken>
using RequestReturn = typename asio::async_result<RequestHandler<CompletionToken>>::type;


}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_TYPES_H_
