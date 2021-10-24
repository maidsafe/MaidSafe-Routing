/*  Copyright 2015 MaidSafe.net limited

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

#include <memory>
#include <vector>

#include "cereal/types/base_class.hpp"
#include "cereal/types/polymorphic.hpp"
#include "maidsafe/common/serialisation/binary_archive.h"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/convert.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/data_types/immutable_data.h"

#include "maidsafe/passport/types.h"

#include "maidsafe/routing/sentinel.h"
#include "maidsafe/routing/messages/messages.h"
#include "maidsafe/routing/account_transfer_info.h"

namespace maidsafe {

namespace routing {

namespace test {

class SentinelTest : public testing::Test {
 public:
  SentinelTest() : sentinel_(new Sentinel([](Address) {}, [](GroupAddress) {})),
                   maid_nodes_(),
                   source_address_(NodeAddress(Address(MakeIdentity())), boost::none,
                                               boost::none) {}
  struct SentinelAddInfo {
    MessageHeader header;
    MessageTypeTag tag;
    SerialisedMessage serialised;
  };

  template <typename MessageType>
  SentinelAddInfo MakeAddInfo(const MessageType& message, const asymm::PrivateKey& private_key,
                              const DestinationAddress& destination, const SourceAddress& source,
                              MessageId message_id, Authority our_authority, MessageTypeTag tag) {
    SentinelAddInfo add_info;
    add_info.tag = tag;
    add_info.serialised = Serialise(message);
    add_info.header = MessageHeader(destination, source, message_id, our_authority,
                                    asymm::Sign(rsa::PlainText(add_info.serialised), private_key));
    return add_info;
  }

  void CreateMaidKeys(size_t quantity) {
    while (quantity-- > 0)
      maid_nodes_.emplace_back(passport::CreateMaidAndSigner().first);
  }

  void CreatePmidKeys(size_t quantity) {
    while (quantity-- > 0)
      pmid_nodes_.emplace_back(passport::CreatePmidAndSigner().first);
  }

  SentinelAddInfo CreateGetKeyResponse(const passport::Maid& maid, MessageId message_id,
                                       Address source, passport::Pmid& pmid) {
    GetClientKeyResponse get_client_response(Address(maid.name()), maid.public_key());
    return MakeAddInfo(get_client_response,
                       pmid.private_key(),
                       DestinationAddress(std::make_pair(Destination(source), boost::none)),
                       SourceAddress(NodeAddress(Identity(pmid.name())),
                                     GroupAddress(source), boost::none),
                       message_id, Authority::nae_manager,
                       MessageTypeTag::GetClientKeyResponse);
  }

  SentinelAddInfo CreateFindGroupResponse(const passport::Maid& maid, MessageId message_id,
        std::vector<passport::Pmid>& pmids, passport::Pmid& pmid) {
    std::vector<passport::PublicPmid> public_pmids;
    for (const auto& pmid : pmids)
      public_pmids.push_back(passport::PublicPmid(pmid));
    FindGroupResponse find_group_response(Address(pmid.name()), public_pmids);
    return MakeAddInfo(find_group_response,
                       pmid.private_key(),
                       DestinationAddress(std::make_pair(Destination(maid.name()), boost::none)),
                       SourceAddress(NodeAddress(Identity(pmid.name())),
                                     GroupAddress(maid.name()), boost::none),
                       message_id, Authority::client_manager,
                       MessageTypeTag::FindGroupResponse);
  }

  std::vector<SentinelAddInfo> CreateFindGroupResponseKeys(MessageId message_id,
                                                           const GroupAddress& target,
                                                           const GroupAddress& source,
                                                           Authority authority,
                                                           std::vector<passport::Pmid> pmids) {
    std::map<Address, asymm::PublicKey> public_key_map;
    for (size_t index(0); index < GroupSize; ++index)
      public_key_map.insert(std::make_pair(Address(Identity(pmids.at(index).name())),
                                           pmids.at(index).public_key()));
    GetGroupKeyResponse get_group_key_response(public_key_map, target);
    return CreateGroupMessage(get_group_key_response, message_id, authority,
                              MessageTypeTag::GetGroupKeyResponse, target, source);
  }

  std::vector<SentinelAddInfo> CreateGetGroupKeyResponse(MessageId message_id,
                                                         const GroupAddress& target,
                                                         const GroupAddress& source,
                                                         Authority authority) {
    std::sort(pmid_nodes_.begin(), pmid_nodes_.end(),
              [&](const passport::Pmid& lhs, const passport::Pmid& rhs) {
                return CloserToTarget(Identity(lhs.name()),
                                      Identity(rhs.name()),
                                      source.data);
              });
    std::map<Address, asymm::PublicKey> public_key_map;
    for (size_t index(0); index < GroupSize; ++index)
      public_key_map.insert(std::make_pair(Address(Identity(pmid_nodes_.at(index).name())),
                                           pmid_nodes_.at(index).public_key()));
    GetGroupKeyResponse get_group_key_response(public_key_map, target);
    return CreateGroupMessage(get_group_key_response, message_id, authority,
                              MessageTypeTag::GetGroupKeyResponse, target, source);
  }

  template<typename MessageType>
  std::vector<SentinelAddInfo>
  CreateGroupMessage(const MessageType& message, MessageId message_id, Authority authority,
                     MessageTypeTag message_type, const GroupAddress& target,
                     const GroupAddress& source) {
    assert(pmid_nodes_.size() >= GroupSize);
    std::vector<SentinelAddInfo> group_message;
    std::sort(pmid_nodes_.begin(), pmid_nodes_.end(),
              [&](const passport::Pmid& lhs, const passport::Pmid& rhs) {
                return CloserToTarget(lhs.name(), rhs.name(), source.data);
              });

    for (size_t index(0); index < GroupSize; ++index) {
      group_message.emplace_back(
          MakeAddInfo(message, pmid_nodes_.at(index).private_key(),
                      DestinationAddress(std::make_pair(Destination(target.data), boost::none)),
                      SourceAddress(NodeAddress(pmid_nodes_.at(index).name()),
                                    source, boost::none),
                      message_id, authority, message_type));
    }

    assert(group_message.size() >= GroupSize);
    return group_message;
  }

 protected:
  void SortPmidNodes(const Address& target) {
    std::sort(pmid_nodes_.begin(), pmid_nodes_.end(),
              [&](const passport::Pmid& lhs, const passport::Pmid& rhs) {
                return CloserToTarget(Identity(lhs.name()), Identity(rhs.name()), target);
              });
  }

  template <size_t N>
  std::vector<passport::Pmid> GetFrontPmids() {
    std::vector<passport::Pmid> pmids;
    size_t size(pmid_nodes_.size() < N ? pmid_nodes_.size() : N);
    for (size_t i = 0; i != size; ++i)
      pmids.push_back(pmid_nodes_[i]);
    return pmids;
  }

  std::unique_ptr<Sentinel> sentinel_;
  std::vector<passport::Maid> maid_nodes_;
  std::vector<passport::Pmid> pmid_nodes_;
  SourceAddress source_address_;
};

TEST_F(SentinelTest, FUNC_BasicNonGroupAdd) {
  CreateMaidKeys(1);
  CreatePmidKeys(QuorumSize);
  ImmutableData data(NonEmptyString(RandomBytes(identity_size)));
  PutData put_data(data.TypeId(), SerialisedData(Serialise(data)));
  auto add_info(MakeAddInfo(put_data, maid_nodes_.at(0).private_key(),
                            DestinationAddress(
                                std::make_pair(Destination(Identity(maid_nodes_.at(0).name())),
                                               boost::none)),
                            source_address_,
                            MessageId(RandomUint32()), Authority::client_manager,
                            MessageTypeTag::PutData));

  auto resolved(this->sentinel_->Add(add_info.header, add_info.tag, add_info.serialised));
  if (resolved)
    EXPECT_TRUE(false);

  for (size_t index(0); index < QuorumSize - 1; ++index) {
      auto add_key_info(CreateGetKeyResponse(maid_nodes_.at(0), add_info.header.MessageId(),
                                             source_address_.node_address.data,
                                             pmid_nodes_.at(index)));
    resolved = (this->sentinel_->Add(add_key_info.header, add_key_info.tag,
                                     add_key_info.serialised));
    if (resolved)
      EXPECT_TRUE(false);
  }
  auto add_key_info(CreateGetKeyResponse(maid_nodes_.at(0), add_info.header.MessageId(),
                                         source_address_.node_address.data,
                                         pmid_nodes_.at(QuorumSize - 1)));
  resolved = (this->sentinel_->Add(add_key_info.header, add_key_info.tag,
                                   add_key_info.serialised));
  if (!resolved)
    EXPECT_TRUE(false);
}

TEST_F(SentinelTest, FUNC_BasicGroupAdd) {
  CreatePmidKeys(GroupSize * 4);
  ImmutableData data(NonEmptyString(RandomBytes(identity_size)));
  PutData put_data(data.TypeId(), SerialisedData(Serialise(data)));
  MessageId message_id(RandomInt32());
  auto group_message(CreateGroupMessage(put_data, message_id, Authority::nae_manager,
                                        MessageTypeTag::PutData,
                                        GroupAddress(source_address_.node_address.data),
                                        GroupAddress(data.Name())));

  auto group_key_response(
      CreateGetGroupKeyResponse(message_id, GroupAddress(source_address_.node_address.data),
                                GroupAddress(data.Name()),
                                Authority::nae_manager));
  for (const auto& add_key_info : group_message) {
    auto resolved(sentinel_->Add(add_key_info.header, add_key_info.tag, add_key_info.serialised));
    if (resolved)
      EXPECT_TRUE(false);
  }

  for (size_t index(0); index < QuorumSize - 1; ++index) {
    auto resolved(sentinel_->Add(group_key_response.at(index).header,
                                 group_key_response.at(index).tag,
                                 group_key_response.at(index).serialised));
    if (resolved)
      EXPECT_TRUE(false);
  }
  auto resolved(sentinel_->Add(group_key_response.at(QuorumSize - 1).header,
                               group_key_response.at(QuorumSize - 1).tag,
                               group_key_response.at(QuorumSize - 1).serialised));
  if (!resolved)
    EXPECT_TRUE(false);
}

TEST_F(SentinelTest, BEH_FindGroupResponse) {
  CreateMaidKeys(1);
  CreatePmidKeys(GroupSize * 4);

  SortPmidNodes(Address(maid_nodes_.at(0).name()));
  auto sorted_pmids(GetFrontPmids<GroupSize>());
  std::vector<std::vector<passport::Pmid>> pmids;

  for (size_t i = 0; i != sorted_pmids.size(); ++i) {
    SortPmidNodes(Address(sorted_pmids[i].name()));
    pmids.push_back(GetFrontPmids<GroupSize>());
  }

  MessageId message_id(RandomUint32()), key_message_id(RandomUint32());
  boost::optional<Sentinel::ResultType> resolved;
  for (size_t i = 0; i != pmids.size(); ++i) {
    auto keys_infos(CreateFindGroupResponseKeys(key_message_id,
        GroupAddress(maid_nodes_.at(0).name()), GroupAddress(pmids.at(i).at(0).name()),
        Authority::client_manager, pmids.at(i)));
    for (const auto& key_info : keys_infos) {
      resolved = sentinel_->Add(key_info.header, key_info.tag, key_info.serialised);
      if (resolved)
        EXPECT_TRUE(false);
    }

    auto info(CreateFindGroupResponse(
        maid_nodes_.at(0), message_id, pmids.at(i), pmids.at(i).at(0)));
    resolved = this->sentinel_->Add(info.header, info.tag, info.serialised);
    if ((i != pmids.size() - 1) && resolved)
      EXPECT_TRUE(false);

    if ((i != pmids.size() - 1) && resolved)
      EXPECT_TRUE(false);
  }

  if (!resolved)
    EXPECT_TRUE(false);
}


class AccountTransfer : public AccountTransferInfo {
 public:
  AccountTransfer() = default;
  AccountTransfer(Identity identy, int value)
      : AccountTransferInfo(identy), value_(value) {}

  std::uint32_t ThisTypeId() const override {
    return 1;
  }

  ~AccountTransfer() override final = default;

  int value() const { return value_; }

  template <typename Archive>
  Archive& save(Archive& archive) const {
    return archive(cereal::base_class<AccountTransferInfo>(this), value_);
  }

  template <typename Archive>
  Archive& load(Archive& archive) {
    try {
      archive(cereal::base_class<AccountTransferInfo>(this), value_);
    } catch (const std::exception&) {
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
    }
    return archive;
  }

  std::unique_ptr<AccountTransferInfo> Merge(
      const std::vector<std::unique_ptr<AccountTransferInfo>>& accounts) override {
    decltype(value_) merged(0);
    for (size_t index(0); index < accounts.size(); ++index)
       merged += dynamic_cast<AccountTransfer*>(accounts.at(index).get())->value();

    return maidsafe::make_unique<AccountTransfer>(Name(), merged);
  }

 private:
  int value_;
};

TEST_F(SentinelTest, FUNC_BasicAccountTransferAdd) {
  CreatePmidKeys(GroupSize * 2);
  SortPmidNodes(source_address_.node_address.data);
  MessageId message_id(RandomInt32());
  std::vector<SentinelAddInfo> account_transfers;
  for (size_t index(0); index < GroupSize; ++index) {
    std::unique_ptr<AccountTransferInfo>
        account(dynamic_cast<AccountTransferInfo*>(
                    new AccountTransfer(Identity(source_address_.node_address.data.string()),
                                        static_cast<int>(index))));
    account_transfers.emplace_back(
        MakeAddInfo(account, pmid_nodes_.at(index).private_key(),
                    DestinationAddress(std::make_pair(
                                           Destination(source_address_.node_address.data),
                                           boost::none)),
                    SourceAddress(NodeAddress(Address(pmid_nodes_.at(index).name())),
                                  GroupAddress(source_address_.node_address.data), boost::none),
                message_id, Authority::nae_manager, MessageTypeTag::AccountTransfer));
  }

  for (const auto& add_info : account_transfers) {
    auto resolved(sentinel_->Add(add_info.header, add_info.tag, add_info.serialised));
    if (resolved)
      EXPECT_TRUE(false);
  }

  auto group_key_response(
      CreateGetGroupKeyResponse(message_id, GroupAddress(source_address_.node_address.data),
                                GroupAddress(source_address_.node_address.data),
                                Authority::nae_manager));
  for (size_t index(0); index < QuorumSize - 1; ++index) {
    auto resolved(sentinel_->Add(group_key_response.at(index).header,
                                 group_key_response.at(index).tag,
                                 group_key_response.at(index).serialised));
    if (resolved)
      EXPECT_TRUE(false);
  }
  auto resolved(sentinel_->Add(group_key_response.at(QuorumSize - 1).header,
                               group_key_response.at(QuorumSize - 1).tag,
                               group_key_response.at(QuorumSize - 1).serialised));
  if (!resolved)
    EXPECT_TRUE(false);

  auto base_ptr(Parse<std::unique_ptr<AccountTransferInfo>>(std::get<2>(*resolved)));
  auto merged(dynamic_cast<AccountTransfer*>(base_ptr.get()));
  EXPECT_EQ(merged->value(), GroupSize*(GroupSize - 1) / 2);
}

}  // namespace test

}  // namespace routing

}  // namespace maidsafe

CEREAL_REGISTER_TYPE(maidsafe::routing::test::AccountTransfer)
