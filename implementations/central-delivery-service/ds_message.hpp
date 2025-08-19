/**
 * @file ds_message.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Specification of messages exchanged between client and centralized
 *  Delivery Service
 */

#ifndef __DS_MESSAGE_HPP__
#define __DS_MESSAGE_HPP__

#include <cstdint>
#include <variant>
#include <vector>

#include "bytes/bytes.h"
#include "mls/common.h"
#include "mls/messages.h"
#include "tls/tls_syntax.h"

enum DSMessageType : uint8_t
{
    DS_SUBSCRIBE_CLIENT = 1,
    DS_SUBSCRIBE_GROUP,
    DS_SEND,
    DS_BCAST
};

struct DSClientSubscribeMessage
{
    mls::bytes_ns::bytes keyPackageRef;
    TLS_SERIALIZABLE(keyPackageRef);
};

struct DSGroupSubscribeMessage
{
    mls::bytes_ns::bytes groupId;
    mls::epoch_t epoch;
    TLS_SERIALIZABLE(groupId, epoch);
};

struct DSSendMessage
{
    std::vector<mls::bytes_ns::bytes> recipients;
    mls::MLSMessage content;
    TLS_SERIALIZABLE(recipients, content);
};

struct DSBcastMessage
{
    mls::bytes_ns::bytes groupId;
    mls::MLSMessage content;
    TLS_SERIALIZABLE(groupId, content);
};

struct DSMessage
{
    std::variant<
        DSClientSubscribeMessage, DSGroupSubscribeMessage,
        DSSendMessage, DSBcastMessage> content;

    DSMessageType type() const
    { return mls::tls::variant<DSMessageType>::type(content); }

    bool isClientSubscribe() const
    { return type() == DS_SUBSCRIBE_CLIENT; }
    bool isGroupSubscribe() const
    { return type() == DS_SUBSCRIBE_GROUP; }
    bool isSend() const
    { return type() == DS_SEND; }
    bool isBcast() const
    { return type() == DS_BCAST; }

    const DSClientSubscribeMessage & clientSubscribe() const
    { return std::get<DSClientSubscribeMessage>(content); }
    const DSGroupSubscribeMessage & groupSubscribe() const
    { return std::get<DSGroupSubscribeMessage>(content); }
    const DSSendMessage & sendMessage() const
    { return std::get<DSSendMessage>(content); }
    const DSBcastMessage & bcastMessage() const
    { return std::get<DSBcastMessage>(content); }

    TLS_SERIALIZABLE(content);
    TLS_TRAITS(mls::tls::variant<DSMessageType>);
};

namespace mls::tls
{
    TLS_VARIANT_MAP(DSMessageType, DSClientSubscribeMessage, DS_SUBSCRIBE_CLIENT);
    TLS_VARIANT_MAP(DSMessageType, DSGroupSubscribeMessage, DS_SUBSCRIBE_GROUP);
    TLS_VARIANT_MAP(DSMessageType, DSSendMessage, DS_SEND);
    TLS_VARIANT_MAP(DSMessageType, DSBcastMessage, DS_BCAST);
}

#endif
