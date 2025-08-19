/**
 * @file delivery_service.cpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Centralized Delivery Service
 *
 * Just forwards every received messages to all connected users
 */

#include "delivery_service.hpp"

#include <algorithm>
#include <cstddef>
#include <set>
#include <unistd.h>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <cstdio>
#include <cstdlib>

#include <netinet/in.h>
#include <sys/socket.h>

#include "bytes/bytes.h"
#include "mls/common.h"
#include "mls/messages.h"

#include "check.hpp"
#include "ds_message.hpp"

int start_server(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s == -1)
        sys_error("Error Opening socket");

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr =
            { .s_addr = INADDR_ANY }
    };

    if(bind(s, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
        sys_error("Error binding socket to port");

    if(listen(s, 100) == -1)
        sys_error("Error listening to socket");

    return s;
}

const char * wire_format_txt(const mls::WireFormat & wire_format)
{
    switch(wire_format)
    {
        case mls::WireFormat::mls_group_info:       return "Group Info";
        case mls::WireFormat::mls_key_package:      return "Key Package";
        case mls::WireFormat::mls_private_message:  return "Private Message";
        case mls::WireFormat::mls_public_message:   return "Public Message";
        case mls::WireFormat::mls_welcome:          return "Welcome";
        case mls::WireFormat::reserved:             return "Reserved";
    }
}

const char * ds_msg_type_txt(const DSMessageType & type)
{
    switch(type)
    {
        case DS_SUBSCRIBE_CLIENT: return "Client Subscribe";
        case DS_SUBSCRIBE_GROUP:  return "Group Subscribe";
        case DS_SEND:             return "Send";
        case DS_BCAST:            return "Broadcast";
    }
}

std::map<mls::bytes_ns::bytes, std::vector<mls::MLSMessage>> clientMessages;
std::map<mls::bytes_ns::bytes, std::vector<mls::MLSMessage>> groupMessages;

std::map<mls::bytes_ns::bytes, mls::epoch_t> estimatedCurrentEpoch;
// Store the index where we estimates the start of an epoch as indication for new members,
//  we may only estimate the start of an epoch too early if an attacker sends an invalid message
std::map<mls::bytes_ns::bytes, std::map<mls::epoch_t, size_t>> estimatedEpochStarts;

std::map<mls::bytes_ns::bytes, std::unordered_set<int>> clientSubscribers,
    groupSubscribers;
std::unordered_map<int, std::vector<mls::bytes_ns::bytes>> subscribedToClients,
    subscribedToGroups;

void disconnectClient(int client)
{
    print(printf("Disconnection: %d\n", client);)
    if(close(client) == -1)
        perror("Error on closing connection (1)");

    for(const auto & clientRef : subscribedToClients[client])
        clientSubscribers[clientRef].erase(client);
    subscribedToClients.erase(client);

    for(const auto & group : subscribedToGroups[client])
        groupSubscribers[group].erase(client);
    subscribedToGroups.erase(client);
}

bool sendList(int receiver, const std::vector<mls::MLSMessage> & messages)
{
    for(const auto & message : messages)
    {
        const mls::bytes_ns::bytes msgBytes = mls::tls::marshal(message);
        const dsMsgSize size = msgBytes.size();

        if(send(receiver, &size, sizeof(dsMsgSize), 0) < 0
                || send(receiver, msgBytes.data(), size, 0) < 0)
        {
            perror("Error while sending messages to client");
            return false;
        }
    }
    return true;
}

void handleMessage(const DSMessage & message, int sender,
    std::unordered_set<int> & disconnected)
{
    print(printf("Received message type:%s from %d\n",
        ds_msg_type_txt(message.type()), sender));

    if(message.isClientSubscribe())
    {
        auto & keyPackageRef = message.clientSubscribe().keyPackageRef;

        print(fprintf(stderr, "Client Subscribe on %d\n", MLS_UTIL_HASH_REF(keyPackageRef));)
        
        clientSubscribers[keyPackageRef].insert(sender);
        subscribedToClients[sender].emplace_back(keyPackageRef);

        if(!sendList(sender, clientMessages[keyPackageRef]))
            disconnected.insert(sender);
    }
    else if(message.isGroupSubscribe())
    {
        auto & groupId = message.groupSubscribe().groupId;
        mls::epoch_t startEpoch = message.groupSubscribe().epoch;

        groupSubscribers[groupId].insert(sender);
        subscribedToGroups[sender].emplace_back(groupId);

        auto estimatedEpochStart = estimatedEpochStarts[groupId].find(startEpoch);
        if(estimatedEpochStart != estimatedEpochStarts[groupId].end())
        {
            size_t messageIdx = estimatedEpochStart->second;

            if(!sendList(sender, std::vector<mls::MLSMessage>(
                groupMessages[groupId].begin() + messageIdx,
                    groupMessages[groupId].end())))
                disconnected.insert(sender);
        }
    }
    else if(message.isSend())
    {
        auto & sendInfo = message.sendMessage();

        const mls::bytes_ns::bytes msgBytes = mls::tls::marshal(sendInfo.content);
        const dsMsgSize size = msgBytes.size();

        print(fprintf(stderr, "Sending to %d recipients\n", sendInfo.recipients.size());)

        for(const auto & recipient : sendInfo.recipients)
        {
            clientMessages[recipient].emplace_back(sendInfo.content);
            print(fprintf(stderr, "Sending to %d\n", MLS_UTIL_HASH_REF(recipient));)

            for(auto recipientSock : clientSubscribers[recipient])
                if(disconnected.count(recipientSock) <= 0)
                    if(send(recipientSock, &size, sizeof(dsMsgSize), 0) < 0
                        || send(recipientSock, msgBytes.data(), size, 0) < 0)
                    {
                        perror("Error while forwarding message to client");
                        disconnected.insert(recipientSock);
                    }
        }
    }
    else if(message.isBcast())
    {
        auto & bcastInfo = message.bcastMessage();

        const mls::bytes_ns::bytes msgBytes = mls::tls::marshal(bcastInfo.content);
        const dsMsgSize size = msgBytes.size();

        if(bcastInfo.content.wire_format() != mls::WireFormat::mls_private_message)
            return;

        const mls::PrivateMessage privateMsg = std::get<mls::PrivateMessage>(
            message.bcastMessage().content.message);
        const auto & groupId = privateMsg.get_group_id();

        const auto estimatedEpoch = bcastInfo.content.epoch();
        if(estimatedEpoch > estimatedCurrentEpoch[groupId])
        {
            for(auto ep = estimatedCurrentEpoch[groupId] + 1; ep <= estimatedEpoch; ++ep)
                estimatedEpochStarts[groupId][ep] = groupMessages[groupId].size();

            estimatedCurrentEpoch[groupId] = estimatedEpoch;
        }

        groupMessages[groupId].emplace_back(bcastInfo.content);

        for(const auto & recipient : groupSubscribers[groupId])
            if(send(recipient, &size, sizeof(dsMsgSize), 0) < 0
                || send(recipient, msgBytes.data(), size, 0) < 0)
            {
                perror("Error while forwarding group message to client");
                disconnected.insert(recipient);
            }
    }
}

int main(int argc, char * argv[])
{
    if(argc < 2)
        fprintf(stderr, "No port number provided, defaulting to %d\n", DS_PORT);

    const int port = argc < 2 ? DS_PORT : atoi(argv[1]);
    const int server = start_server(port);

    std::set<int> clients;
    fd_set readfds;
    while(1)
    {
        const int nfds = std::max(
            server, *std::max_element(clients.begin(), clients.end())) + 1;
        FD_ZERO(&readfds);

        FD_SET(server, &readfds);
        for(const auto& client : clients)
            FD_SET(client, &readfds);

        if(select(nfds, &readfds, NULL, NULL, NULL) <= 0)
            sys_error("Error on call to select()");

        if(FD_ISSET(server, &readfds))
        {
            struct sockaddr addr;
            socklen_t addrLen = sizeof(struct sockaddr);

            const int newClient = accept(server, &addr, &addrLen);
            if(newClient == -1)
            {
                perror("Error accepting connection");
            }
            else
            {
                clients.insert(newClient);
                print(printf("New connection: %d\n", newClient);)
            }            
        }

        for(auto it = clients.begin(); it != clients.end(); )
        {
            auto client = *it;

            if(FD_ISSET(client, &readfds))
            {
                dsMsgSize size;
                const ssize_t n = recv(client, &size, sizeof(dsMsgSize), 0);
                if(n <= 0)
                {
                    if(n < 0)
                        perror("Error receive message");

                    disconnectClient(client);
                    it = clients.erase(it);
                    continue;
                }

                // Read client's message and broadcast it
                uint8_t * content = new uint8_t[size]();
                dsMsgSize idx = 0;
                while(size - idx > 0)
                {
                    const ssize_t n = recv(client, &content[idx], size - idx, 0);
                    if(n <= 0)
                    {
                        perror("Error during message reception");

                        disconnectClient(client);
                        it = clients.erase(it);
                        continue;
                    }
                    else
                        idx += n;
                }

                print(fprintf(stderr, "Received message %d-%d\n", size, hash32(content, size));)
                std::vector<uint8_t> messageBytes{content, content + size};
                delete[] content;

                DSMessage message;

                try
                {
                    mls::tls::unmarshal(messageBytes, message);
                }
                catch(std::exception & e)
                {
                    fprintf(stderr, "Error interpreting message from %d: %s\n",
                        client, e.what());

                    disconnectClient(client);
                    it = clients.erase(it);
                    continue;
                }

                std::unordered_set<int> disconnected;
                handleMessage(message, client, disconnected);

                if(!disconnected.empty())
                {
                    for(const auto & discClient : disconnected)
                    {
                        disconnectClient(discClient);
                        clients.erase(discClient);
                    }

                    break; // The erasures broke the iterator, so we'll simply start again with another select
                }
            }

            it++;
        }
    }

    return 0;
}
