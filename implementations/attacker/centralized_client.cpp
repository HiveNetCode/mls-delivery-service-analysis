/**
 * @file centralized_client.cpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief MLS Client relying on centralized Delivery Service
 *  Additionally this client provides a command to send an invalid commit
 *      (in this case a commit referencing a proposal that does not exist)
 * 
 * Usage: ./mls_client <identity> <pki-addr> <ds-addr> <network-rtt>
 *  - identity:    unique string identifier for the client
 *  - pki-addr:    address of the pki to be used
 *  - ds-addr:     address of the delivery service to be used
 *  - network-rtt: rtt with the farthest client in the network (in ms)
 *      -> after submitting proposal and waiting one rtt, client will commit
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bytes/bytes.h"
#include "mls/crypto.h"

#include "centralized_ds_interface.hpp"
#include "check.hpp"
#include "delivery_service.hpp"
#include "malicious_client.hpp"
#include "net_resolv.hpp"
#include "network.hpp"

const mls::bytes_ns::bytes GROUP_ID = { 0xAB, 0xCD };
const mls::CipherSuite SUITE { mls::CipherSuite::ID::X448_AES256GCM_SHA512_Ed448 };

template<typename T>
const std::function<bool(void)> mlsClientCommandCallback(MaliciousClient<T> & client,
    const mls::bytes_ns::bytes & groupId)
{
    return [&]()
    {
        std::string line;
        std::getline(std::cin, line);

        std::istringstream iss(line);
        std::string command, arg;

        iss >> command >> std::ws;
        std::getline(iss, arg);

        if(command == "create")
            client.create(groupId);
        else if(command == "add" || command == "remove" || command == "message")
        {
            if(arg.empty())
                printf("Error: missing argument for command %s\n", command.c_str());
            else
            {
                if(command == "add")
                    client.add(arg);
                else if(command == "remove")
                    client.remove(arg);
                else if(command == "message")
                    client.message(arg);
            }
        }
        else if(command == "update")
            client.update();
        else if(command == "invalid-commit")
            client.commit(true);
        else if(command == "stop")
            return false;
        else
            printf("Invalid command\n");

        return true; // Client did not stop
    };
}

int main(int argc, char * argv[])
{
    if(argc < 5)
    {
        fprintf(stderr, "usage: %s <identity> <pki-addr> <ds-addr> <network-rtt>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char * clientIdentity = argv[1];
    const char * pkiAddress = argv[2];
    const char * dsAddress = argv[3];
    const int networkRtt = atoi(argv[4]);

    int client = socket(AF_INET, SOCK_STREAM, 0);
    PCHECK(client);

    struct sockaddr_in dsSockAddr = getSockaddrFromString(dsAddress, DS_PORT);

    if(connect(client, (struct sockaddr *) &dsSockAddr, sizeof(struct sockaddr_in)) == -1)
        sys_error("Error connecting to the Delivery Service");

    mls::bytes_ns::bytes clientIdBytes{{clientIdentity,
        clientIdentity + strlen(clientIdentity)}};

    Network network(client);
    MaliciousClient<CentralizedDSInterface> mlsClient(network, SUITE,
        clientIdBytes, pkiAddress, networkRtt);

    mlsClient.runSelect(mlsClientCommandCallback(mlsClient, GROUP_ID));

    return 0;
}
