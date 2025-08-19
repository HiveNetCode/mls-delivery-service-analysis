/**
 * @file pki_client.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Client functions to interact with PKI
 */

#ifndef __PKI_CLIENT_HPP__
#define __PKI_CLIENT_HPP__

#include <netdb.h>
#include <netinet/in.h>

#include "check.hpp"
#include "net_resolv.hpp"
#include "pki.hpp"

static int connectToPKI(const char * hostname)
{
    int client = socket(AF_INET, SOCK_STREAM, 0);
    PCHECK(client);

    struct sockaddr_in PKIAddr = getSockaddrFromString(hostname, PKI_PORT);

    if(connect(client, (struct sockaddr *) &PKIAddr, sizeof(struct sockaddr_in)) == -1)
        sys_error("Error connecting to PKI");

    return client;
}

static void publishToPKI(const char * pkiAddress, struct sockaddr_in addr,
    std::string id, Bytes keyPackage)
{
    int client = connectToPKI(pkiAddress);

    PKIRequest req;
    req.type = REQUEST_PUBLISH;
    req.pubRequest = PKIPublishRequest{id, ntohs(addr.sin_port), {keyPackage}};
    PKISendRequest(client, req);

    PKIPublishResponse resp = PKIRecvPublishResponse(client);
    CHECK(resp.success);

    PCHECK(close(client));
}

static PKIQueryResponse queryPKI(const char * pkiAddress, std::string id)
{
    int client = connectToPKI(pkiAddress);

    PKIRequest req;
    req.type = REQUEST_QUERY;
    req.queryRequestId = id;
    PKISendRequest(client, req);

    PKIQueryResponse resp = PKIRecvQueryResponse(client);
    CHECK(resp.success);

    PCHECK(close(client));
    return resp;
}

static PKIQueryResponse queryAddrPKI(const char * pkiAddress, std::string id)
{
    int client = connectToPKI(pkiAddress);

    PKIRequest req;
    req.type = REQUEST_ADDR;
    req.queryRequestId = id;
    PKISendRequest(client, req);

    PKIQueryResponse resp = PKIRecvAddrResponse(client);
    CHECK(resp.success);

    PCHECK(close(client));
    return resp;
}

#endif
