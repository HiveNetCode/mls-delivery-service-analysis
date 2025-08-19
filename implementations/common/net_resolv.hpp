/**
 * @file net_resolv.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Network address resolution utilities
 */

#ifndef __NET_RESOLV_HPP__
#define __NET_RESOLV_HPP__

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <string>

static struct in_addr getAddrFromName(const char * hostname)
{
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Use IPv4

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0)
    {
        fprintf(stderr, "Error resolving name %s: %s\n", hostname, gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    // Assuming only the first result
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    struct in_addr ipAddr = ipv4->sin_addr;

    freeaddrinfo(res);
    return ipAddr;
}

static struct sockaddr_in getSockaddrFromString(const char * fullAddr,
    int defaultPort)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    std::string hostport{fullAddr};
    size_t colonPos = hostport.find(':');
    std::string hostname;
    int port;

    if (colonPos != std::string::npos)
    {
        // Split the hostport string into hostname and port
        hostname = hostport.substr(0, colonPos);
        port = std::stoi(hostport.substr(colonPos + 1));
    }
    else
    {
        // No port specified, use the default port
        hostname = hostport;
        port = defaultPort;
    }

    // Resolve hostname to IP address
    struct in_addr ipAddr = getAddrFromName(hostname.c_str());
    addr.sin_addr = ipAddr;
    addr.sin_port = htons(port);

    return addr;
}

#endif
