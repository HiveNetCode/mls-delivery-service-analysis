/**
 * @file network.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Handle low level network operations for clients
 */

#ifndef __NETWORK_HPP__
#define __NETWORK_HPP__

#include <algorithm>
#include <bits/chrono.h>
#include <bits/types/struct_timeval.h>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <optional>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "check.hpp"
#include "delivery_service.hpp"
#include "message.hpp"

using timePoint = std::chrono::time_point<std::chrono::system_clock>;

static constexpr int BUF_SIZE = 4096;

class Network
{

public:
    using timeoutID = size_t;
    using timeoutCallback = std::function<void(const timeoutID &)>;

    Network(int socket)
        : m_socket(socket), m_handleMessage(nullptr)
    { }

    void runSelect(const std::function<bool(void)> & notifyIn)
    {
        bool goon = true;

        fd_set readSet;

        while(goon)
        {
            timeval * timeout = nullptr;
            auto closestTimeout = nextTimeout();
            
            while(closestTimeout && closestTimeout->first.tv_sec == 0
                && closestTimeout->first.tv_usec == 0)
            {
                auto timeoutID = closestTimeout->second;

                m_timeouts[timeoutID].second(timeoutID);
                unregisterTimeout(timeoutID);

                closestTimeout = nextTimeout();
            }
            if(closestTimeout)
                timeout = &closestTimeout->first;

            FD_ZERO(&readSet);
            FD_SET(0, &readSet);
            FD_SET(m_socket, &readSet);

            int selectRes = select(m_socket+1, &readSet, NULL, NULL, timeout);
            PCHECK(selectRes);

            if(selectRes == 0 && closestTimeout)
            {
                auto timeoutID = closestTimeout->second;

                m_timeouts[timeoutID].second(timeoutID);
                unregisterTimeout(timeoutID);
            }

            if(FD_ISSET(0, &readSet))
            {
                goon = notifyIn();
            }

            if(FD_ISSET(m_socket, &readSet))
            {
                Bytes message = readMessage();
                m_handleMessage(message);
            }
        }
    }

    timeoutID registerTimeout(int msDelay, timeoutCallback callback)
    {
        timeoutID timeoutID = m_timeoutCounter++;

        timePoint targetedTime = std::chrono::system_clock::now()
            + std::chrono::milliseconds{msDelay};
        m_timeouts.insert({timeoutID, { targetedTime, callback }});

        return timeoutID;
    }

    void unregisterTimeout(timeoutID id)
    {
        m_timeouts.erase(id);
    }

    void send(const Bytes & message)
    {
        print(fprintf(stderr, "[Net] Sending %d-%d\n", message.size, message.hash()));

        dsMsgSize size = message.size;
        if(::send(m_socket, &size, sizeof(dsMsgSize), 0) != sizeof(dsMsgSize))
            sys_error("Error sending message to Delivery Service (header)");

        dsMsgSize idx = 0;
        while(idx < message.size)
        {
            const ssize_t n = ::send(m_socket, &message.content[idx], message.size-idx, 0);
            if(n <= 0)
                sys_error("Error while sending message to Delivery Service");
            
            idx += n;
        }
    }

    void setMessageCallback(const std::function<void(Bytes &)> & handleMessage)
    {
        m_handleMessage = handleMessage;
    }

    struct sockaddr_in getAddr()
    {
        struct sockaddr_in addr;
        socklen_t addrLen = sizeof(struct sockaddr_in);

        if(getsockname(m_socket, (struct sockaddr *) &addr, &addrLen) == -1)
            sys_error("Error retrieving local address");

        return addr;
    }

protected:
    static timeval remainingTimeval(const timePoint & timePoint)
    {
        auto now = std::chrono::system_clock::now();
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            timePoint - now);

        if(remaining.count() <= 0)
        {
            return (timeval) { .tv_sec = 0, .tv_usec = 0 };
        }
        
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(remaining);
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            remaining - seconds);

        return (timeval) { .tv_sec = seconds.count(), .tv_usec = microseconds.count() };
    }

    std::optional<std::pair<timeval, timeoutID>> nextTimeout()
    {
        if(m_timeouts.empty())
            return {};
        else
        {
            const auto chosen = std::min_element(
                m_timeouts.begin(), m_timeouts.end(),
                [](const auto & lhs, const auto & rhs)
                { return lhs.second.first < rhs.second.first; });

            return {{ remainingTimeval(chosen->second.first), chosen->first }};
        }
    }

    Bytes readMessage()
    {
        dsMsgSize size;
        const ssize_t n = recv(m_socket, &size, sizeof(dsMsgSize), 0);
        if(n == 0)
        {
            fprintf(stderr, "Delivery Service disconnected, shutting down\n");
            exit(EXIT_SUCCESS);
        }
        else if(n < 0)
            sys_error("Error receiving message from Delivery Service");

        Bytes message{size};
        dsMsgSize idx = 0;
        while(size - idx > 0)
        {
            const ssize_t n = recv(m_socket, &message.content[idx], size-idx, 0);
            if(n <= 0)
                sys_error("Error while receiving message from Delivery Service");

            idx += n;
        }

        return message;
    }

private:
    const int m_socket;

    std::function<void(Bytes &)> m_handleMessage;

    timeoutID m_timeoutCounter = 0;
    std::unordered_map<timeoutID, std::pair<timePoint, timeoutCallback>> m_timeouts;
};

#endif
