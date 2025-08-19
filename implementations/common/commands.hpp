/**
 * @file commands.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Common interface to control MLS Client using commands from standard
 *  input
 * 
 * Common commands are:
 *  - Create
 *  - Add <identity>
 *  - Remove <identity>
 *  - Update
 *  - Message <message>
 *  - Stop
 */

#ifndef __COMMANDS_HPP__
#define __COMMANDS_HPP__

#include <functional>
#include <iostream>

#include "mls_client.hpp"

template<typename T>
const std::function<bool(void)> mlsClientCommandCallback(MLSClient<T> & client,
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
        else if(command == "print")
            client.printTree();
        else if(command == "stop")
            return false;
        else
            printf("Invalid command\n");

        return true; // Client did not stop
    };
}

#endif
