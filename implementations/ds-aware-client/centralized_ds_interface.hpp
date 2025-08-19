/**
 * @file centralized_ds_interface.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Interface of MLS Client with centralized Delivery Service
 */

#ifndef __CENTRALIZED_DS_INTERFACE_HPP__
#define __CENTRALIZED_DS_INTERFACE_HPP__

#include <algorithm>
#include <functional>
#include <iterator>
#include <optional>
#include <vector>

#include "bytes/bytes.h"
#include "mls/core_types.h"
#include "mls/crypto.h"
#include "mls/messages.h"

#include "ds_message.hpp"
#include "extended_mls_state.hpp"
#include "mls_client.hpp"
#include "network.hpp"

class CentralizedDSInterface
{
public:
    using NetworkType = Network;

    CentralizedDSInterface(MLSClient<CentralizedDSInterface> & mlsClient,
        Network & network)
        : mlsClient(mlsClient), network(network)
    {
        network.setMessageCallback(std::bind(
            &CentralizedDSInterface::handleMessage, this, std::placeholders::_1));

        const auto & keyPackage = mlsClient.getKeyPackage();

        DSMessage message = {
            .content = (DSClientSubscribeMessage) {
                .keyPackageRef = keyPackage.cipher_suite.ref(keyPackage)
            }
        };

        network.send(marshalToBytes(message));
    };

    void init(ExtendedMLSState * initState)
    {
        state = initState;

        DSMessage message = {
            .content = (DSGroupSubscribeMessage) {
                .groupId = state->group_id(),
                .epoch   = state->epoch()
            }
        };

        network.send(marshalToBytes(message));
    }

    void broadcastProposalOrMessage(const mls::MLSMessage & msg)
    {
        if(!state)
            return;

        DSMessage message = {
            .content = (DSBcastMessage) {
                .groupId = state->group_id(),
                .content = msg
            }
        };

        network.send(marshalToBytes(message));
    }

    bool canProposeCommit() const
    {
        return true; // No indication available / first received commit will be chosen anyway
    }

    void proposeCommit(const mls::MLSMessage & msg,
        std::optional<mls::Welcome> welcome)
    {
        if(welcome)
        {
            proposedCommit = { state->cipher_suite().ref(msg) };
            associatedWelcome = { welcome };
        }

        DSMessage message = {
            .content = (DSBcastMessage) {
                .groupId = state->group_id(),
                .content = msg
            }
        };

        network.send(marshalToBytes(message));
    }

    void handleMessage(Bytes & messageBytes)
    {
        mls::MLSMessage message;
        unmarshal(messageBytes, message);

        if(message.wire_format() == mls::WireFormat::mls_welcome)
            handleWelcome(std::get<mls::Welcome>(message.message));
        else if(message.wire_format() == mls::WireFormat::mls_private_message)
        {
            auto privateMessage = std::get<mls::PrivateMessage>(message.message);

            auto type = std::get<2>(privateMessage._tls_fields_w());
            if(type == mls::ContentType::commit)
                handleCommit(message);
            else
                handleProposalOrMessage(message);
        }
    }

protected:
    void handleWelcome(const mls::Welcome & welcome)
    {
        // TODO Case where the welcome is invalid ?
        init(mlsClient.handleWelcome(welcome));
    }

    void handleProposalOrMessage(const mls::MLSMessage & message)
    {
        auto proposalRef = state->isValidProposal(message);
        if(proposalRef)
        {
            currentProposals.insert(proposalRef.value());

            mlsClient.handleProposalOrMessage(message);
        }
        else if(state->isValidApplicationMessage(message))
        {
            mlsClient.handleProposalOrMessage(message);
        }
    }

    void handleCommit(const mls::MLSMessage & message)
    {
        if(state->isValidCommit(message))
        {
            auto commitProposals = state->isValidCommit(message);
            if(!commitProposals.has_value())
                return;

            auto proposalExists = [&](const mls::bytes_ns::bytes & ref)
            { return currentProposals.count(ref) > 0; };

            // First verify we can resolve all proposal references,
            //  otherwise we reject the commit
            // Other members wil reject the commit as well, on the condition
            //  that they receive messages in the same order
            if(!std::all_of(commitProposals->begin(), commitProposals->end(),
                proposalExists))
            {
                fprintf(stderr, "Ignoring commit with missing proposal(s)\n");
                return;
            }

            auto oldState = *state;
            state = mlsClient.handleCommit(message);

            currentProposals.clear();

            if(associatedWelcome
                && proposedCommit == oldState.cipher_suite().ref(message))
                sendWelcome(oldState.getAddedKeyPackages(message));

            proposedCommit = {}, associatedWelcome = {};
        }
    }

    void sendWelcome(const std::vector<mls::KeyPackage> & recipientsPackages)
    {
        std::vector<mls::bytes_ns::bytes> packagesRefs;
        std::transform(recipientsPackages.begin(), recipientsPackages.end(),
            std::back_inserter(packagesRefs),
            std::bind(&mls::CipherSuite::ref<mls::KeyPackage>,
                state->cipher_suite(), std::placeholders::_1));

        DSMessage message = {
            .content = (DSSendMessage) {
                .recipients = packagesRefs,
                .content    = associatedWelcome.value()
            }
        };

        network.send(marshalToBytes(message));
    }

private:
    MLSClient<CentralizedDSInterface> & mlsClient;
    Network & network;

    std::set<mls::bytes_ns::bytes> currentProposals;

    std::optional<mls::bytes_ns::bytes> proposedCommit;
    std::optional<mls::Welcome> associatedWelcome;

    ExtendedMLSState * state = nullptr;
};

#endif
