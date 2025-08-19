/**
 * @file malicious_client.hpp
 * @author Ludovic PAILLAT (Ludovic.PAILLAT@hivenet.com)
 * @brief Generic MLS Client that works with any type of Delivery Service
 */

#ifndef __MLS_CLIENT_HPP__
#define __MLS_CLIENT_HPP__

#include <functional>
#include <optional>
#include <string>

#include "bytes/bytes.h"
#include "mls/core_types.h"
#include "mls/crypto.h"
#include "mls/messages.h"

#include "extended_mls_state.hpp"
#include "pki_client.hpp"

const mls::MessageOpts securedMessageOptions{ true, {}, 0 };

template<typename DeliveryServiceI>
class MaliciousClient
{
public:
    MaliciousClient(typename DeliveryServiceI::NetworkType & network,
        const mls::CipherSuite & suite, const mls::bytes_ns::bytes & id,
        const char * pkiAddress, int networkRtt)
        : initKey(mls::HPKEPrivateKey::generate(suite)),
            leafKey(mls::HPKEPrivateKey::generate(suite)),
            identityKey(mls::SignaturePrivateKey::generate(suite)),
            leafNode(suite, leafKey.public_key, identityKey.public_key,
                mls::Credential::basic(id), mls::Capabilities::create_default(),
                mls::Lifetime::create_default(), {}, identityKey),
            keyPackage(suite, initKey.public_key, leafNode, {}, identityKey),
            pkiAddress(pkiAddress), networkRtt(networkRtt),
            ds(*this, network), network(network)
    {
        auto keyPackageBytes = marshalToBytes(keyPackage);
        publishToPKI(pkiAddress, network.getAddr(),
            std::string{(const char *) id.data(), id.size()},
            keyPackageBytes);
    }

    void create(const mls::bytes_ns::bytes & groupId)
    {
        if(state)
            return;

        state = {{mls::State{groupId, keyPackage.cipher_suite, leafKey, identityKey, leafNode, {}}}};

        ds.init(&state.value());

        // TODO Initial credentials should be deleted (for Forward Secrecy)
    }

    void add(const std::string & ids)
    {
        // Split string to allow multiple adds (using ',')

        std::istringstream iss(ids);

        std::string id;
        while(std::getline(iss, id, ','))
        {
            PKIQueryResponse resp = queryPKI(pkiAddress, id);
            if(!resp.success)
                printf("User not found: %s\n", id.c_str());
            else
            {
                std::vector<uint8_t> packageBytes = {resp.preKey.content, resp.preKey.content + resp.preKey.size};

                mls::KeyPackage keyPackage;
                mls::tls::unmarshal(packageBytes, keyPackage);

                mls::MLSMessage proposal = state->add(keyPackage, securedMessageOptions);
                ds.broadcastProposalOrMessage(proposal);
            }
        }
    }

    void remove(const std::string & id)
    {
        std::vector<uint8_t> idBytes{id.begin(), id.end()};
        const auto proposal = state->remove(idBytes, securedMessageOptions);

        if(proposal)
        {
            ds.broadcastProposalOrMessage(proposal.value());
        }
    }

    void update()
    {
        const auto proposal = state->update(mls::HPKEPrivateKey::generate(state->cipher_suite()), {}, securedMessageOptions);

        ds.broadcastProposalOrMessage(proposal);
    }

    void message(const std::string & message)
    {
        std::vector<uint8_t> messageBytes{message.begin(), message.end()};
        const auto protectedMessage = state->protect({}, messageBytes, 0);

        ds.broadcastProposalOrMessage(protectedMessage);
    }

    void commit(bool addInvalidProposal = false)
    {
        if(!addInvalidProposal && !ds.canProposeCommit())
            return; // Too late to propose commit, don't make the effort to create one

        // Copy the state to avoid side-effects of removeSelfUpdate()
        ExtendedMLSState copyState = state.value();
        copyState.removeSelfUpdate();

        auto [commit, welcome, newState] = copyState.commit(copyState.freshSecret(), 
            mls::CommitOpts{ {}, true, true, {} }, securedMessageOptions, addInvalidProposal);

        m_proposedCommit = { commit };
        m_associatedState = { newState };
        
        ds.proposeCommit(commit, welcome);
    }

    ExtendedMLSState * handleWelcome(const mls::Welcome & welcome)
    {
        if(state)
            return nullptr;

        // TODO Welcome could be incorrect, handle it

        state = {{mls::State{initKey, leafKey, identityKey, keyPackage, welcome, std::nullopt, {}}}};

        printf("Joined group epoch %ld\n", state->epoch());
        fflush(stdout);

        // TODO Initial credentials should be deleted (for Forward Secrecy)

        return &state.value();
    }

    void handleProposalOrMessage(const mls::MLSMessage & message)
    {
        const auto appMessage = state->isValidApplicationMessage(message);
        if(appMessage)
        {
            auto [authData, messageBytes] = state->unprotect(message);
            printf("Message: %.*s\n", (int) messageBytes.size(), messageBytes.data());
            fflush(stdout);
        }
        else if(state->isValidProposal(message))
        {
            state->handle(message);

            if(!m_chooseCommitterTimeout)
            {
                m_chooseCommitterTimeout = network.registerTimeout(networkRtt, [this](const auto &)
                {
                    m_chooseCommitterTimeout = {};
                    auto committer = determineCommitter();
                    if(committer == state->index())
                        commit();
                    else
                    {
                        m_forceCommitTimeout = network.registerTimeout(networkRtt,
                        [this](const auto &)
                        {
                            m_forceCommitTimeout = {};
                            commit();
                        });
                    }
                });
            }
        }
    }

    ExtendedMLSState * handleCommit(const mls::MLSMessage & message)
    {
        if(state->isValidCommit(message))
        {
            auto [added, removed] = state->getCommitMembershipChanges(message);

            for(const auto & addedId : added)
                printf("Added: %.*s\n", (int) addedId.size(), addedId.data());

            for(const auto & removedId : removed)
                printf("Removed %.*s\n", (int) removedId.size(), removedId.data());

            if(m_proposedCommit
                && state->cipher_suite().ref(message) == state->cipher_suite().ref(m_proposedCommit.value()))
            {
                state = m_associatedState;
                printf("Local commit new epoch %ld id %u\n", state->epoch(),
                    MLS_UTIL_HASH_STATE(*state));
            }
            else
            {
                std::optional<mls::State> newState;

                try
                {
                    newState = newState = state->handle(message);
                }
                catch (std::exception &)
                {
                    fprintf(stderr, "Cannot process commit, most likely because we were removed. Exiting...");
                    exit(EXIT_FAILURE);
                }

                if(!newState)
                    sys_error("Invalid commit\n");

                state = ExtendedMLSState{newState.value()};
                printf("Remote commit new epoch %ld id %u\n", state->epoch(),
                    MLS_UTIL_HASH_STATE(*state));
            }
            fflush(stdout);
            
            // Clean the state
            m_proposedCommit = {};
            m_associatedState = {};
            if(m_chooseCommitterTimeout)
            {
                network.unregisterTimeout(m_chooseCommitterTimeout.value());
                m_chooseCommitterTimeout = {};
            }
            if(m_forceCommitTimeout)
            {
                network.unregisterTimeout(m_forceCommitTimeout.value());
                m_forceCommitTimeout = {};
            }

            return &state.value();
        }

        return nullptr;
    }

    const mls::KeyPackage & getKeyPackage() const
    {
        return keyPackage;
    }

    void runSelect(const std::function<bool(void)> & notifyIn)
    {
        network.runSelect(notifyIn);
    }

protected:
    // Based on the current proposals, determine the best member to commit
    mls::LeafIndex determineCommitter()
    {
        // Choose in priority a member who sent an Update proposal, and pick the committer
        //  randomly using the epoch number to keep it deterministic
        auto epochMod = state->epoch() % state->getMembersIdentity().size();

        auto proposalsIt = state->cachedProposals().begin();

        mls::LeafIndex bestIdx = proposalsIt->sender.value();
        auto bestDist = bestIdx.val +
            (bestIdx.val < epochMod ? state->getMembersIdentity().size() : 0) - epochMod;
        bool isBestUpdate = proposalsIt->proposal.proposal_type() == mls::ProposalType::update;
        ++proposalsIt;

        for(; proposalsIt != state->cachedProposals().end(); ++proposalsIt)
        {
            if(!isBestUpdate
                && proposalsIt->proposal.proposal_type() == mls::ProposalType::update)
            {
                isBestUpdate = true;
                bestIdx = proposalsIt->sender.value();
                bestDist = bestIdx.val +
                    (bestIdx.val < epochMod ? state->getMembersIdentity().size() : 0)
                    - epochMod;
            }
            else if(!isBestUpdate || (isBestUpdate
                && proposalsIt->proposal.proposal_type() == mls::ProposalType::update))
            {
                auto dist = proposalsIt->sender.value().val +
                    (bestIdx.val < epochMod ? state->getMembersIdentity().size() : 0) - epochMod;

                if(dist < bestDist)
                {
                    bestDist = dist;
                    bestIdx = proposalsIt->sender.value();
                }
            }
        }

        return bestIdx;
    }

private:
    mls::HPKEPrivateKey initKey, leafKey;
    mls::SignaturePrivateKey identityKey;
    mls::LeafNode leafNode;
    mls::KeyPackage keyPackage;

    const char * pkiAddress;
    const int networkRtt;

    DeliveryServiceI ds;
    typename DeliveryServiceI::NetworkType& network;

    std::optional<mls::MLSMessage> m_proposedCommit = {};
    std::optional<ExtendedMLSState> m_associatedState = {};

    std::optional<typename DeliveryServiceI::NetworkType::timeoutID>
        m_chooseCommitterTimeout = {}, m_forceCommitTimeout = {};

    std::optional<ExtendedMLSState> state;
};

#endif
