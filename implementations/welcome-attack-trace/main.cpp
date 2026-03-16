#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "extended_mls_state.hpp"
#include <mls/crypto.h>
#include <mls/messages.h>
#include <mls/state.h>

using namespace mls;

struct TraceMessage {
  std::string senderName;
  MLSMessage message;
  std::optional<Welcome> welcome;
};

struct Client {
  std::string name;
  HPKEPrivateKey initKey;
  HPKEPrivateKey leafKey;
  SignaturePrivateKey identityKey;
  LeafNode leafNode;
  KeyPackage keyPackage;
  std::optional<ExtendedMLSState> state;
  std::optional<State> nextState;

  Client(const std::string &n, CipherSuite suite)
      : name(n), initKey(HPKEPrivateKey::generate(suite)),
        leafKey(HPKEPrivateKey::generate(suite)),
        identityKey(SignaturePrivateKey::generate(suite)),
        leafNode(suite, leafKey.public_key, identityKey.public_key,
                 Credential::basic(bytes_ns::from_ascii(n)),
                 Capabilities::create_default(), Lifetime::create_default(), {},
                 identityKey),
        keyPackage(suite, initKey.public_key, leafNode, {}, identityKey) {}

  void createGroup(const std::string &groupId) {
    bytes_ns::bytes gid = bytes_ns::from_ascii(groupId);
    state = {{State{
        gid, keyPackage.cipher_suite, leafKey, identityKey, leafNode, {}}}};
    std::cout << name << " created group " << groupId << " (Epoch 0)"
              << std::endl;
  }

  MLSMessage add(const std::shared_ptr<Client> &target,
                 const MessageOpts &msgOpts) {
    return state->add(target->keyPackage, msgOpts);
  }

  MLSMessage update(const MessageOpts &msgOpts) {
    state->clearCachedUpdate(); // Technically this should be done after
                                // handling a commit, but here this ensures it
                                // never triggers an error
    return state->update(HPKEPrivateKey::generate(state->cipher_suite()), {},
                         msgOpts);
  }

  TraceMessage commit(const MessageOpts &msgOpts,
                      const CommitOpts &commitOpts = {{}, true, true, {}}) {
    // Follow the pattern in mls_client.hpp:
    // Copy the state to avoid side-effects of removeSelfUpdate() on the current
    // state, then remove any self-sent update proposals before committing, as
    // the commit itself will provide a new leaf key/path update.
    ExtendedMLSState copyState = *state;
    copyState.removeSelfUpdate();

    auto [c, w, s] = copyState.commit(copyState.freshSecret(), commitOpts, msgOpts);
    nextState = s;
    return {name, c, std::optional<Welcome>(w)};
  }

  void handleTraceMessage(const TraceMessage &tm) {
    if (!state) {
      if (tm.welcome) {
        try {
          state = {{State{initKey,
                          leafKey,
                          identityKey,
                          keyPackage,
                          *tm.welcome,
                          std::nullopt,
                          {}}}};
          std::cout << "  " << name << " joined group (Epoch " << state->epoch()
                    << ")" << std::endl;
        } catch (const std::exception &) {
          // If we fail here, it's likely because the Welcome message was not
          // intended for us (it contains no entry for our KeyPackage).
          // We stay silent to avoid noise if we are just an observer in the group list.
        }
      }
      return;
    }

    if (state->isValidProposal(tm.message)) {
      try {
        state->handle(tm.message);
        std::cout << "  " << name << " handled proposal from " << tm.senderName << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "  " << name << " failed to handle proposal from "
                  << tm.senderName << ": " << e.what() << std::endl;
      }
    } else if (state->isValidCommit(tm.message)) {
      if (tm.senderName == name && nextState) {
        state = ExtendedMLSState{*nextState};
        nextState.reset();
        std::cout << "  " << name << " applied own Commit (Epoch "
                  << state->epoch() << ")" << std::endl;
      } else {
        try {
          auto newState = state->handle(tm.message);
          if (newState) {
            state = ExtendedMLSState{*newState};
            std::cout << "  " << name << " processed Commit from "
                      << tm.senderName << " (Epoch " << state->epoch() << ")"
                      << std::endl;
          }
        } catch (const std::exception &e) {
          std::cerr << "  " << name << " failed to handle commit from "
                    << tm.senderName << ": " << e.what() << std::endl;
        }
      }
    } else {
       std::cout << "  " << name << " ignored message from " << tm.senderName << " (not valid proposal or commit for current state)" << std::endl;
    }
  }
};

void broadcast(const std::vector<std::shared_ptr<Client>> &clients,
               const TraceMessage &tm, const std::string &label = "") {
  std::cout << ">>> BROADCAST [" << tm.senderName << "]";
  if (!label.empty()) std::cout << " (" << label << ")";
  std::cout << std::endl;
  for (auto &client : clients) {
    client->handleTraceMessage(tm);
  }
}

void verifyConsistency(const std::vector<std::shared_ptr<Client>> &clients, bool expectInconsistent = false) {
  std::cout << "Verification:" << std::endl;
  std::optional<uint32_t> firstHash;
  bool consistent = true;
  for (const auto &client : clients) {
    if (client->state) {
      uint32_t hash = MLS_UTIL_HASH_STATE(*client->state);
      std::cout << "  " << client->name << " (Epoch " << client->state->epoch()
                << "): " << hash << std::endl;
      if (!firstHash)
        firstHash = hash;
      else if (*firstHash != hash)
        consistent = false;
    } else {
      std::cout << "  " << client->name << " (No State)" << std::endl;
      consistent = false;
    }
  }
  if (consistent)
    std::cout << "  SUCCESS: Consistent." << std::endl;
  else {
    if (expectInconsistent) {
      std::cout << "  INFO: Inconsistent (as expected for this scenario)." << std::endl;
    } else {
      std::cerr << "  FAILURE: Inconsistent!" << std::endl;
      exit(1);
    }
  }
}

void honest_scenario() {
  std::cout << "################################################" << std::endl;
  std::cout << "# RUNNING HONEST SCENARIO                      #" << std::endl;
  std::cout << "################################################" << std::endl;

  CipherSuite suite(CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519);
  MessageOpts msgOpts{true, {}, 0};

  auto alice = std::make_shared<Client>("Alice", suite);
  auto bob = std::make_shared<Client>("Bob", suite);
  auto charlie = std::make_shared<Client>("Charlie", suite);
  auto dave = std::make_shared<Client>("Dave", suite);
  auto eve = std::make_shared<Client>("Eve", suite);

  // Group of 4 initially
  std::vector<std::shared_ptr<Client>> currentMembers = {alice, bob, charlie,
                                                         dave};
  // Eve will be added later
  std::vector<std::shared_ptr<Client>> allPossibleClients = {alice, bob,
                                                             charlie, dave, eve};

  std::cout << "--- STEP 1: INITIAL JOIN (Alice adds Bob, Charlie, Dave) ---"
            << std::endl;
  alice->createGroup("trace-group");

  std::cout << "Alice prepares Add proposals for Bob, Charlie, and Dave"
            << std::endl;
  auto pAddB = alice->add(bob, msgOpts);
  auto pAddC = alice->add(charlie, msgOpts);
  auto pAddD = alice->add(dave, msgOpts);

  std::cout << "Broadcasting Add proposals to the current group (Alice)"
            << std::endl;
  broadcast(currentMembers, {"Alice", pAddB, std::nullopt}, "Add Bob");
  broadcast(currentMembers, {"Alice", pAddC, std::nullopt}, "Add Charlie");
  broadcast(currentMembers, {"Alice", pAddD, std::nullopt}, "Add Dave");

  std::cout << "Alice commits the proposals and generates Welcome messages..."
            << std::endl;
  auto joinCommit = alice->commit(msgOpts);

  std::cout << "Broadcasting Commit + Welcome to all participants" << std::endl;
  broadcast(allPossibleClients, joinCommit, "Commit Initial Join");
  verifyConsistency(currentMembers);

  std::cout << "\n--- STEP 2: SESSION 1 (Alice & Bob update, Charlie adds Eve, "
               "Bob commits) ---"
            << std::endl;

  auto pUpAlice = alice->update(msgOpts);
  broadcast(currentMembers, {"Alice", pUpAlice, std::nullopt}, "Update Alice");

  auto pUpBob = bob->update(msgOpts);
  broadcast(currentMembers, {"Bob", pUpBob, std::nullopt}, "Update Bob");

  std::cout << "Eve provides her KeyPackage to Charlie" << std::endl;
  std::cout << "Charlie generates Add proposal for Eve's KeyPackage"
            << std::endl;
  auto pAddEve = charlie->add(eve, msgOpts);

  std::cout << "Broadcasting Eve's Add proposal to the group" << std::endl;
  broadcast(currentMembers, {"Charlie", pAddEve, std::nullopt}, "Add Eve");

  std::cout << "Bob commits and generates the Welcome message for Eve"
            << std::endl;
  auto session1Commit = bob->commit(msgOpts);

  std::cout << "Broadcasting: Commit (to members) and Welcome (to Eve)"
            << std::endl;
  broadcast(allPossibleClients, session1Commit, "Commit Session 1");

  // Now Eve is a member
  std::cout << "Eve has processed the Welcome and is now part of the group."
            << std::endl;
  currentMembers.push_back(eve);
  verifyConsistency(currentMembers);

  std::cout
      << "\n--- STEP 3: SESSION 2 (Alice, Bob, Eve update, Bob commits) ---"
      << std::endl;

  auto pUpAlice2 = alice->update(msgOpts);
  broadcast(currentMembers, {"Alice", pUpAlice2, std::nullopt}, "Update Alice");

  auto pUpBob2 = bob->update(msgOpts);
  broadcast(currentMembers, {"Bob", pUpBob2, std::nullopt}, "Update Bob");

  auto pUpEve2 = eve->update(msgOpts);
  broadcast(currentMembers, {"Eve", pUpEve2, std::nullopt}, "Update Eve");

  std::cout << "Bob commits all updates..." << std::endl;
  auto session2Commit = bob->commit(msgOpts);
  broadcast(currentMembers, session2Commit, "Commit Session 2");
  verifyConsistency(currentMembers);

  std::cout << "\nHonest trace finished successfully." << std::endl;
}

void attack_scenario() {
  std::cout << "\n################################################" << std::endl;
  std::cout << "# RUNNING ATTACK SCENARIO                      #" << std::endl;
  std::cout << "################################################" << std::endl;

  CipherSuite suite(CipherSuite::ID::X25519_AES128GCM_SHA256_Ed25519);
  MessageOpts msgOpts{true, {}, 0};

  auto alice = std::make_shared<Client>("Alice", suite);
  auto bob = std::make_shared<Client>("Bob", suite);
  auto charlie = std::make_shared<Client>("Charlie", suite);
  auto dave = std::make_shared<Client>("Dave", suite);
  auto eve = std::make_shared<Client>("Eve", suite);

  std::vector<std::shared_ptr<Client>> currentMembers = {alice, bob, charlie,
                                                         dave};
  std::vector<std::shared_ptr<Client>> allPossibleClients = {alice, bob,
                                                             charlie, dave, eve};

  std::cout << "--- STEP 1: INITIAL JOIN (Alice adds Bob, Charlie, Dave) ---"
            << std::endl;
  alice->createGroup("attack-group");
  broadcast(currentMembers, {"Alice", alice->add(bob, msgOpts), std::nullopt}, "Add Bob");
  broadcast(currentMembers, {"Alice", alice->add(charlie, msgOpts), std::nullopt}, "Add Charlie");
  broadcast(currentMembers, {"Alice", alice->add(dave, msgOpts), std::nullopt}, "Add Dave");
  broadcast(allPossibleClients, alice->commit(msgOpts), "Commit Initial Join");
  verifyConsistency(currentMembers);

  std::cout << "\n--- STEP 2: ATTACK PREPARATION (Bob generates real commit and welcome) ---" << std::endl;
  
  // Proposals for Step 2
  broadcast(currentMembers, {"Alice", alice->update(msgOpts), std::nullopt}, "Update Alice");
  broadcast(currentMembers, {"Charlie", charlie->add(eve, msgOpts), std::nullopt}, "Add Eve");
  
  // Bob prepares a real commit for the group (Epoch 1 -> 2)
  auto realCommit = bob->commit(msgOpts);

  std::cout << "\n--- STEP 3: THE SPLIT (Broadcast Decoy Commit + Real Welcome) ---" << std::endl;
  
  // Bob Attacker prepares a decoy group state to distract the group
  auto bobDecoy = std::make_shared<Client>("Bob (Attacker)", suite);
  bobDecoy->createGroup("attack-group");
  bobDecoy->commit(msgOpts); // Advance to Epoch 1
  bobDecoy->update(msgOpts);
  auto decoyCommit = bobDecoy->commit(msgOpts); // Decoy Commit for Epoch 2
  
  std::cout << "Broadcasting: [Decoy Commit] to Group and [Real Welcome] to Eve" << std::endl;
  TraceMessage splitMsg = {"Bob (Attacker)", decoyCommit.message, realCommit.welcome};
  broadcast(allPossibleClients, splitMsg, "Split Delivery: Decoy Commit + Real Welcome");

  std::cout << "\nIntermediate Check (EXPECT DESYNC):" << std::endl;
  verifyConsistency({alice, bob, charlie, dave});
  if (eve->state) {
      std::cout << "  Eve (Epoch " << eve->state->epoch() << "): " << MLS_UTIL_HASH_STATE(*eve->state) << std::endl;
  }

  std::cout << "\n--- STEP 4: PARALLEL STATE (Bob & Eve handle malicious proposal) ---" << std::endl;
  // Bob MUST reach Epoch 2 in his real state to send malicious Epoch 2 proposals
  bob->handleTraceMessage(realCommit); 
  
  auto malory = std::make_shared<Client>("Malory", suite);
  std::cout << "Bob sends a malicious ADD proposal for 'Malory' in Epoch 2" << std::endl;
  auto pMalicious = bob->add(malory, msgOpts);
  // We explicitly only send it to Bob and Eve (others are stuck in Epoch 1 or reach Epoch 2 without this proposal)
  broadcast(allPossibleClients, {"Bob", pMalicious, std::nullopt}, "Add Malory (Malicious)");

  // Bob generates the 'attack commit' (Epoch 2 -> 3) which includes Malory's Add
  TraceMessage attackCommit;
  try {
      ExtendedMLSState copyState = *bob->state;
      // We don't remove self-update because it's Malory's Add, not Bob's update
      auto [commit3, welcome3, newState3] = copyState.commit(copyState.freshSecret(), 
          std::optional<CommitOpts>({{}, true, true, {}}), msgOpts);
      
      bob->nextState = newState3;
      attackCommit = {"Bob", commit3, std::nullopt};
      std::cout << "Bob generated the attack commit for Epoch 3 (including Malory)" << std::endl;
  } catch (const std::exception &e) {
      std::cerr << "  Bob unexpectedly failed to generate the attack commit: " << e.what() << std::endl;
      return;
  }

  std::cout << "\n--- STEP 5: RESYNC THE REST (Reveal Real Commit) ---" << std::endl;
  std::cout << "Bob sends the Real Commit to everyone (others reach Epoch 2)" << std::endl;
  broadcast(allPossibleClients, realCommit, "Reveal Real Commit");

  std::cout << "\nIntermediate Check (SHOULD BE CONSISTENT AT EPOCH 2):" << std::endl;
  verifyConsistency(allPossibleClients);

  std::cout << "\n--- STEP 6: THE BREAKDOWN (Broadcast Attack Commit) ---" << std::endl;
  std::cout << "Bob sends the Attack Commit (Epoch 3). Alice/Others should fail because they missed Malory's Add." << std::endl;
  currentMembers.push_back(eve);
  broadcast(currentMembers, attackCommit, "Attack Commit (including Malory)");

  std::cout << "\nFinal Results (EXPECTING INCONSISTENCY/FAILURE):" << std::endl;
  verifyConsistency(currentMembers, true);

  std::cout << "\nAttack scenario finished." << std::endl;
}

int main() {
  honest_scenario();
  attack_scenario();
  return 0;
}
