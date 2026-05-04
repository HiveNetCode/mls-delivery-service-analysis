# Implementations of centralized Delivery Service and MLS compatible clients

This folder contains all Proofs-of-concept associated to our security analysis of a centralized MLS Delivery Service, based on the open-source implementation [MLS++](https://github.com/cisco/mlspp).

## Structure

Dependencies:

* `mlspp/`: (created at build) copy of the [MLS++](https://github.com/cisco/mlspp) open-source implementation of MLS, cloned from Github at commit `92aaa4134fa45ec39957a7c81a342401fba7feb2` (Date: `Mon Apr 13 15:29:45 2026 -0400`).

Utilities:

* `common/`: contains code shared between multiple of our POCs.
* `simplified-pki/`: implements a simplified PKI needed for member to store their Key Packages

Implementations:

* `central-delivery-service/`: contains our implementation of the central server for the Delivery Service.
* `centralized-client/`: contains our implement of an MLS client in the context of the single-tier Delivery Service, this client directly forward messages to MLS layer.
* `mlspp-attacker/`: (created at build) contains a modified version the MLS++ implementations that allows to create invalid commit containing invalid proposal references. This modified version is created by applying the patch `mlspp-invalid-proposal-ref.patch` on a copy of `mlspp/`.
* `attacker/`: contains a Proof-of-concept of an attacker that can emit invalid commits using invalid proposal reference.
* `ds-aware-client/`: implements a client that follows the 2-tier Delivery Service and includes a validation layer. This client is not affected by the case of invalid proposal references and stays in a coherent state with all clients implementing the same solution.

## Build

The project requires basic C++ compilation tools, such as `g++` or equivalent, and automated build tools: `git`, `make` and `cmake`.

First, one should install `mls++` dependencies: `openssl` and `nlohmann-json`.

Then, all subprojects can be directly built using the main Makefile and the command `make`.

The resulting executables will be placed in `bin/`.

## Usage

The PKI and Delivery Service can be started directly with the following commands:

```bash
bin/pki
```

and

```bash
bin/delivery_service
```

Then, all the client (`centralized_client`, `attacker`, and `ds_aware_client`) takes the same parameters:

```bash
bin/centralized_client <name> <pki-addr> <delivery-service-addr> <network-rtt>
```

The parameters are the following:

* `<name>` is the name associated with the client. The client will use this name to register with the PKI. Then, other client will use this name as well to invite this member to a group.
* `<pki-addr>` is the IP address of the PKI. If running on the same machine, I can just use `127.0.0.1`.
* `<delivery-service-addr>` is the IP address of the Delivery Service. If running on the same machine, I can just use `127.0.0.1`.
* `<network-rtt>` is an estimation of the average network round-trip time of messages. This helps member to decide when to commit newly received proposals. This parameter does not affect the study if all members use the same value. Therefore, an acceptable value can be `300` for 300ms.

Then, the client can be controlled using the following commands:

* `create`: allows a first member to create an initial group.
* `message <message>`: allows to send an MLS encrypted text message to all the members of the group. In practice this can be used to prove that members have a coherent state, thus can communicate with each other.
* `add <name>`: allows a group member to invite another member to the group.
* `update`: allows a member to issue an update of its encryption keys.
* `remove <name>`: allows a member to remove another group member.

The last 3 operations actually issues proposals. Then, after a short propagation delay, the client will automatically commit them. In the current setting where clients are operated by a single human and not script, there likely won't be more than one proposal per commit, as the proposal will be committed faster than the time needed for the human to enter the command to issue another operation. Similarly, the client sending the proposal will likely be the one committing this proposal as well, as most likely there won't be any concurrent proposals.

Additionally, the attacker client includes another command `invalid-commit` allowing him to send a commit containing invalid proposal reference.

## Scenarios

Here we detail, and transcribe the two executions related the paper: the case where an attacker manages to alter the normal function of another client in the group, and the case where clients follow the 2-tier Delivery Service architecture and therefore reject the commit with an invalid proposal reference.

These scenarios can be executed either manually, or using the `run_scenarios.sh` script that does it automatically.

### Attack case

We first start the PKI and the Delivery Service, then we start a normal client, in charge of creating a group and inviting an attacker.

```
# bin/centralized_client client1 127.0.0.1 127.0.0.1 500
> create
> add client-attacker
Added: client-attacker
Local commit new epoch 1 id 3827465116
```

Then, the attacker previously started correctly joins the group:

```
# bin/attacker client-attacker 127.0.0.1 127.0.0.1 500
Joined group epoch 1
```

The attacker can then issue an invalid commit with the corresponding command:

```
> invalid-commit
Local commit new epoch 2 id 3236357022
```

We can then see the behavior of the normal client, who gets terminated as the MLS++ implementation did not handle the case of possibly invalid proposal reference:

```
terminate called after throwing an instance of 'std::runtime_error'
  what():  bad_optional_access
zsh: IOT instruction (core dumped)  bin/centralized_client client1 127.0.0.1 127.0.0.1 500
```

### Scenario with improved clients

We first start the PKI and the Delivery Service, then we start a client that creates a group, invite another client, and finally invites the attacker.

```
# bin/ds-aware-client client1 127.0.0.1 127.0.0.1 500
> create
> add client2
Added: client2
Local commit new epoch 1 id 3848337622
> add client-attacker
Added: client-attacker
Local commit new epoch 2 id 3012602262
```

We can see that the second client gets invited into the group, and then later correctly receive the commit that adds the attacker into the group:

```
# bin/ds-aware-client client2 127.0.0.1 127.0.0.1 500
Joined group epoch 1
Added: client-attacker
Remote commit new epoch 2 id 3012602262
```

Similarly, the attacker correctly joins the group:

```
# bin/attacker client-attacker 127.0.0.1 127.0.0.1 500
Joined group epoch 2
```

Then, the attacker try to issue a commit with invalid proposal reference, with the specific command:

```
> invalid-commit
Local commit new epoch 3 id 67955128
```

We can see that, as wanted, both improved clients ignore this commit as they detect the invalid reference. This can be seen as they both display the following message:

```
Ignoring commit with missing proposal(s)
```

Finally, we can verify that both clients still function correctly, by first sending an update that gets committed later, and then sending an MLS Message:

Client 1 issues an update, that gets committed, then send a message:

```
> update
Local commit new epoch 3 id 181247607
> message testOK
Message: testOK
```

Client 2 correctly receives and process the valid commit, and receives the message:

```
Remote commit new epoch 3 id 181247607
Message: testOK
```
