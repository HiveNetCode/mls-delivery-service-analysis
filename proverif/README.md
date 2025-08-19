
# ProVerif analysis

Here we provide ProVerif scripts, as well as their output, showing the evidence of an attack using invalid proposal reference, then later proving the effectiveness of our solution to prevent such attacks.

## Structure

* `mls.pvl`: This library file contains out model of the MLS Protocol (RFC 9420).
* `test_attack.pv`: This script contains the model of the Delivery Service, as well as security properties and tests scenarios. These scenarios showcase the possibility of an attack using invalid proposal reference to break the Epoch-Content Consistency property.
* `test_solution.pv`: The script improves the previous one with the presented solution, and prove its effectiveness against invalid proposal reference attacks.

## Usage

Both scripts can be run using (ProVerif)[https://bblanche.gitlabpages.inria.fr/proverif/] automatic prover, using the following commands:

```bash
proverif -lib mls.pvl test_attack.pv
proverif -lib mls.pvl test_solution.pv
```

## Output

For convenience, we also include the ProVerif output for both scenarios:

* `test_attack_output.txt` contains the output for the attack scenario.
* `test_solution_output.txt.gz` contains the output for the scenario proving the solution. We compressed this output using `gzip` as the uncompressed file would be too large. It can be decompressed using `gunzip` command or equivalent.

## Output explanation

### Attack case

In the case where the attack is possible, we can see in the end of the output fails to prove the Epoch-Content Consistency:

```pv
- Query event(receiveCommitProposalReference(id_7,commit_8,ref_8)) ==> event(receivedProposal(id_7,ref_8)) is false.
```

Additionally, ProVerif can give such a clear as it was able to find an attack trace invalidating the property. In details, we can see line `18428` that the property was invalidated when encountering the following proposals' list:

```
listProposals(a_5,a_6,subIndexedProposals(proposalOrRefWithIndex(a_7,wrapProposalRef(a_8)))),a_9,a_10)
```

We can see that this list contains a proposal reference `a_8`. However, `a_8` does not refer to anything. Hence, what we call an invalid reference.

### Solution case

In the case, when can mostly observe the end of the ProVerif output, summarizing which property were validated by ProVerif.

The complete summary is provided below:

```
--------------------------------------------------------------
Verification summary:

Query(ies):
 - Query not event(receivedProposal(id_7,ref_24)) is false.
 - Query not event(receiveCommitProposalReference(id_7,commit_9,ref_24)) cannot be proved.
 - Query not (event(receivedProposal(id_7,ref_24)) && event(receiveCommitProposalReference(id_7,commit_9,ref_24))) cannot be proved.
 - Query not event(acceptCommit(ep_39,id_7,commit_9)) is false.
 - Query event(acceptCommit(ep_39,id_7,commit_9)) && event(receiveCommitProposalReference(id',commit_9,ref_24)) ==> event(receivedProposal(id',ref_24)) is true.
Associated restriction(s):
 - Restriction event(addedLeaf(tid_16,idx_30,lf_40)) && event(addedLeaf(tid_16,idx_30,lf')) ==> lf_40 = lf' in process 1.
 - Restriction event(createdCommit(ep_39,id_7,m)) && event(createdCommit(ep_39,id_7,m')) ==> m = m' in process 1.
 - Restriction event(clientWillProcessCommit(id_7,cm)) && event(happenedBefore(pm,cm)) ==> event(clientProcessedProposal(id_7,pm)) in process 1.
 - Restriction event(createdCommit(ep_39,id_7,commit_9)) && event(clientWillProcessCommit(id',commit_9)) ==> id_7 ≠ id' in process 1.
 - Restriction event(acceptCommit(ep_39,id_7,m)) && event(acceptCommit(ep_39,id_7,m')) ==> m = m' in process 1.
Associated lemma(s):
 - Lemma event(clientProcessedProposal(id_7,wrapPrivateMessage(privateMessage(ep_39,CT_Proposal,appAuthData_20,HPKEEncrypt(senderKey,pair(lbl2,ctx2),createSenderData(idx_30)),HPKEEncrypt(pubKey_26,pair(lbl_105,ctx_81),privateMessageContent(proposalAsContent(proposal_21),authData_30)))))) ==> event(receivedProposal(id_7,ReferenceToProposal(authenticatedContent(framedContent(ep_39,idx_30,appAuthData_20,proposalAsContent(proposal_21)),authData_30)))) is true in process 1.
 - Lemma event(receiveCommitProposalReference(id_7,commit_9,ref_24)) ==> event(receivedProposal(id_7,ref_24)) is true in process 1.

--------------------------------------------------------------
```

First, we can see that most of our reachability tests succeeded, meaning that in a scenario honest clients can actually receive a proposal message, as well as accept a commit:

```
Query(ies):
 - Query not event(receivedProposal(id_7,ref_24)) is false.
 - Query not event(acceptCommit(ep_39,id_7,commit_9)) is false.
```

However, ProVerif cannot find a clear trace on clients receiving a proposal reference. But, as we already validated that client can accept commits, when known that they can actually receive proposal references as they are including in commits:

```
 - Query not event(receiveCommitProposalReference(id_7,commit_9,ref_24)) cannot be proved.
 - Query not (event(receivedProposal(id_7,ref_24)) && event(receiveCommitProposalReference(id_7,commit_9,ref_24))) cannot be proved.
```

Then, we see that ProVerif validates the Epoch-Content Consistency, here classified as a lemma, as we want ProVerif to take advantage of this result in the rest of the analysis:

```
 - Lemma event(receiveCommitProposalReference(id_7,commit_9,ref_24)) ==> event(receivedProposal(id_7,ref_24)) is true in process 1.
```

Finally, we can see that ProVerif also validates our intermediate property used to prove the Epoch-Agreement property:

```
 - Query event(acceptCommit(ep_39,id_7,commit_9)) && event(receiveCommitProposalReference(id',commit_9,ref_24)) ==> event(receivedProposal(id',ref_24)) is true.
```
