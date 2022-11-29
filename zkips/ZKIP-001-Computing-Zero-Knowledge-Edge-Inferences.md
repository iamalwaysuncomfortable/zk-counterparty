# ZKIP 001 - ZK-Edge - Zero-Knowledge Computation & Sharing of Edge Inferences for Use in Decision Functions

# Summary

ZK-Edge proposes a protocol for creation of machine learning inferences that can be shared between parties which allow 
both parties to make decisions based on the inferences without revealing the content of the inferences or data used to
generate them.

The protocol describes how parties using discriminative machine learning functions of the form `I = f(Y|X)` to generate
inferences `I` can hide the content of the inferences through hiding functions `h(I)` and construct proofs about the
content of those inferences `p(h(I))` which counterparties can use within decision logic.

The protocol is designed to be portable wherein the counterparties are running it on both ends and able to transmit
encrypted data to each other on any platform.

# Motivation

When machine learning is performed within an application in a web browser or mobile device, there is little 
expectation or guarantee of privacy.  Any data the user generates can often be assumed to collected and used
to make an inference about the user, wherein the inference itself becomes identifying metadata about the user
that is often sold without their explicit consent beyond agreeing to platform terms of service.

However, the usefulness of inferences in creating desirable user experiences has arguably been shown.
So it is optimal to not have a binary choice between privacy and utility and motivates the creation
of a system which can provide both.

## Prior Art

Current efforts exist to create private machine learning, but to date many are in research phases and there is a lack of
easily usable protocol implementations that allow data protection. Many focus on being able to train models homomorphically
but no protocols for end-usage of algorithms. Thus this protocol is focused on enabling easy application-level privacy
protection within machine learning.

# Protocol Overview

ZK-Edge assumes two parties Alice and Bob who are both capable using inference function `{x : I(x) = f(y | x) }` that takes private input data `x` to generate an inference `I`. 

They are also capable of  using the inference `I` and associated data `AD` to generate a proof set `P = { (x, AD) : P1(I, AD), .., PN(I, AD) }` that proves desired statements `{S1, .., SN}` about that data and sending those to each other. The proof should be structured such that neither Bob or any other party who obtains the proof gains information about the inference or data inputs to the inference function. The proofs `P` are then used to do verification operations on the proofs which can also intake potential decision data `[d1..dN]` into a verification function `V(P, [d1..dN]) -> R`. The result of the verification function `R` can then be used as inputs Bob's program `D` to make decisions.

This process is shown graphically below.

```mermaid
flowchart LR
    subgraph Alice
    A[Generate Data]-->|data: x|B[\"Inference: I(x) = f(y| x)"\]
    B -->|data: I|C[\"Proofs: P(I, AD)"\]
    end
    subgraph Bob
    C -->|wire: P| D[\"V(P)"\]
    D -->|R|E[\"Decision: D(R)"\]
    end
```


Naturally the protocol will need to include verification that a correct statement was run, and may include previously published proof data. 

```mermaid
flowchart TB
    subgraph Alice
    A[Generate Data]-->|data: x|B[\"Inference: I(x) = f(y| x)"\]
    B -->|data: I|C[\"Proofs: P(I, AD)"\]
    end
    subgraph Bob
    C -->|wire-data: P| D[\"V(P)"\]
    D -->|R|E[\"Decision: D(R)"\]
    F[Decision Data] --> H[Blinding Function]
    G[Challenge Data] --> |wire-data: challenge|B
    H --> |wire-data: d-blinded|C
    G --> |wire-data: challenge|C
    end
```

# Protocol Goals

## Privacy Goals

It is assumed that both Alice and Bob have the following data they don't want to reveal to other parties:
  * Sensitive data `x` that serves as inputs to inference functions `I(x)`
  * Derived inferences `I` which by definition are statistics about their data
  * Decision parameters `d` which reveal decision preferences

The following privacy goals are thus established based on this information sensitivity:

1. **Sensitive Shouldn't Leak:** Ensure all sensitive data `x`, inferences `I` and decision parameters `d` are never directly exposed (for example, being sent over the wire)

2. **Encrypted Secrets Reveal No Information:** Collection of encrypted versions of `E(x)`, `E(I)` and `E(d)` by a counterparty or any third party do not reveal any data about these secrets

3. **Proofs Should Not Invadvertently Leak Secrets:** Secrets are not discoverable over multiple proofs (necessitating appropriate blinding factors)
   
4. **Public Proof Statements Should't Lead to Reconstruction of Original Data:** It should be impossible to gain significant information about the original data through Public or semi-public proof statements 

## Non-Goals 

1. **Statements can be public:** Statements are not meant to be hidden and can be published publicly or shared in cleartext over the while
   
2. **Proved Statements can be Statistics:** The protocol is meant to protect mining of data. It does not however prevent the results of what's proved from becoming a statistic itself. It is left to the protocol implementors to decide how much what data public statements being proved reveal
   
3. **Not Fully Homomorphic ML:** The protocol posits that the machine learning functions and data inputs `f(y|x)` themselves are not required to be encrypted so long as they do not leave an environment trusted by the protocol user. This does not **prevent** one from using a fully homomorphic encryption scheme with this protocol however.
