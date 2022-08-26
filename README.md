# Zero Knowledge Tools for Consumer Apps

## Introduction
This repository contains a collection libraries and tools meant to help developers 
add cryptographic capabilities to their applications in a way that preserves the privacy
of the end user.

## Overview
Many excellent cryptography libraries exist, but it is often hard to employ them in a secure 
manner without significant knowledge of the mathematics and security considerations involved.

This repository implements a set common cryptography use-cases that are commonly used in modern
consumer facing applications which can be used to implement strong privacy for end users
of applications. These applications will include:
- Range proofs allowing users to prove values lie within specific ranges to each other without revealing the underlying values
- Proof of authenticity, authorship & ownership of documents

This project is in its infancy and is not yet ready for production use and will likely be split
into smaller libraries in the future. 

Another aim of this repository is to help engineers without robust experience in cryptography
understand how to apply it within their applications. Therefore Robust examples and examples explaining underlying cryptographic
context however will be included as each piece of functionality is developed in order facilitate
understanding of the underlying concepts and encourage their correct application.

