# LF: Fully Decentralized Fully Replicated Key/Value Store

**Design** ~~white~~**purplepaper.** (Purple because this is not a cryptocurrency scam.)

<img src="doc/underconstruction.gif">

## Abstract

## Introduction

## Directed Acyclic Graph

## Blind Selectors and Queries

## Local Reputation Heuristics and Commentary

## Network Protocol

## Roll Your Own Cryptography (-ish)

### Wharrgarbl

<img src="doc/wharrgarbl.jpg"><br>

**Wharrgarbl** is LF's proof of work function. It's based on an approach called [momentum hashing](doc/momentum.pdf) designed by Daniel Larimer that relies on a search for collisions in a hash function accelerated by the use of a memory cache to exploit the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem). The name comes from the above meme, which seemed relevant to something whose memory intensiveness grows with challenge difficulty.

The goal of Wharrgarbl is to resist significant acceleration using GPUs or ASICs. While this is less critical for a system like this than for a proof of work cryptocurrency, it still carries some importance as a countermeasure against flooding attacks against public unpermissioned LF deployments. A secondary goal is to be "architecturally fair" in the sense of avoiding algorithms or design choices that perform significantly better on e.g. X64 vs ARM64 or vice versa (assuming other things such as core speed being roughly equal).

Note that while Wharrgarbl is vastly accelerated by the use of a memory cache, it's still *possible* to run it on less memory. The collision search is accelerated by the memory cache, so smaller memory caches will make the search take a lot longer.

### Shandwich256

Changing the hash algorithm for record hashes would be very painful and annoying. To avoid ever having to do this, we combined SHA-256 with SHA3-256 using AES as a combining function to yield a somewhat slower but very future-proof hash. It's only used for record identity hashes with SHA3-256 being used in most other places.

The code for this [can be seen in shandwich.go](pkg/lf/shandwich.go).

The algorithm is:

 1. Compute SHA256 of input.
 2. Compute SHA3-256 of input.
 3. Use SHA3-256 hash as a 256-bit key to initialize AES-256.
 4. Generate final hash by encrypting SHA256 hash in ECB mode as two AES blocks.

This yields a 256-bit hash that should remain very strong even if SHA2 or SHA3 are significantly broken at some point in the future.
