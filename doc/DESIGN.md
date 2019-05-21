# LF: Fully Decentralized Fully Replicated Key/Value Store

<img src="underconstruction.gif">

## Abstract

## Introduction

## Directed Acyclic Graph

## Blind Selectors and Queries

## Local Reputation Heuristics and Commentary

## Network Protocol

## Wharrgarbl Proof of Work Algorithm

<img src="wharrgarbl.jpg"><br>

**Wharrgarbl** is LF's proof of work function. It's based on an approach called [momentum hashing](doc/momentum.pdf) designed by Daniel Larimer that relies on a search for collisions in a hash function accelerated by the use of a memory cache to exploit the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem). The name comes from the above meme, which seemed relevant to something whose memory intensiveness grows with challenge difficulty.

The goal of Wharrgarbl is to resist significant acceleration using GPUs or ASICs. While this is less critical for a system like this than for a proof of work cryptocurrency, it still carries some importance as a countermeasure against flooding attacks against public unpermissioned LF deployments. A secondary goal is to be "architecturally fair" in the sense of avoiding algorithms or design choices that perform significantly better on e.g. X64 vs ARM64 or vice versa (assuming other things such as core speed being roughly equal).

Note that while Wharrgarbl is vastly accelerated by the use of a memory cache, it's still *possible* to run it on less memory. The collision search is accelerated by the memory cache, so smaller memory caches will make the search take a lot longer.

## FAQ

**Q:** Won't the LF data store grow without bound?
**A:** It will, but storage is very cheap and continues to fall in cost at near-exponential rates. Unlike conventional silicon electronic transistor densities and core frequencies we appear to be nowhere near any practical or physical limit for data storage density, meaning this "Moore's law" like reduction in storage cost is likely to continue for some time. The structure of LF records and the DAG are deliberately designed to allow for future optimizations such as partial nodes and local discarding of old data that could significantly mitigate the storage overhead of LF, but these aren't implemented yet.

**Q:** Why use a DAG ([directed acyclic graph](https://en.wikipedia.org/wiki/Directed_acyclic_graph)) and not a block chain?
**A:** A DAG has numerous interesting properties including superior scalability and straightforward continuity of operation under "split brain" (network split) conditions. It's also somewhat simpler to implement as records and the "chain" are the same thing and synchronization is a simple matter of crawling the DAG in reverse. The fact that LF is not a cryptocurrency means that there's no incentive for runaway proof of work or other high investment consensus weighting activities, removing much of the benefit of a singular block chain. In place of these we've chosen a multi-paradigm approach to consensus and collision resistance that permits developers to elect different policies as suit their applications and security needs.

**Q:** Why use any kind of chain? Why not just rumor mill replicate records?
**A:** A flat set of records with no linkages would provide no mechanism to ensure that a node has the latest copy of every record and no intrinsic temporal or relational structure to implement any kind of automatic conflict resolution. There are already numerous un-trustworthy distributed data storage technologies for P2P networks. We needed something with much stronger security guarantees both for public Internet use and for private projects with key customers.

**Q:** Why use NIST elliptic curves instead of ed25519?
**A:** (1) Owners can be full x509 certificates and can be part of a signature chain, and many/most x509 implementations (including the one in Go) don't support ed25519 and similar, and (2) several large ZeroTier customers want NIST or NSA certifiable cryptography. We will probably add ed25519 (EDDSA) owner support once Go's x509 implementation supports it. We are aware that there is some suspicion about the NIST curves, but having reviewed the literature we don't see any actual evidence to back it up. The US NSA and military continue to use these curves for top secret information and this would seem an unlikely behavior in the era of rampant leaks if a backdoor did exist. These curves are also quite old and have been the subject of significant cryptanalysis.

**Q:** Why isn't the code pure Go?
**A:** The core database is a major performance bottleneck. The part that handles weight propagation down the DAG is particularly sensitive and really wants to be as close to "native" as possible as it makes heavy use of memory mapped files and other very low level techniques. Our dependency on SQLite means that LF can't be pure Go anyway, and there are no comparable pure Go embeddable database solutions.
