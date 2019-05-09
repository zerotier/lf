# LF: Fully Decentralized Fully Replicated Key/Value Store

**A mad science project of [ZeroTier, Inc.](https://www.zerotier.com)**

## Introduction

LF (pronounced "aleph") is a fully decentralized fully replicated key/value store.

LF is intended to fill a role akin to the key/value store aspects of [etcd](https://github.com/etcd-io/etcd) or [consul](https://www.consul.io) but for fully decentralized systems that lack both a single point of failure and (in many cases) a single controlling entity. It's designed to store small infrequently changing bits of data like certificates, keys, identity information, DNS records, and other information critical to the operation of a system.

The design of LF is inspired by several different cryptocurrencies and other kinds of block chain or hash tree database systems. It's not a cryptocurrency but could in theory be used as the underlying data store for one. It was created to help [ZeroTier](https://www.zerotier.com/) fully decentralize its root server infrastructure and support decentralized controller models for ultra high reliability private networks.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept, and at one point a character calls it "the LF" because "aleph" is mis-heard as an acronym. We used LF because there's already an open source project called Aleph and because a two layer obscure literary reference is cool.

### Features and Benefits

 * Fully decentralized network with no required single points of control or failure.
 * Fully decentralized trust model permitting network operation between multiple parties with no existing trust relationship.
 * Fully replicated for fast predictable time queries against arbitrary keys and continued operation under partial or total network failure conditions.
 * Simple JSON API and nodes are easy to set up and operate.
 * Works "out of the box" with a default global network and default seed peers.
 * Network can be arbitrarily split with all nodes continuing to operate in full read/write mode. Re-synchronization on re-connection is automatic.
 * Multiple conflict resolution mechanisms exist: cumulative "weight" through proof of work (a proxy for time), elective node trust relationships, and elective certificate trust models. Users and node operators can choose which mechanism to use, balancing assurance against ease of use and degree of trust decentralization.
 * Supports composite multi-element keys and range queries.
 * The non-range-queryable "name" portion of record keys is cryptographically blinded, private, and authenticated, allowing information about records to be kept private and making intentional key-collision attacks harder.
 * Record values can be optionally encrypted with a masking key to keep data private. Combined with blind keys this makes fully private use possible even on global open networks.

### Limitations and Disadvantages

 * Only suitable for small data such as keys, certificates, names, IPs, etc.
 * Not generally suitable for frequently changing or dynamic data.
 * [CAP theorem](https://en.wikipedia.org/wiki/CAP_theorem) trade-off: availability and partition-tolerance. Data is eventually consistent and locks and transactions are not supported.
 * Some attention must be paid to trust, consensus, or record validity concerns when designing an application to ensure that it is not vulnerable to data set poisoning attacks.
 * Moderately high CPU, memory, and storage requirements for full nodes make LF unsuitable for very resource constrained devices.
 * Storage requirements grow over time and could become quite large, though storage costs are also decreasing over time and several space-saving optimizations aren't implemented yet.

## Building and Running

LF works on Linux and Mac systems. (FreeBSD may work too but hasn't been tried. Windows isn't supported yet.) It's mostly written in Go (1.11+) with some C for performance critical bits and is easy to build. The only external dependency is [sqlite](https://sqlite.org/) whose libraries and header files will need to be available. Since it contains parts written in C it can't easily be cross-compiled like pure Go, so you'll have to build on your native target.

If you have all that stuff, just type `make` and it should build.

## Usage

LF has three components: **full nodes** that store and forward all data, **proxies** that can do proof of work and encryption on behalf of clients (not implemented yet!), and a **command line `lf` client** for querying these things and locally generating records. The LF Go code can also be linked into applications to do the things the `lf` client does internally to them.

All of these things exist in the same `lf` binary that gets built when you type `make`.



## Internals

See [PURPLEPAPER.md](PURPLEPAPER.md) for details.

## Credits

(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/) 
Written by [Adam Ierymenko](http://adamierymenko.com/) 
Licensed under the [GNU GPLv3](LICENSE.txt)
