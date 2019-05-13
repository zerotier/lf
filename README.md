# LF: Fully Decentralized Fully Replicated Key/Value Store

*(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/)* 
*Licensed under the [GNU GPLv3](LICENSE.txt)*

## Introduction

LF (pronounced "aleph") is a fully decentralized fully replicated key/value store.

LF is intended to fill a role akin to the key/value store aspects of [etcd](https://github.com/etcd-io/etcd) or [consul](https://www.consul.io) but for fully decentralized systems that lack both a single point of failure and (in many cases) a single controlling entity. It's designed to store things like public keys, certificates, names, DNS records, and other small but important bits of data required for systems to bootstrap and operate.

In most fully decentralized systems this role is filled by a distributed data structure like [Kademlia](https://en.wikipedia.org/wiki/Kademlia) or another distributed hash table (DHT). DHTs are typically slow, depend on network reliability for full data set reachability, and are vulnerable to a variety of denial of service and other attacks. LF provides an alternative that trades much higher local storage overhead for fast queries and continuous availability.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept, and at one point a character calls it "the LF" because "aleph" is mis-heard as an acronym. We used LF because there's already an open source project called Aleph and because a two layer obscure literary reference is cool.

### Features and Benefits

 * Fully decentralized network with no mandatory single points of control or failure.
 * Flexible trust model allowing application authors to decide between different conflict resolution mechanisms including cumulative record weight (proof of work), certificates (not implemented yet, coming soon!), or none at all.
 * Fast nearline queries against all data and continuous availablility even during partial or total network failures.
 * A simple JSON API and command line client make LF easy to use. Full nodes are easy to set up and operate.
 * Supports multi-element keys and range queries over an optional 64-bit integer ordinal associated with each key.
 * Keys are encrypted and authenticated. Queries can be performed without revealing keys or ordinals.

### Limitations and Disadvantages

 * Only suitable for small records.
 * Not generally suitable for frequently changing or dynamic data.
 * [CAP theorem](https://en.wikipedia.org/wiki/CAP_theorem) trade-off: availability and partition-tolerance. Data is eventually consistent and locks and transactions are not supported.
 * Moderately high CPU, memory, and storage requirements for full nodes make LF unsuitable for very resource constrained devices.
 * Full node storage requirements grow over time (like a block chain or similar system) and could become quite large, though storage costs are also decreasing over time.

## Building and Running

LF works on Linux and Mac systems. (FreeBSD may work too but hasn't been tried. Windows isn't supported yet.) It's mostly written in Go (1.11+) with some C for performance critical bits and is easy to build. The only external dependency is [sqlite](https://sqlite.org/) whose libraries and header files will need to be available. Since it contains parts written in C it can't easily be cross-compiled like pure Go, so you'll have to build on your native target.

If you have all that stuff, just type `make` and it should build.

## Usage

LF has three components: **full nodes** that store and forward all data, **proxies** that can do proof of work and encryption on behalf of clients (not implemented yet!), and a **command line `lf` client** for querying these things and locally generating records. The LF Go code can also be linked into applications to do the things the `lf` client does internally to them.

All of these things exist in the same `lf` binary that gets built when you type `make`.



## Internals

See [DESIGN.md](doc/DESIGN.md) for details.
