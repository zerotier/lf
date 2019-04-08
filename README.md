# LF: A Decentralized Fully Replicated Key/Value Store

## Introduction

LF (pronounced like "aleph") is a distributed and decentralized key/value store where every node stores a current copy of all data.

The main advantages of LF over decentralized alternatives like distributed hash tables are very fast and free reads and continuous full data set availability even if the network is unreliable. This comes at a cost of much higher storage requirements. Storage is cheap and continues to get cheaper exponentially, making this a tolerable trade-off for many applications.

Since reads are free, writes are more costly, and storage is a globally shouldered cost, LF is designed to store very small values that change infrequently. Examples include identity information, public keys, certificates, DNS or DNS-like records, URLs, etc.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept, and at one point a character calls it "the LF" because "aleph" is mis-heard as an acronym. We used LF because there's already an open source project called Aleph and because a two layer obscure literary reference is cool.

## Purpose

LF is intended to be analogous to [etcd](https://github.com/etcd-io/etcd) or the key/value store aspect of [consul](https://www.consul.io) but for fully decentralized system that lacks central points of failure or singular authorities.

[ZeroTier](https://www.zerotier.com/) created LF as part of a larger effort to fully decentralize its [root server](https://www.zerotier.com/manual.shtml#2_1_1) system. With LF it becomes possible to look up the root servers used by a particular ZeroTier node, removing hierarchy from the ZeroTier system and allowing ZeroTier's roots and customer-operated roots to be equal network participants. Nodes can now home themselves at any root without sacrificing the ease of use afforded by ZeroTier's global address namespace.

This is why LF was created but we didn't want to restrict it to only this use. The more people use it the more robust and secure it will become and the more it can be improved. We are releasing LF as an independent project and encouraging anyone to use it for anything they might consider building.

## Building and Running

LF works on Linux and Mac systems. (FreeBSD may work too but hasn't been tried. Windows isn't supported yet.) It's is written in Go (1.11+) and C and is easy to build. The only external dependency is [sqlite](https://sqlite.org/) whose libraries and header files will need to be available. Since it contains parts written in C it can't easily be cross-compiled like pure Go, so you'll have to build on your native target.

First type `make godeps` to "go get" the project's Go dependencies. Then type `make` to build the binary.

## Usage

## Internals

## Credits

LF was written by [Adam Ierymenko](mailto:adam.ierymenko@zerotier.com) of ZeroTier, Inc. Work on LF was supported by the sorts of people who want highly secure distributed networks that lack single points of failure.

(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/) 
MIT License
