# LF: A Decentralized Fully Replicated Key/Value Store

## Introduction

LF (pronounced "aleph") is a fully decentralized fully replicated key/value store.

LF is intended to fill a role akin to the key/value store aspects of [etcd](https://github.com/etcd-io/etcd) or [consul](https://www.consul.io) but for fully decentralized systems that lack both a single point of failure and (in many cases) a single controlling entity. It's designed to store small infrequently changing bits of data like certificates, keys, identity information, DNS records, and other information critical to the operation of a system.

The design of LF is inspired by several different cryptocurrencies and other kinds of block chain or hash tree database systems. It's not a cryptocurrency but could in theory be used as the underlying data store for one. It was created to help [ZeroTier](https://www.zerotier.com/) fully decentralize its root server infrastructure and support decentralized controller models for ultra high reliability private networks.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept, and at one point a character calls it "the LF" because "aleph" is mis-heard as an acronym. We used LF because there's already an open source project called Aleph and because a two layer obscure literary reference is cool.

## Building and Running

LF works on Linux and Mac systems. (FreeBSD may work too but hasn't been tried. Windows isn't supported yet.) It's mostly written in Go (1.11+) with some C for performance critical bits and is easy to build. The only external dependency is [sqlite](https://sqlite.org/) whose libraries and header files will need to be available. Since it contains parts written in C it can't easily be cross-compiled like pure Go, so you'll have to build on your native target.

First type `make godeps` to "go get" the project's Go dependencies. Then type `make` to build the binary.

## Usage

## Internals

## Credits

LF was written by [Adam Ierymenko](mailto:adam.ierymenko@zerotier.com) of ZeroTier, Inc.

(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/) 
MIT License
