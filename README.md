# LF: Fully Decentralized Fully Replicated Key/Value Store

*(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/)* 
*Licensed under the [GNU GPLv3](LICENSE.txt)*

**LF is currently beta software!**

## Introduction

LF (pronounced "aleph") is a fully decentralized fully replicated key/value store.

Fully decentralized means anyone can run a node without obtaining special permission and all nodes are effectively equal. Fully replicated means every node stores all data.

LF is built on a [directed acyclic graph (DAG)](https://en.wikipedia.org/wiki/Directed_acyclic_graph) data model. Proof of work is used to rate limit writes to the shared data store on public networks and as one thing that can be considered by conflict resolution and trust algorithms. See [DESIGN.md](doc/DESIGN.md) for details.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept. At one point a character calls it the "LF" because "aleph" has been mis-heard as an acronym. We used LF because there's already an open source project called Aleph, it gives the command line client `lf` a short name, and because two levels of obscure literary reference recursion is cool.

### Why?

The purpose of LF is to provide for decentralized systems what the key/value store aspects of [etcd](https://github.com/etcd-io/etcd) and [consul](https://www.consul.io) provide in centrally managed environments, namely a fast reliable store for small but critical pieces of information.

Most decentralized systems rely on distributed hash tables (DHTs) like [Kademlia](https://en.wikipedia.org/wiki/Kademlia) to fill this role. This has been the standard approach since [magnet links](https://en.wikipedia.org/wiki/Magnet_URI_scheme) and similar DHT-based schemes were developed for open file sharing applications in the early 2000s.

For several years ZeroTier has researched ways to more completely decentralize our network. This drive is both economic and philosophical. We have multiple enterprise clients that want to minimize hard dependency on third party physical infrastructure and one that wants very reliable operation in very unreliable environments. We don't mind cutting our hosting costs either. Philosophically we began life as a "re-decentralize the Internet" open source effort and that's still very much in our DNA.

We looked at DHTs but unfortunately they are not up to the task. They're vulnerable to multiple types of network level denial of service and ["Sybil"](https://en.wikipedia.org/wiki/Sybil_attack) attacks, lose access to data if even parts of the network become unreachable, and are slow. Unfortunately everyone in the decentralization space seems to think DHTs solve the small data problem. More recent serious projects like [IPFS](https://ipfs.io) and [Dat](https://dat.foundation) are concentrating on decentralizing storage for medium to large data objects.

ZeroTier's initial minimally centralized design might offend decentralization purists but it's fast and secure. We wanted something just as good. Until mid-2018 we [weren't sure it was possible](http://adamierymenko.com/decentralization.html). Then we realized certain ideas from the cryptocurrency space combined with certain other ideas from the decentralized trust arena could be combined to yield something new, and we started creating LF.

LF will allow us to completely decentralize our root server infrastructure, letting customers use only their own roots or other third party roots without sacrificing ZeroTier's powerful and convenient single unified namespace. It will also let us deliver network virtualization solutions to our enterprise customers that are no less reliable than the network itself, continuing to operate even when sections of the overall network become slow or unreachable.

### Features and Benefits

* Easy to use and easy to deploy.
* Fully decentralized network with no mandatory single points of control or failure.
* Multi-paradigm trust model allowing user choice between different conflict resolution mechanisms including cumulative proof of work "weight," local node heuristics, elective trust of oracle nodes, and (eventually) certificates.
* Fast (milliseconds) nearline queries against the entire global data set at all times.
* Multiple record keys (up to 15) allow nested directory-like relationships.
* Range queries are possible against a 64-bit ordinal value assocaited with each record key.
* Encrypted record keys and values for improved privacy and security.
* Novel proof-of-knowledge mechanism makes it impossible to generate valid records identified by a key whose plain text is not known.

### Limitations and Disadvantages

* LF is only useful for small bits of information that don't change very often like certificates, keys, IP addresses, names, etc.
* The [CAP theorem](https://en.wikipedia.org/wiki/CAP_theorem) trade-off is availability and partition-tolerance, meaning eventual consistency and no transactions.
* High storage requirements for full nodes make LF unsuitable for resource constrained devices. These devices usually work by querying larger servers or stationary devices anyway.
* Storage requirements grow over time in a manner not unlike a block chain. Fortunately [storage is getting cheaper over time too](https://www.backblaze.com/blog/hard-drive-cost-per-gigabyte/) and unlike transistor density on conventional 2d silicon wafers we do not appear to be near a physical limit. The way LF records are stored and hashed allows some old data to be discarded too, but this is not implemented yet.

## Building and Running

LF works on Linux, Mac, and probably BSD. It won't work on Windows yet but porting shouldn't be too hard if anyone wants it. It's mostly written in Go (1.11+ required) with some C for performance critical bits. Building it is easy. The only non-Go dependency is a reasonably recent version of [SQLite](https://sqlite.org/) whose libraries and header files will need to be available on the system.

If you have recent Go, a C compiler, and SQLite just type `make` and it should build.

Once we get out of beta we'll probably provide some pre-built binaries as is the custom for Go projects.

## Getting Started

LF comes with a full node implementation and a command line client that can be used to create and query records and to some limited extent control nodes (if accessing them from localhost). All of these things exist in the same `lf` binary that gets built when you type `make`. Once you build the binary just run it for help.

LF ships out of the box with its command line client configured to query `lf.zerotier.com`, a node operated by ZeroTier. If you want to see LF work, try a simple query:

    $ ./lf get bad horse#

The `./` prefix assumes you just built LF and it's sitting in the current directory. You won't need that if you installed it somewhere like `/usr/local/bin`.

If you don't know, these are the lyrics to [Bad Horse](https://www.youtube.com/watch?v=VNhhz1yYk2U) from the musical [Dr. Horrible's Sing-Along Blog](https://drhorrible.com).

### Selectors, Ordinals, and Values

LF uses a whole lot of black magic under the hood, but the API it provides to clients is quite simple. This is the ZeroTier philosophy for everything we build.

Record keys are cryptographic objects called *selectors* that are generated from plain text selector *names* and *ordinals*. The name of a selector is any text or binary string, while the ordinal is a 64-bit integer. Zero is used if no ordinal is specified.

The query system in LF allows values to be looked up by selector name, but these names are not sortable once LF cryptographically mangles them. To retrieve a record its first selector name must be known. If you need range queries you have to use ordinals and build your application's data model accordingly.

The command line client lets you specify selector names and ordinals using a `name#ordinal` or `name#min#max` syntax. In the `get bad horse#` query we leave the ordinal empty. This is shorthand for `#0#18446744073709551615` where that huge number is the maximum value of an unsigned 64-bit integer.

You can see selectors and ordinals in the `get bad horse#` output. Now try a few variations:

    $ ./lf get bad horse`

    $ ./lf get bad horse#2#10

The first case with no hash sign is equivalent to `get bad horse#0` and returns only ordinal zero. The second case asks for a range of ordinals and returns only those lines.

### Multiple Selectors

All queries must specify at least one selector, but a record can have up to eight. If multiple selectors exist they form a hierarchy. A query for fewer selectors will return all records beneath them in a manner not unlike a `find` command executed against a directory hierarchy.

The Bad Horse records each have two selectors: `bad` and `horse`. The first selector has ordinal zero. The second has a range of ordinals with each corresponding to one line in the song. Try asking for just the first:

    $ ./lf get bad

**Be warned**: you'll see the lyrics to Bad Horse, but that's not all you'll see. We can make **no warranties** regarding what others may have stored in the public DAG! This brings us to the next section...

### First Come, First Serve!

... for **unique** sequences of selector names.

If LF is open and decentralized, what happens if someone does this?

    $ ./lf set bad horse#0 'Good Horse, Good Horse`

A record will be created and published. Chances are nobody will ever see it unless they ask for it by its exact record hash or otherwise dig for it.

The already existing Bad Horse records have three big things going for them:

1. They're older and therefore more work (in a proof of work sense) has been added to the DAG since their creation. Each record references older records and when it gets stitched into the DAG its work is transferred to its ancestors all the way back to the beginning of time, increasing a metric called their *weight*. A determined attacker willing to buy a lot of compute power could overcome this, but the more time passes the more costly this attack becomes.
2. They are going to have lower *local reputation* scores on current nodes, including the one you are likely querying. When a record arrives at a running node that collides with an existing fully synchronized and verified record, it gets flagged as suspect. Lower reptuation records also don't get picked to be links for new records, meaning they pick up weight more slowly. Nodes also score them lower when computing the default trust metric.
3. Their reputation won't have been tarnished by gossip. Nodes can be configured to generate *commentary*. When such a node sees a suspect record, it adds it to a running set of records it publishes called commentary records. These are received and parsed by all other nodes and can (optionally) be taken into account if elected by a user (this isn't fully implemented yet as of 0.5).

That's a bit of an oversimplification but it should give you some insight into LF's security and data integrity model.

There is one more catch though. What if someone does this?

    $ ./lf set bad cow '!ooM'

We did that already so you might recognize it as one of the odd results obtained by just querying `bad`.

Records are disambiguated according to a compound key computed from all their selector names (but not ordinals) in order. That means `bad cow` can indeed be owned by someone different from `bad horse`. While it's possible to query against incomplete lists of selectors, application developers must be aware of the implications. In most cases you'll want to execute queries against all selectors.

But what does happen to lower weight or lower reputation records? Try this:

    $ ./lf -json get bad horse#0

Results are returned as lists of records sorted in descending order of trust according to the selected metric. The default behavior of the command line client is to show only the highest scoring result for each set of selectors and ordinals. The `-json` flag requests and dumps everything. This query will give you all records that match `bad horse#0` and that will likely include quite a few impostors.

Since names are first come first serve, short names like `bad` aren't the sorts of names you'll want to use for the first selector for records in a production system. (Subsequent selectors could have short names if they make sense.) We suggest a backwards DNS naming scheme similar to Java's class names and many other sorts of identifiers, which would cause us to create keys that start with `com.zerotier...`. That's only a suggestion though. It doesn't really matter as long as the odds of an accidental collision are extremely low.
