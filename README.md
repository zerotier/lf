# LF: A Secure Globally Shared Key/Value Store

## Introduction

LF (pronounced "aleph") is a fully replicated shared key/value store that can be operated by arbitrary numbers of unrelated and mutually untrusted parties.

Its purpose is to provide an omnipresent authoritative reference store for keys, identities, content hashes, certificates, static IPs/URLs, and other small and infrequently changing bits of important information. Think of it as something like [etcd](https://github.com/etcd-io/etcd) or the key/value storage aspect of [consul](https://www.consul.io) but for fully open and decentralized applications and systems.

[ZeroTier](https://www.zerotier.com/) developed LF to help fully decentralize our global root server infrastructure and deliver incredibly robust network state replication capabilities to enterprise customers operating ZeroTier networks in unreliable or hostile environments. We are making it generally available to the world and encouraging others to use it for other things because we like open source and decentralization and because the security and robustness of the public Internet LF instance is improved if more people use it.

## Design and Rationale

### Records, Selectors, and Masking

LF provides a key/value store where each value is identified by one or more keys termed *selectors*. Selectors are subject to equality queries and also to limited range queries, though only keys longer than 12 bytes can be queried by range and only the last 8 bytes of keys are comparable. (Example: `FooBar12345677` comes before `AbcDef12345678` even though `F` comes after `A` since only the last eight bytes are sorted.)

Selector keys are hashed to render them invisible to ignorant third parties. Selectors that appear in records are actully a 256-bit hash of their plain text keys plus the last eight bytes of each key (for keys at least 12 bytes in length) to render them partially sortable but still masked. A small 112-bit (secp112r1) elliptic curve public key from a key pair computed deterministically from a hash of the plain text selector key is also embedded into each selector (by replacing 113 bits of the original hash). Such tiny ECC keys are not considered secure enough for most use cases, but in this case the only purpose is to deter denial of service or cache pollution attacks involving the naive duplication of entries or front-running of sequences of entries. These key pairs are termed *claim keys* in LF. Each record is signed by the claim keys from all its selectors, making it impossible to create a record identified by a combination of selectors unless those selectors' real plain text keys are known to the record creator. Owner signatures use much larger keys.

Record values are themselves hidden by being encrypted with a secret key derived from another hash of the plain text key of the first selector. Since the first selector for a record is normally a unique record identifier (with range queryable fields reserved for secondary selectors) this makes record values unreadable to those that do not know what they're trying to find. Value masking can be disabled for a record but is the default behavior.

### Ownership and Authenticity

### Proof of Work

Without a rate limiting mechanism it would be trivial to attack LF by flooding the network with meaningless entries. Each LF record must be "paid for" by a proof of work calculation computed against the record's contents. The cost of a record is computed from its length using a formula specified at data store creation.

The objective real world cost of computing work will decrease as computers get faster, but storage and bandwidth costs should also be decreasing at the same time. (Since the early twenty-teens storage costs have decreased faster than compute power costs.)

### The Record Graph

LF records contain hashes of older records, linking all records together to form a directed acyclic graph (DAG). By default each record must link three ancestors.

This DAG accomplishes two things.

First, it makes it simple to synchronize with other nodes by starting with some recent record and then requesting the hashes of earlier records repeatedly until no "dangling links" remain. (Records with permanent dangling links are invalid and are eventually forgotten.)

Second, it allows work from records to be applied to ancestor records recursively. This provides a sunk cost based ordering mechanism similar to proof of work in a cryptocurrency block chain. Each record has a "weight" consisting of the cumulative work of all the records above it and all ancestor records with the same list of selectors and the same owner. This provides a strong and perpetually growing first line of defense against attempts to "steal keys." The longer an entry has been claimed by a given owner the harder it is to forge provided other users are also adding later records.

Link hashes are chosen to avoid linking records that appear suspect in any way, causing weight to accrue to valid and original records.

### Commentary Feeds

Nodes can also use local heuristics to detect apparently suspect records. Once a node's database has been synchronized it can flag any record that appears to duplicate a record received at an earlier local time. When a suspect record is created a node can create a new entry in LF itself indicating its disapproval of it.

LF nodes can be configured to trust other nodes' *commentary feeds* and flag or censor records that their trusted peers indicate may be problematic. This provides an optional opt-in trust based security mechanism that operates alongside and in addition to cumulative proof of work.

(This is not implemented yet as of the current alpha release!)

## Installation and Operation

LF has been tested on Linux and MacOS. It's written in both Go and C and requires a recent version of the SQLite3 embedded database library.

For full nodes we recommend a 64-bit system (it memory maps potentially large files) with a minimum of 2GB of RAM and a reasonably fast network connection. Right now the data store isn't very big but as it grows you might also need the ability to grow the partition on which LF's database resides. Clients and proxies (local API relays that can perform proof of work and encryption before accessing a full node) can run on smaller systems, though we still recommend at least 1GB of RAM since LF's proof of work is memory-intensive.

## Use Case Examples

### Decentralized Shared PGP Key Server

### ZeroTier Root Server Decentralization

## Security Best Practices

While LF has at least three overlapping security mechanisms (local heuristics, proof of work, and opt-in commentary from trusted nodes) to prevent already claimed keys from being modified or replaced, these mechanisms should not be trusted blindly. Application designers must understand the security posture of LF and design their applications to take appropriate precautions where necessary. The degree of paranoia required will of course depend on the use case and the nature of the application. An application used for financial transactions would demand more attention to security details than one for storing custom emojis.

Depending on the nature of the data being stored and retrived several different approaches might be used to add extra security. All of these are outside the scope of LF itself since their implementation details are going to differ by application.

* **Intrinsically unforgeable keys:** Some entry types can have keys that are intrinsically impossible (or at least prohibitively difficult) to store. An example would be a value identified by its own cryptographic hash, making it trivial to verify and impossible to change.

* **Certificates and signatures:** Values in LF could be signed by certificates validated by a CA chain, adding a secondary trust hierarchy based security mechanism alongside LF's native decentralized mechanisms.

* **Pinning:** A client could remember owners associated with entries and "pin" them in a manner similar to certificate pinning in SSL clients. Records from different owners wouldn't be accepted unless the previous owner created a record with a value indicating the new owner or otherwise handing off ownership.

* **Caching:** Long term or permanent local caching of records could be a security measure. If a record is already cached by most of its users there's little value to an attacker in attempting to alter it in the LF data store.

* **Active out of band verification:** Some systems might provide mechanisms for verification of entries via some additional out of band mechanism. In the PGP key server example a test e-mail might be sent encrypted to the recipient to check that they are indeed the owner of that e-mail address and that the key is correct.

This isn't an exhaustive list since novel applications might offer their own unique channels and heuristics for detecting forged, modified, or corrupt data. Be creative!

## FAQ

**Q:** What does the name LF mean?  
**A:** [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_(short_story)) is a story by Argentine writer and poet Jorge Luis Borges about a single point in space that allows the entire universe to be seen across all space and time. It seemed a fitting name for a shared data store where every node holds everything. Science fiction writer William Gibson used this term to refer to a [massive virtual world](http://www.antonraubenweiss.com/gibson/sprawlgloss.html) whose physical implementation is contained in a small box. In Gibson's novel *Mona Lisa Overdrive* the characters first mistake the word *aleph* for the letters *LF*, so we went with that as a multi-layered nerd joke and because there's already a different open source project called [aleph](https://github.com/ztellman/aleph).

**Q:** Won't LF get huge?  
**A:** LF is designed for very small data objects like keys, URLs, hashes, etc. Nevertheless it could get big if it's used by many people over many years. If everyone on Earth created a key once a year, you'd have 5-10 terabytes of data after a few years. A 10TB hard drive currently costs $200 (USD). We don't think this is likely to be a problem. If it does become an issue it would be possible to implement support for fractional nodes that do not have to cache the entire record graph.

**Q:** What prevents someone from flooding LF with garbage data?  
**A:** LF entries must be "paid for" via a memory and CPU intensive proof of work function. This work also helps add security to existing entries in the data store in a manner similar to a proof of work cryptocurrency. If someone wants to expend money and energy to create large numbers of garbage entries and in the process help secure existing entries against forgery they are welcome to do so.

**Q:** Is LF an anonymity system like Tor or FreeNET?  
**A:** Not really, and it's not designed for this use case. LF entries do not contain any intrinsic information that could trace them to a particular individual or IP address, but it would be possible for the operators of LF nodes to log network traffic and determine the likely point of origin for a new entry.

## License

LF is released under the MIT License  
(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/)
