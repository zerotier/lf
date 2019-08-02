# LF: Fully Decentralized Fully Replicated Key/Value Store

*(c)2018-2019 [ZeroTier, Inc.](https://www.zerotier.com/)* 
*Licensed under the [GNU GPLv3](LICENSE.txt)*

**LF is currently beta software!** Until 1.x object formats, APIs, and protocols may change in abrupt and non-backward-compatible ways (though we try to avoid it).

[toc]

## Introduction

LF (pronounced "aleph") is a fully decentralized fully replicated key/value store.

Fully decentralized means anyone can run a node without obtaining special permission and all nodes are effectively equal. Fully replicated means every node stores the entire data set.

LF is built on a [directed acyclic graph (DAG)](https://en.wikipedia.org/wiki/Directed_acyclic_graph) data model that makes synchronization easy and allows many different security and conflict resolution strategies to be used. One way to think of LF's DAG is as a gigantic [conflict-free replicated data type](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type) (CRDT).

Proof of work is used to rate limit writes to the shared data store on public networks and as one thing that can be taken into consideration for conflict resolution. Other things that can be considered (at the querying client's discretion) are local subjective heuristics at the node and certificates issued by a certificate authority.

The name LF comes from the short story [The Aleph](https://en.wikipedia.org/wiki/The_Aleph_%28short_story%29) by Jorge Luis Borges and the novel [Mona Lisa Overdrive](https://en.wikipedia.org/wiki/Mona_Lisa_Overdrive) by William Gibson. Borges' story involves a point in space that contains all other points, a fitting metaphor for a data store where every node stores everything. Gibson's novel features a sci-fi take on Borges' concept. At one point a character calls it the "LF" because "aleph" has been mis-heard as an acronym. We used LF because there's already an open source project called Aleph, it gives the command line client `lf` a short name, and because two levels of nerdy literary recursion are cool.

### Why Does This Exist?

The purpose of LF is to provide for fully open decentralized systems what things like [etcd](https://github.com/etcd-io/etcd) and [consul](https://www.consul.io) provide in centrally managed environments, namely a fast reliable store for small but critical pieces of information. These are things like keys, certificates, identity information, configuration files, IPs, DNS names, URLs, data hashes, and so on.

Most decentralized systems use distributed hash tables (DHTs) for this purpose. DHTs scale well but are slow, require a reliable global network to maintain full access to the data set, and are vulnerable to ["Sybil"](https://en.wikipedia.org/wiki/Sybil_attack) type attacks. We at ZeroTier wanted something very fast, secure, and continuously available even under unreliable network conditions. This prompted us to develop something fundamentally new. As far as we know nothing quite like LF exists (we looked). The closest analogs are cryptocurrency block chains and CRDT-based distributed databases.

### Features and Benefits

* **Easy to use and deploy**, ships with useful defaults and credentials to use an open public network.
* **Fully decentralized** system with open participation and no single points of failure. (Private LF databses can be created that require certificates, but this is optional.)
* **Fast sub-second nearline queries** against the entire global data set at all times, even when network is down.
* **Versatile security model** allowing user choice between different conflict resolution mechanisms that can be used alone or in combination with one another. These include local heuristics, proof of work "weight," elective trust of other nodes, and certificates.
* **Flexible record lookup** API allowing multiple nested keys and range queries against 64-bit ordinals associated with each key.
* **Everything is encrypted** including record keys making the system private and secure even though all data is replicated globally. Records whose keys are not known cannot even be enumerated or looked up.
* **Liveness signaling** through the *pulse* mechanism to enable LF to be used to advertise service, object, or user availability in near-real-time.

### Limitations and Disadvantages

* **LF is only good for small bits of information** that don't change very often. It's explicitly not designed for large data.
* **[CAP theorem](https://en.wikipedia.org/wiki/CAP_theorem) trade-off: AP** (availability, partition-tolerance). The database is eventually consistent and locks are not supported.
* **High CPU, memory, storage, and bandwidth requirements** make LF unsuitable for small and resource constrained devices.
* **Storage requirements grow over time** in a manner not unlike a block chain. Fortunately [storage is getting cheaper over time too](https://www.backblaze.com/blog/hard-drive-cost-per-gigabyte/). The data model and protocol are designed to permit partial data discarding and fractional nodes. These features are not implemented yet and likely won't be needed for years.

## Building and Running

LF builds and runs on Linux, Mac, and probably Free/Open/NetBSD. It won't work on Windows yet but porting shouldn't be too hard if anyone wants it. It's mostly written in Go (1.11+ required) with some C for performance critical bits. It depends on a recent version of SQLite which is included in source form to avoid problems due to excessively old versions on some systems.

To build on most platforms just type `make`. You will need Go 1.11 or newer (type `go version` to check) and a relatively recent C compiler supporting the C99 standard.

## Getting Started

Both a command line client and a full node implementation are present in the same `lf` binary. Just run it and it will print help.

LF ships out of the box with its command line client configured to query `lf.zerotier.com`, a public node using the default public database operated by ZeroTier. That means you can try a simple query right away:

```text
$ ./lf get bad horse#
Bad Horse, Bad Horse                                      | bad#0 horse#0
Bad Horse, Bad Horse                                      | bad#0 horse#1
He rides across the nation, the thoroughbred of sin       | bad#0 horse#2
He got the application that you just sent in              | bad#0 horse#3
It needs evaluation, so let the games begin               | bad#0 horse#4
A heinous crime, a show of force                          | bad#0 horse#5
(a murder would be nice of course!)                       | bad#0 horse#6
Bad Horse, Bad Horse                                      | bad#0 horse#7
Bad Horse, He's Bad!                                      | bad#0 horse#8
The evil league of evil is watching so beware             | bad#0 horse#9
The grade that you receive'll be your last, we swear      | bad#0 horse#10
So make the bad horse gleeful, or he'll make you his mare | bad#0 horse#11
You're saddled up; there's no recourse                    | bad#0 horse#12
It's "hi-yo, silver!"                                     | bad#0 horse#13
Signed: Bad Horse.                                        | bad#0 horse#14
```

Drop the `./` before `lf` if you already installed the binary somewhere in your path. Don't forget the trailing hash sign on `horse#` or you will only get the first record (more on this later).

These are the lyrics to [Bad Horse](https://www.youtube.com/watch?v=VNhhz1yYk2U) from the musical [Dr. Horrible's Sing-Along Blog](https://drhorrible.com). Yes, we put that in the public data store. We hope it's fair use.

### Selectors, Ordinals, and Values

Record keys are cryptographic objects called *selectors* that are generated from plain text selector *names* and *ordinals*. The name of a selector is any text or binary string. The ordinal is an unsigned 64-bit integer. (If no ordinal is specified, it is zero.) Names can only be looked up directly but if you know a name you can ask for ranges of its ordinals.

Bad Horse is stored as a series of records with two selectors and with the ordinals in the second selector placing them in order. You can see them in the output above. Now try a few variations:

```text
$ ./lf get bad horse
Bad Horse, Bad Horse | bad#0 horse#0

$ ./lf get bad horse#2#10
He rides across the nation, the thoroughbred of sin  | bad#0 horse#2
He got the application that you just sent in         | bad#0 horse#3
It needs evaluation, so let the games begin          | bad#0 horse#4
A heinous crime, a show of force                     | bad#0 horse#5
(a murder would be nice of course!)                  | bad#0 horse#6
Bad Horse, Bad Horse                                 | bad#0 horse#7
Bad Horse, He's Bad!                                 | bad#0 horse#8
The evil league of evil is watching so beware        | bad#0 horse#9
The grade that you receive'll be your last, we swear | bad#0 horse#10
```

When you ask for `bad horse#` (in the very first example) the trailing hash is expanded to `#0#18446744073709551615`. That huge number is the maximum value of a 64-bit unsigned integer. Leaving off the trailing hash is equivalent to `#0` and gets only ordinal zero. Using `#2#10` asks for ordinals two through ten inclusive. Try it!

#### Conflict Resolution

If LF is open and decentralized, what happens if someone does this?

```text
$ ./lf set bad horse#0 'Good Horse, Good Horse'
```

A record will be created and published. Chances are nobody will see it.

The already existing Bad Horse records have three big things going for them:

1. They're older and therefore more work (in a proof of work sense) has been added to the DAG since their creation. Each record references older records and when it gets stitched into the DAG its work is transferred to its ancestors all the way back to the beginning of time, increasing a metric called their *weight*. A determined attacker willing to buy a lot of compute power could overcome this, but the more time passes the more costly this attack becomes.
2. They are going to have lower *local reputation* scores on current nodes, including the one you are likely querying. When a record arrives at a running node that collides with an existing fully synchronized and verified record, it gets flagged as suspect. Lower reputation records also don't get picked to be links for new records, meaning they pick up weight more slowly and get replicated more slowly (if at all).
3. *Oracle nodes* will gossip about the impostor, but not the original. An oracle node is a node configured to generate *commentary*, special records that perform the dual function of adding work to the DAG and commenting on records these nodes find suspect. The commentary of all oracle nodes is available but users are free to decide whether or not to trust it.

But what does happen to lower weight or lower reputation records? Try this:

```text
$ ./lf -json get bad horse#0
```

The LF API returns results as an array of arrays. Each array in the first dimension represents a set of records that share the same set of selector keys. The array in the second dimension is these records sorted in descending order of trust according to whatever conflict resolution mechanism(s) are active. The default behavior of the command line client is to show only the "winner" for each set of selectors, but `-json` tells it to request and dump everything.

Since names are first come first serve, short names like `bad` aren't the sorts of names you'll want to use for the first selector for records in a production system. Good naming strategies include reverse-DNS-order names similar to Java class names (e.g. `com.zerotier...`), unique GUIDs, and random strings. The latter options are good for systems that don't want to advertise their keys globally and want to avoid making their records available to users not in-the-know. Just remember that [naming things is one of the two hard things in computing](https://www.martinfowler.com/bliki/TwoHardThings.html).

### Running a Full Node

Running a node on the public network is easy:

```text
$ ./lf node-start &
```

If you are a normal user the node will keep its files in `$HOME/.lf`. If you are root it will be `/var/lib/lf`. Obviously you'll want to set this up via *systemd* or some other process-supervising system to run it on a real server.

Nodes listen by default on P2P port 9908 and HTTP port 9980. These can be changed with command line options. If you're on a server on the open Internet and are root (or can bind port 443) you can use `-letsencrypt <hostname>` to enable SSL and automatically obtain a certificate from [Let's Encrypt](https://letsencrypt.org).

Here are some of the node-specific files you'll see in the node's home directory:

* `lf.pid`: PID of running node
* `node.log`: Node log output (`tail -f` this file to watch your node synchronize)
* `identity-secret.pem`: Secret ECC key for node's commentary and also for encryption of node-to-node P2P communications
* `authtoken.secret`: HTTP API bearer auth token.
* `peers.json`: Periodically updated to cache information about P2P peers of this node
* `genesis.lf`: Genesis records for the network this node participates in
* `node.db`: SQLite indexing and meta-data database
* `records.lf`: Flat data file containing all records in binary serialized format. This file will get quite large over time.
* `weights.b??`: Record proof of work weights with 96-bit weights striped across three memory mapped files to reduce I/O load during weight updates
* `graph.bin`: Memory mapped record linkage graph data structure
* `wharrgarbl-table.bin`: Static table used by proof of work algorithm, auto-generated on first use

The node will also create or modify `client.json` to add its own local (127.0.0.1) HTTP URL so that client queries on the local system will use it.

Watch `node.log` after you start your server for the first time and you'll see it synchronizing with the network. This can take a while. Once the node is fully synchronized you should be able to make queries against any data.

A few caveats for running nodes:

* We recommend a 64-bit system with a bare minimum of 1gb RAM for full nodes. Full nodes usually use between 384mb and 1gb of RAM and may also use upwards of 1gb of virtual address space for memory mapped files. 32-bit systems may have issues with address space exhaustion.
* Don't locate the node's files on a network share (NFS, CIFS, VM-host mount, etc.) as LF makes heavy use of memory mapping and this does not always play well with network drives. It could be slow, unreliable, or might not work at all.
* Hard-stopping a node with `kill -9` or a hard system shutdown could corrupt the database. This might get improved in the future.

### Pulses for Liveness Signaling

In real world systems it's very often useful to be able to provide information about which objects are "alive." Examples include users in a chat systems, nodes in a distributed network, or services in a distributed micro-service architecture.

Signaling liveness in LF by constantly updating records would be very inefficient. LF therefore provides (since 0.9.18) a much more efficient method called a **pulse**.

Each LF record contains a 64-bit field called *PulseToken*. This field contains the final hash that results from iteratively evaluating a 64-bit AES-based short input cryptographic hash function (see `th64.go`) 525,600 times. The first hash in this hash chain is based on a hash of the record's plain text selector name(s), ordinal(s), timestamp, and owner secret key.

525,600 is non-coincidentally the number of minutes in one year. To generate a pulse the owner of a record computes and broadcasts hash N in the record's pulse hash chain where N equals 525,600 minus the number of minutes that have elapsed since the record's timestamp. Any node can verify the validity of a pulse by hashing the pulse M times where M equals the number of minutes being signaled by the pulse and verifying that the result equals the record's *PulseToken*. Since pulses can only work up to one year since a record's original timestamp, after one year a new record containing the same data will have to be made. The pulse feature reduces the frequency of full record rewrites for liveness messaging from once-per-minute or once-per-few-minutes to once-per-year.

This is effectively the same as the [S/KEY](https://en.wikipedia.org/wiki/S/KEY) one-time password scheme originally invented by cryptographer Leslie Lamport, only in this case each one-time password indicates a timestamp.

Pulses are extremely lightweight. They consist of a 64-bit hash plus three bytes for the minute count. Ten million objects could signal liveness with one minute resolution and consume only 1.8 megabytes per second of bandwidth (1.8% of a one gigabit connection). A billion objects would require a bit more than two gigabits of bandwidth. If scalability of the pulse mechanism becomes a concern broadcasting could be replaced by a sharded or DHT-like pulse signaling algorithm.

This lightness comes at a cost of some security. A 64-bit hash is not sufficient to prevent a determined attacker with large amount of compute power or storage from falsifying pulse messages, but the cost is high enough to deter casual or mass scale abuse. If you need to convey liveness information with a higher level of security than that offered by the pulse mechanism, a secondary check must be employed. Since pulses typically signal liveness the simplest approach would be to directly verify liveness by querying the object or service in question before concluding definitively that it is alive.

On the public network there's a record called `pulse.test` that can be used to test pulses. Try `./lf -json get pulse.test` to output verbose JSON information about this record:

```json
{
  "Hash": "=iJniIEzkyHOg6a3h1j84NfK9zAimbKOIdtueFiBmhqW",
  "Size": 253,
  "Record": {
    "Value": "\buejQNR7CCbAQXvwnfSMKDs6uEmQcIA92E0olsb4c",
    "Owner": "@BwAIObsaWYF1CiOXgol",
    "Links": ["=WWXjsYR5RofL0HX9kQ5SgXxaG4K53UBAJX9cAaAVBbz", "=yJbYgUszcV0sHRuuqpADsdu1tmM5DSIXdZuIkMiiZds"],
    "Timestamp": 1564413035,
    "PulseToken": 2307216339445404689,
    "Type": 0,
    "Selectors": [
      {
        "Ordinal": "\b015cQjQWnbkEmtGKpOoJX",
        "Claim": "\bYRsSUaW7KRTQulx9HPPxmMjleJFuA2rCfN9J2FRKXLtRSashX1glxLt"
      }
    ],
    "Work": "\b1hUKPQBAAW6CoI6KeBP",
    "WorkAlgorithm": 1,
    "Signature": "\b14RFxlZgEuGoalSdN6Z4SyknXw6QMU145kYLDUIvcPY5AsRH6IyfCFUyAxONARQpUPsosc3VgCLq"
  },
  "Value": "This record is being pulsed.",
  "Pulse": 1564413815,
  "Trust": 0.9,
  "LocalTrust": 1,
  "OracleTrust": 1,
  "Weight": [0, 0, 0, 71774169],
  "Signed": false
}
```

One of ZeroTier's nodes has a *cron* job running to emit this pulse every minute. The field *Pulse* will indicate the record's timestamp plus the number of minutes indicated by the latest received pulse.

Pulses are broadcast using a best-effort rumor mill algorithm. A node caches information about the latest pulses it has observed but nodes do not get old pulses when they synchronize nor are pulses re-transmitted if a node re-joins after being offline for a period of time. Pulses are ephemeral signals of liveness, not permanent parts of the data set.

### Oracles and Elective Trust

LF's intrinsic conflict resolution mechanism relies upon proof of work as a hard to forge proxy for time, much like many cryptocurrencies. Proof of work is not foolproof, especially in LF where there is no intrinsic economic mechanism to incentivize the runaway growth of PoW "mining" investment. As a result a well financed or determined attacker willing to throw a lot of compute power at the problem could overcome the PoW "weight" of the records beneath a target record in the LF DAG and replace it.

This is why PoW is only one of LF's built in conflict resolution mechanisms. It's the easy one in that it requires no configuration but it also offers weaker security in the presence of an attacker who knows your selector names (remember that they're encrypted!) and wants to co-opt your records.

For stronger security it is possible to electively trust select LF nodes.

LF nodes maintain an internal *reputation* value for each record. A node computes reputation based on a few heuristics with by far the most important being which record arrives first. If a record appears to collide with another record that is fully synchronized (meaning all its dependencies are met) it gets a zero reputation rating.

When a node is run with the `-oracle` flag it will use spare CPU cycles on the system to constantly create its own *commentary* records. These records are overloaded with work to add work to the DAG (like a miner in the cryptocurrency world) but they can also contain information about records a particular node thinks are suspect.

Oracle nodes document low reputation records in commentary records. When a node sees a commentary record it extracts this information and caches it internally in an indexed table.

To use commentary information a client includes owners representing oracle nodes in the *Oracles* field of its queries. In the command line client these can be managed with the `oracle` command. When oracles are included the query takes commentary from these oracles into consideration when computing apparent trust for a record. If two records have the same trust then proof of work weight is used as a tie breaker.

If used with care the oracle system can provide very hard security guarantees that simply are not possible with a purely automatic zero interaction system like proof of work. An organization can run its own pool of oracle nodes and trust them for all its queries, ensuring that its nodes act as the final arbiter of truth if there is a record value conflict.

Casual users can choose to trust nodes that are generally trusted. Applications could ship with trust lists similar to how they ship with SSL CA lists.

*Note that you shouldn't run nodes in `-oracle` mode on variable or burstable CPU cloud instances as this could result in a large bill or a surprise failure when the instance uses up its CPU quota. Use reserved CPU or bare metal systems for oracle nodes.*

### LFFS

LF contains a FUSE filesystem that allows sections of the global data store to be mounted. It can be mounted by remote clients or directly by full nodes, with the latter offering much higher performance since all data is local to the process. LFFS requires FUSE on Linux or [OSXFUSE](https://osxfuse.github.io) on Mac.

LFFS is very basic and does not support full POSIX filesystem semantics. It's intended to be used for things like configuration file replication. Don't even try to put a database or something else complex on it. Even a git repository is likely to be too much. Here's a current list of known issues and limitations:

* Hard links, special modes like setuid/setgid, named pipes, device nodes, and extended attributes are not supported.
* Filesystem permission and ownership changes are not supported and chmod/chown are silently ignored.
* File locks are not supported.
* Renaming is a bit clunky and slow and doesn't quite obey POSIX semantics as it's implemented as delete-create.
* Name length is limited to 511 bytes. This is for names within a directory. There is no limit to how many directories can be nested.
* If you must perform proof of work, writes will be extremely slow to propagate and CPU-intensive. There is currently no way to cancel a write.
* A single LF owner is used for all new files under a mount and there's no way to change this without remounting.
* Once a filename is claimed by an owner there is currently no way to transfer ownership even if the file is subsequently deleted.

Some of these might get fixed or improved in the future, but as we said LFFS is intended for very simple use cases and small data.

To try out LFFS try this:

```text
$ ./lf mount -maxfilesize 4096 -passphrase 'The sparrow perches on the steeple in the rain.' /tmp/lffs-public-test com.zerotier.lffs.public-test
```

If everything works you should be able to access a public test LFFS share at `/tmp/lffs-public-test`. **Be aware** that this is a global public test share, so it could contain anything! If you see anything nasty there feel free to delete it. Since the passphrase (which generates both the owner and the masking key) is public, anyone can read and write.

The above command mounts via the HTTP(S) API, which is slow. To mount directly under a running full node, edit a file called `mounts.json` in the node's home directory and then restart it. Here's an example `mounts.json` to mount the same public test share.

```json
[
	{
		"Path": "/tmp/lffs-public-test",
		"RootSelectorName": "com.zerotier.lffs.public-test",
		"MaxFileSize": 4096,
		"Passphrase": "The sparrow perches on the steeple in the rain."
	}
]
```

The complete schema for mount points in `mounts.json` is:

* **Path**: Path to mount FUSE filesystem on host (must have read/write access).
* **RootSelectorName**: LF selector name (without ordinal) of filesystem root.
* **OwnerPrivate**: Owner private key (if omitted the node's identity is used).
* **MaskingKey**: Masking key to encrypt record (file) contents (if omitted root selector name is used).
* **Passphrase**: If present this overrides both **OwnerPrivate** and **MaskingKey** and is used to generate both.
* **MaxFileSize**: This limits the maximum size of locally written files. Files larger than this can appear if someone else wrote them. The hard global maximum is 4mb. Note that large files can take a *very* long time to commit due to proof of work on public networks!

## Sol: The Default Public Database / Network

LF ships with a default configuration for a public network we call *Sol* after our home solar system. This configuration contains a default node URL and default *genesis records* allowing nodes to automatically bootstrap themselves.

Sol permits record values up to 1024 bytes in size, though records that big take a lot of proof-of-work to publish. It also includes an *authorization certificate*. Normally records require proof of work to create. An authorization certificate allows this to be skipped if the record's owner is signed and this signature is included.

We intend to use LF (via Sol) to decentralize our root server infrastructure. Our roots service quite a few ZeroTier customers so that means they'll be forced to create quite a lot of (tiny) LF records. Doing proof of work for all those is possible but costly, so we stuffed a certificate into Sol's configuration to let us cheat and be special. Think of it as our "fee" for creating and maintaining LF and donating it as open source to the community.

LF is open source. It's possible to make your own LF networks and configure them however you like. You can even create private LF networks that *require* signatures for anyone to add records. These will be of interest to our enterprise customers with private air-gapped environments.

## Local Test Mode

Running `node-start -localtest` runs a full node in local test mode. Local test nodes store their state and data in a `localtest` subfolder of the LF home path (to not conflict with any full node you're running) and do not communicate over the P2P network. They also ignore proof of work and/or certificate requirements for new records. Local test nodes are good for testing software designed to store data in LF without polluting live databases with test records and junk and without having to wait for proof of work computation.

## Creating a Private Database Instance / Network

To create a private database/network you need to create your own *genesis records*. These serve as the first anchor points in the DAG (and are exempt from the normal linkage and other rules) and contain your network's configuration.

To do this use the command `makegenesis`. Here's a simple example:

```text
$ ./lf makegenesis
Network name: Test
Network ID will be 3bee213bd4f522cf7fb0dd0dfd282274b423800ef6237e3a4b03e93806fcdc4c
Network contact []: test@test.com
Network comment or description []: Test network
Record minimum links [2]:
Record maximum value size [1024]:
Record maximum time drift (seconds) [60]:
Amendable fields (comma separated) []:
Create a record authorization certificate? [y/N]:

{
  "ID": [59, 238, 33, 59, 212, 245, 34, 207, 127, 176, 221, 13, 253, 40, 34, 116, 180, 35, 128, 14, 246, 35, 126, 58, 75, 3, 233, 56, 6, 252, 220, 76],
  "Name": "Test",
  "Contact": "test@test.com",
  "Comment": "Test network",
  "AuthRequired": false,
  "RecordMinLinks": 2,
  "RecordMaxValueSize": 1024,
  "RecordMaxTimeDrift": 60
}

Creating 2 genesis records...

{
  "Value": "\b1NRxUEv6TMkj9W1Axhi2q43vIJ4Ym3WPQAyuWhUuDq12mSa8wrMuGTHvHCiaRVAJ4kZ9K4V3814aJDq8ZMTdrnx82rAqoexDkX2yAkn0pAFZBOubxtwcSCxyRz6jEk4V88kceD9eJZoueCdlasXhCcTavZg9St6maiKDMUjCsQB6joAw2eKj6KJmj9T2jLqHpdCv1jDSxbp0EWmg8ZWpQcoAHdPj6l41uqr3NSM2zSRTjPwdU33OzT1XW",
  "Owner": "@ITfjM17BeR3hKXBIboHL47ZCV4BW1LBN",
  "Timestamp": 1559670505,
  "Type": 1,
  "Work": "\bEJCFhkG4wTfl0mjjLxW",
  "WorkAlgorithm": 1,
  "Signature": "\bk8cIwUuEqqO7vkUxmHEJuruVSuguMS2Y9paDVNc01Dipee67nN7bm802AL3847BB0ZgnWqQH3kAQGMoJbnoMoW1gEPEkDsiHzrogrOZZ8Mg0szj2rFEE2cmF6W0A1t3AD"
}

{
  "Owner": "@ITfjM17BeR3hKXBIboHL47ZCV4BW1LBN",
  "Links": ["=Ppgm1j4vlMFMjOMrQlTKl4cy4VOXfgQwAvxB1S9EnSW"],
  "Timestamp": 1559670506,
  "Type": 1,
  "Work": "\bJQtb3wX18tPEPWLnhia",
  "WorkAlgorithm": 1,
  "Signature": "\bLxaUamrKULQ8IJnRngLbflFtysp9CQH73F6vO0Yj8H7Rs942am2HkZTDiNPNjUAwFEdVrFWXsH8hvNIJV3vO9QDchQhN6lOlQCpPEpfwXFgKlbdNbBZpIepIoBSrWlqc"
}
```

In addition to the above output the files `genesis.lf` and `genesis.go` will be saved in the current directory. If you place `genesis.lf` in a new node's home directory *before* starting it, it will join that network instead of the default. The `genesis.go` file just contains the genesis records as a Go byte array literal for inclusion in the code and you can safely delete it.

If you listed any amendable fields or created any certificates the private keys for those will also be saved as .pem files in the current directory. Keep these somewhere safe.

LF peers will not talk to one another if they aren't members of the same network. This is accomplished by cryptographic means using the network's unique 256-bit ID as a pre-shared key. Beyond this simple mechanism there is no system built into LF to control node access over the network. It's the responsibility of those running private networks to secure them by (for example) running them only over ZeroTier virtual networks instead of over the public Internet.

## Certificate Authorities and Owner Authorization

Networks can have certificate authorities (CAs) capable of issuing certificates to owners to authorize them to add records to the network without "paying" via proof-of-work. Signed owners are also given priority in conflict resolution via the default trust estimation algorithm. Private database instances can be created that always require certificates and do not accept records from unauthorized owners.

The certificate mechanism is based around the same x509 public key infrastructure employed by SSL. When a network is created its genesis records can contain root certificate authorities. These CAs can sign owner authorization certificates or intermediate CA certificates that can then be used to authorize owners.

### Authorizing an Owner

*NOTE: right now only p224 and p384 type owners can be signed as Go's x509 implementation does not yet support EDDSA (ed25519) type public keys. Once this support is added we'll add owner signature support for ed25519 type owners.*

Authorization of an owner requires one to possess a CA private key, so users will only be able to do this on private database instances they have created using `makegenesis` as described above.

The first step involves generating a certificate signing request (CSR) with `lf owner makecsr <owner name>`. The command line client will ask a few questions similar to those asked by the `openssl` command when making CSRs. This CSR can then be sent to the holder of the CA signing keys in a procedure almost identical to the process for getting SSL keys for a web server signed by a web CA.

On the CA side the following command is used to authorize the owner: `lf owner authorize <path to CA private key> <path to owner CSR> <certificate TTL in days>`.

Unlike web SSL servers there is no need to send a certificate back to the owner. LF is a global shared data store and therefore makes use of itself to publish certificates. The authorize command submits a certificate that is stored in LF itself and picked up by all other nodes. This certificate in turn is automatically detected and used when creating or validating records by the signed owner.

You can use the `lf owner status` command to check an owner's signature status. As explained above the default public network has a CA controlled by ZeroTier, Inc. If your CLI is configured to use the public network try this to see a signed owner: `lf owner status @s0ZcB1A9uFId65wS6SRkkko1xZ5e1YnM`.

### Revoking Certificates

CRLs that revoke owner certificates are supported but this capability is not yet exposed in the API or CLI.

Revocation of an owner certificate causes all records relying on this certificate for approval to be effectively deleted. They can't actually be removed from the DAG but they no longer show up in queries.

## Future Work

Our next order of business will be to implement LF as a data backend for ZeroTier roots. Once this happens there will be a release of ZeroTier's core product that will demote our root servers from being the exclusive top-level anchor points of the ZeroTier universe to co-equal root servers alongside any others that users happen to set up.

We'll also be exploring other uses of LF within our own product and service line and other things that can be done with it.

## Contributing

If you find a bug or want to contribute to LF, please feel free to open a pull request!
