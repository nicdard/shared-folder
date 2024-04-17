# Baseline

Idea: implement 2 baselines, one without CGKA and one with CGKA.

## Asymmetric encryption per user baseline

In this baseline implementation we will not make use of a group key agreement protocol.

We assume the existance of a PKI. 
We further assume we have the pk of the CA bundled into the application.
This choice is made so that we still perform validation, but we do not account for network in our benchmarking. Also this simplification is made to have our project
sized for 6 months.
Each user is therefore represented as a couple of asymmetric keys (`sk_u1`, `pk_u1`).
Each file has an associated encryption key (`k_f1`, `k_f2`...), used to perform symmetric encryption on the file.
All of those file encryption keys are encrypted under a shared key `K_f`. 
The shared key is saved and shared by encrypting it with asymmetric encryption for each user using its `pk`. 
All of the encrypted key material could be stored in the shared folder metadata.

Server storage:

```
{K_f}pk_A,pk_B
 |
 |--------------- ...
 |       |
{k_f1} {k_f2} ...
 |
 | symmetric encryption
{f1}k_f1
```

As an high level architecture, the Authentication Service (AS) will be implemented using the [X.509](https://datatracker.ietf.org/doc/html/rfc5280) certificates standard. We assume certificates that never expire.
The storage server will be based on the Amazon Simple Storage Service (S3). 
We will use a public bucket to store the objects as we are not interested in enforcing ACL through the server provided mechanisms.
Although protecting access from the public could be relevant in a real setting (TODO: maybe discuss how to implement if there is time?). 
Furthermore, the security property of this baseline as well as the ones for the SSF scheme do not depend on the storage being publicly readable or writable.
Availability is out of scope for the SSF and thus should also for the baselines.

Clarify:
1. We do not assume a notification system for the time being or any form of messaging in the baseline, the communication is kept as simple as possible. In this case the assumption is that a user can just use any other form of communication to share the bucket and the folder name with the other client.
2. Another possible solution would be to implement a kind of Delivery Service (DS) to notify users that they are added to a new folder.

Clients:

The client will register itself in the file sharing system. It will also create it's credentials in the X.509 format to do so.

A client which wants to share one of its folder can just encrypt the `K_f` under the pk of the other user client. Then it can notify the other user sending the bucket name and the folder name within the url of the shared folder.


## CGKA baseline

In this more sophisticated version of the baseline, the clients will run a CGKA to agree on a shared key for the group.
From this key they derive a `K_f` as above, which is used to encrypt the file keys (`k_f1`, `k_f2`, ...).

As in MLS, this baseline requires an AS and a DS to run. The AS will again use X.509 PKI.
For the DS we will instead need to write a base implementation similar to the one provided in [openmls library](https://github.com/openmls/openmls/tree/main/delivery-service). The design would be characterised as follows:
* The DS does not know about groups.
* Clients have to send a list of clients (group members) along with each message for the DS to know where to send the message.
* The DS stores and delivers key packages.

Diversely from the cited implementation, the DS will perfom authentication for clients as required in CGKA.


## On X509 certificates

OpenMLS doesn't support this type of credentials as of now (only basic credential types).

aws/mls-rs library seems to support them but not for the WebAssembly target.

Some resources:
* [Using WebCrypto apis to deal with X.509 certificates](https://blog.engelke.com/2014/10/21/web-crypto-and-x-509-certificates/)
* https://github.com/digitalbazaar/forge?tab=readme-ov-file#x509
* https://docs.rs/x509-certificate/0.23.1/x509_certificate/
* https://github.com/briansmith/webpki

Create X.509 cretificates for testing:
* https://github.com/rustls/rcgen/blob/main/rcgen/examples/rsa-irc-openssl.rs
* https://docs.rs/x509-certificate/0.23.1/x509_certificate/

## Miscellaneus
* https://crates.io/crates/zeroize/1.7.0
