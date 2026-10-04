# Wicket Fund — draft application (English)

Local file. It lives in `documents/`, and that folder is in `.gitignore`. Do not commit it.

Send the text below by email to apply@wicketfund.org.
Wicket Fund pays grants in Bitcoin. The amount is given in euros as the equivalent they asked for.
The letter is longer than one page because the 100000 euro figure is itemised. Do not attach the NLnet form.

---

To: apply@wicketfund.org
Subject: Grant application — VOID delivery protocol

Project name: VOID delivery protocol

VOID is an open protocol for accountless delivery between peers, plus a desktop application that already runs on it. The repository holds both. The protocol is the stream rules and frames under `src/`. The application is the Tauri desktop (Windows, Linux, macOS) that speaks those rules. Identity is a key on the device, not an account. A replaceable dispatcher forwards opaque bytes and stores a sealed offline envelope. It cannot read the message. It still sees addresses, sizes, timing, and, today, a stable sender on the envelope. This is not Tor and not a mix network. Status is alpha. One person maintains the only endpoint and the only dispatcher.

Repository: https://github.com/MarshalV/p2p-messenger
Reference dispatcher: https://github.com/MarshalV/bootstrap_node

What the grant would fund is the protocol contract, not a new chat window. Author time is 2400 hours at 30 euro per hour (72000 euro), about 18 months at 30 hours a week. One outside contract is 28000 euro. Total 100000 euro.

The first 45000 euro makes the protocol readable by someone else:

1. Normative specification of the streams already implemented (signed hello, session frames, offline envelope, discovery that does not store chat text, dispatcher reservation, seed exchange between dispatchers, onion wrapper and its limits). 400 hours, 12000 euro. Text under CC BY 4.0.
2. Rust libraries with no user interface: frames, session, envelope seal, onion wrap. The existing desktop becomes one consumer. 500 hours, 15000 euro.
3. Machine-readable test vectors and a two-process harness with no graphical interface, so a second implementation can follow the specification alone. 300 hours, 9000 euro.
4. An envelope a dispatcher can expire and hand over without a stable cleartext sender, plus a written list of the metadata that remains. 300 hours, 9000 euro. This will not be described as anonymity.

The remaining 55000 euro is what those four tasks do not buy. A specification of an unaudited custom session is still one person's composition. A single dispatcher binary is still a single point a censor can block.

5. Independent review, contracted out, of the signed hello, the Double Ratchet and its skipped-key cap, the envelope seal, the onion wrapper, and the written threat model. 28000 euro. I will not review my own cryptography and call it done.
6. My time to answer that review and land the agreed fixes. 200 hours, 6000 euro.
7. A second dispatcher written only from the specification, plus a signed list of dispatcher addresses, so a client can switch when one operator is blocked without taking a new address from an unsigned webpage. 400 hours, 12000 euro.
8. A size policy for the envelope and the onion wrapper, with test vectors, so packet length reveals less. This is not a mix network and will not be described as one. 200 hours, 6000 euro.
9. Reproducible builds and signed tags for the libraries and both dispatchers, so a third party can check the binary against the source. 100 hours, 3000 euro.

Group encryption and interface work stay out of scope. Groups today are pairwise fan-out. The specification will say so. No travel. No equipment. The review contract is the only payment to someone other than me.

Requested amount: 100000 euro, paid in bitcoin at the rate you use when the grant is sent.

Background: I am the author and sole maintainer of both repositories, GitHub handle MarshalV. I wrote the stream names, the signed hello, the session, the offline envelope, the dispatcher, and the desktop application that runs them. There is no second maintainer and no external cryptographic review yet. The grant is to make that contract readable and testable without me in the room.

Licence: code is MIT. The specification produced under this grant will be CC BY 4.0.
