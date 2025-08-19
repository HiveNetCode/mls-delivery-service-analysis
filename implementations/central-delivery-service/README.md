# Central Delivery Service

Proof-of-concept of a centralized Delivery Service.

The Delivery Service implements a simple protocol describe below:

The server accepts the following types of messages:

* `ClientSubscribe`: allows a client to subscribe to message related to one of its KeyPackages. This is meant for the client to receive Welcome messages from other members through the Delivery Service.
* `SendMessage`: allows a client to send a message to a given client. This is primarly used to send Welcome messages to identified users.
* `GroupSubscribe`: allows a client to subscribe to messages sent in the context of an MLS Message.
* `BroadcastMessage`: allows a client to broadcast a message to a given MLS Group, through the Delivery Service.
