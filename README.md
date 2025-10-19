# E2EEClientWithServer
Basic working example of a E2EE client with a server that they can communicate through.

It uses RSA encryption (from OpenSSL library) and TCP to send data. When you first log in as a certain nickname into the client app, it will create a pair of keys for you and store them as files. When you send a message to someone, it asks the receiver for their public key, and then stores it in a file, so this procedure is only needed once, even if you reopen the app. All communication between clients is performed by the server, which, however, does not implement any ecnryption/decryption code and only routes data to its receiver.

The server is deliberately compromised and prints out all that passes through it (to show it reads gibberish instead of messages):). It has access to public keys that are sent through it, but they can only be used to encrypt data and don't give access to the messages.

The client project uses CMake to make linking easier, the server is much simpler and uses direct linking with #pragma for winsock2. Both are for Windows, but it wouldn't be hard to add a number of changes to make this multiplatform.
