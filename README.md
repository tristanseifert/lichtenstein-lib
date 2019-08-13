# liblichtenstein
A collection of libraries to make working with the [Lichtenstein client](https://github.com/tristanseifert/lichtenstein-client) and [server](https://github.com/tristanseifert/lichtenstein-server) easier.

## libLichtensteinProto
This static library contains the C++ class definitions of all messages in use by the Lichtenstein protocol. This is used internally to implement the protocol on the server and official clients.

Your program probably doesn't need to link against this library; consider the client library instead.

## libLichtensteinClient
Dynamic library containing a full implementation of a Lichtenstein client. This handles network communication with a server, exposing a control API for this server, and advertising on the local network via mDNS.

This API is exposed as a simple C++ class that only requires some minor configuration, and will then forward all events to user-specified callbacks.

Internally, this will start several threads that handle network communication, so you will need to take care to properly release resources once you're done with them. Note that to use TLS, you will need to link with OpenSSL.

## libLichtensteinClientControl
Provides a simple C++/C interface to send commands to a running local Lichtenstein client instance, as implemented by libLichtensteinClient.

This can be used by scripts running locally to affect the client, for maintenance purposes, for example.
