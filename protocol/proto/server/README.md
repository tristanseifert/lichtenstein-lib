This directory contains all messages used to communicate with a Lichtenstein server. This includes the messages sent TO the server, as well as its responses.

## Message Types
### Message
Wrapper around all messages sent to/received from the server. This wraps into the message a version number.

### ReqPing
Request sent to the server to check whether it is still alive, aka a ping or heartbeat.
### RespPong
Response to a "ping" request.