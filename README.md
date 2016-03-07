# tls_server
Playing with TLS in Go

Root Cert and Sub Cert are samples generated using the OpenSSL command line tool

This code sample starts a TLS server on localhost:8080, then starts a client and connects through the loopback interface. 
The client verifies the server certificate using sample root ca and sub ca certs and then verifies the hostname.
The server automatically sends the client a gob serialized datastructure with a fake `Security Header` struct.
