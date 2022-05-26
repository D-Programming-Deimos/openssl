# sslecho: A simple echo server

This example was ported from [the official OpenSSL repository](https://github.com/openssl/openssl/tree/ef8040bce02758de86fc55412ee4ac9102f9ffab/demos/sslecho).
The certificates can be generated using:
```shell
openssl req -batch -newkey rsa:4096 -x509 -sha256 -days 3650 -subj "/C=FR/CN=localhost" -nodes -out cert.pem -keyout key.pem
```
And 'localhost' was used as domain.

The server and client need to be called with the following commands (respectively):
```shell
$ ./sslecho s # Starts the server
$ ./sslecho c localhost
```
Note that using `127.0.0.1` will not work.