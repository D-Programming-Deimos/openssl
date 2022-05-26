/// https://github.com/openssl/openssl/tree/master/demos/sslecho
module app;

import core.stdc.stdio;
import core.sys.posix.netinet.in_;
import core.sys.posix.stdio : getline;
import core.sys.posix.unistd;

import std.algorithm : startsWith;
import std.stdio : write, writeln, writefln;

import deimos.openssl.opensslv;
import deimos.openssl.err;
import deimos.openssl.ssl;

const ushort server_port = 4433;

int create_socket(bool isServer)
{
    int optval = 1;
    sockaddr_in addr;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        return -1;
    }

    if (!isServer)
        return s;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* Reuse the address; good for quick restarts */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, optval.sizeof) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    if (bind(s, cast(sockaddr*) &addr, addr.sizeof) < 0) {
        perror("Unable to bind");
        return -1;
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        return -1;
    }

    return s;
}

private int usage()
{
    writeln("Usage: sslecho s");
    writeln("       --or--");
    writeln("       sslecho c ip");
    writeln("       c=client, s=server, ip=dotted ip of server");
    return 1;
}

int main(string[] args)
{
    int result;

    /* used by getline relying on realloc, can't be statically allocated */
    // char *txbuf = NULL;
    // size_t txcap = 0;
    // int txlen;

    // struct sockaddr_in addr;
    // unsigned int addr_len = sizeof(addr);

    /* Splash */
    writefln("sslecho : Simple Echo Client/Server (OpenSSL %s): %s %s",
             OpenSSLVersion.text, __DATE__, __TIME__);

    /* Need to know if client or server */
    if (args.length < 2)
        return usage();

    if (const isServer = args[1].startsWith('s'))
        return runServer();

    /* If client get remote server address (should be localhost) */
    if (args.length != 3)
        return usage();

    const remote_server_ip = args[2];
    return runClient(remote_server_ip);
}

private int runServer (ushort port = server_port)
{
    char[256] buffer;
    int       result;

    writeln("We are the server on port: ", port);

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx is null)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    scope (exit) SSL_CTX_free(ctx);

    /* Configure server context with appropriate key files */
    if (SSL_CTX_use_certificate_chain_file(ctx, "cert.pem".ptr) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem".ptr, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Create server socket; will bind with server port and listen */
    int server_skt = create_socket(true);
    if (server_skt < 0) return 1;
    scope (exit) close(server_skt);

    /*
     * Loop to accept clients.
     * Need to implement timeouts on TCP & SSL connect/read functions
     * before we can catch a CTRL-C and kill the server.
     */
    while (true) {
        /* Wait for TCP connection from client */
        sockaddr_in addr;
        socklen_t addr_len = sockaddr_in.sizeof;
        int client_skt = accept(server_skt, cast(sockaddr*) &addr, &addr_len);

        if (client_skt < 0) {
            perror("Unable to accept");
            return 1;
        }

        writeln("Client TCP connection accepted");
        scope (exit) close(client_skt);

        /* Create server SSL structure using newly accepted client socket */
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_skt);
        scope (exit) {
            /* Cleanup for next client */
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

        /* Wait for SSL connection from the client */
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }

        writeln("Client SSL connection accepted");

        /* Echo loop */
        while (true) {
            /* Get message from client; will fail if client closes connection */
            if ((result = SSL_read(ssl, buffer.ptr, buffer.length)) <= 0) {
                if (result == 0) {
                    writeln("Client closed connection");
                }
                ERR_print_errors_fp(stderr);
                break;
            }

            const rcvd = buffer[0 .. result];
            /* Look for kill switch */
            if (rcvd == "kill\n") {
                /* Terminate...with extreme prejudice */
                writeln("Server received 'kill' command");
                return 0;
            }
            /* Show received message */
            writefln("Received %s bytes:", rcvd.length);
            write(rcvd);
            /* Echo it back */
            if (SSL_write(ssl, rcvd.ptr, result) <= 0) {
                ERR_print_errors_fp(stderr);
            }
        }
    }
    writeln("Server exiting...");
    return 0;
}

private int runClient (string remote)
{
    char[256] buffer;
    writeln("We are the client");

    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx is null)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    scope (exit) SSL_CTX_free(ctx);

    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem".ptr, null)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* Create "bare" socket */
    int client_skt = create_socket(false);
    if (client_skt < 0) return 1;
    scope (exit) close(client_skt);

    /* Set up connect address */
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    // Note: The runtime ensures that `args` are `\0` terminated
    inet_pton(AF_INET, remote.ptr, &addr.sin_addr.s_addr);
    addr.sin_port = htons(server_port);
    /* Do TCP connect with server */
    if (connect(client_skt, cast(sockaddr*) &addr, addr.sizeof) != 0) {
        perror("Unable to TCP connect to server");
        return 1;
    }
    writeln("TCP connection to server successful");

    /* Create client SSL structure using dedicated client socket */
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_skt);
    scope (exit)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    /* Set host name for SNI */
    SSL_set_tlsext_host_name(ssl, remote.ptr);
    /* Configure server hostname check */
    static if (OPENSSL_VERSION_AT_LEAST(1, 1, 0))
        SSL_set1_host(ssl, remote.ptr);

    /* Now do SSL connect with server */
    if (SSL_connect(ssl) != 1) {
        writeln("SSL connection to server failed");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    writeln("SSL connection to server successful");

    /* Loop to send input from keyboard */
    while (true) {
        /* Get a line of input */
        auto len = buffer.length;
        auto pptr  = buffer.ptr;
        ssize_t txlen = getline(&pptr, &len, stdin);

        /* Exit loop on error */
        if (txlen < 1 || pptr is null)
            break;
        /* Exit loop if just a carriage return */
        if (buffer[0] == '\n')
            break;
        assert(txlen <= int.max);

        /* Send it to the server */
        auto result = SSL_write(ssl, buffer.ptr, cast(int) txlen);
        if (result <= 0) {
            writeln("Server closed connection");
            ERR_print_errors_fp(stderr);
            break;
        }

        /* Wait for the echo */
        auto rxlen = SSL_read(ssl, buffer.ptr, cast(int) buffer.length);
        if (rxlen <= 0) {
            writeln("Server closed connection");
            ERR_print_errors_fp(stderr);
            break;
        }
        /* Show it */
        writefln("Received %s bytes (sent: %s bytes):", rxlen, txlen);
        writeln(buffer[0 .. rxlen]);
    }
    writeln("Client exiting...");
    return 0;
}
