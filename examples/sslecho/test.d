/// Runs the server and the client in a fork for CI
module test;

import core.thread;
import core.time;

import std.process;
import std.stdio;

int main ()
{
    auto serverPid = spawnProcess([ "./sslecho", "s" ]);
    writeln("Server has been spawned");
    Thread.sleep(3.seconds);
    auto clientPid = spawnShell(`echo "Hello World\nkill" | ./sslecho c localhost`);
    writeln("Client has been spawned");
    Thread.sleep(3.seconds);

    if (auto res = clientPid.wait())
        return res;
    if (auto res = serverPid.wait())
        return res;

    return 0;
}
