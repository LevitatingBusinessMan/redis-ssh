# REDIS-SSH
This script attempts to exploit unauthenticated redis servers by writing a public key to .ssh/authorized_keys.
It should work on any server serving Redis publicly, persistent and unauthenticated as a user with a .ssh directory.
It only requires a host and appropiate ports to run.

```
Usage: ./redis_ssh.rb [options]
    -h, --host HOST                  Victim (required)
    -p, --port PORT                  Port (default: 6379)
    -v, --[no-]verbose               Run verbosely
    -t, --timeout TIME               Time to wait for packets (default: 1)
    -u, --user USER                  Force specific user
    -d, --dir DIR                    Force specific .ssh directory
    -s, --sshport PORT               Port to ssh to (default: 22)
    -c, --check                      Run a vulnerability check
    -i, --info                       Print info about a redis server
    -e, --stealth                    Restore configuration to stay hidden
        --help                       Print this help
```
