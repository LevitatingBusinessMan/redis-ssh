# REDIS-SSH
This script attempts to exploit unauthenticated redis servers by writing a public key to .ssh/authorized_keys.

```
Usage: ./redis_ssh.rb [options]
    -h, --host HOST                  Victim (required)
    -p, --port PORT                  Port (default: 6379)
    -v, --[no-]verbose               Run verbosely
    -t, --timeout TIME               Time to wait for packets (default: 1)
    -u, --user USER                  Force specific user
    -d, --dir DIR                    Force specific directory
    -s, --sshport PORT               Port to ssh to (default: 22)
    -c, --check                      Run a vulnerability check
    -i, --info                       Print info about a redis server
        --help                       Print this help
```
