```
Usage: ./redis_ssh.rb [options]
    -h, --host HOST                  Victim
    -p, --port PORT                  Port (default: 6379)
    -v, --[no-]verbose               Run verbosely
    -t, --timeout TIME               Time to wait for packets (default: 1)
    -u, --user USER                  User to try and compromise
    -d, --dir DIR                    .ssh directory to use
    -s, --sshport PORT               Port to ssh to (default: 22)
    -c, --check                      Run a vulnerability check
    -i, --info                       Print info about a redis server
        --help                       Print this help
```