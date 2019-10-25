# scan

An epoll(7) based single threaded IPv4 and IPv6 TCP/UDP port scanner in C.

[![Build Status](https://travis-ci.org/keithnoguchi/scan.svg)](https://travis-ci.org/keithnoguchi/scan)

[![asciicast](https://asciinema.org/a/48492.png)](https://asciinema.org/a/48492)

## Build

```
$ ./configure && make
```

## Test

```
$ make test
```

## Execution

```
$ sudo ./scan localhost
```

You need to be root, as `scan` uses the raw socket to the packet handling.

## ASCII cast

```
$ asciinema play scan.json
```

Happy hacking!
