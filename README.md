# scan

An IPv4 and IPv6 TCP port scanner in C.

[![Build Status](https://travis-ci.org/keithnoguchi/scan.svg)](https://travis-ci.org/keithnoguchi/scan)

[![asciicast](https://asciinema.org/a/48492.png)](https://asciinema.org/a/48492)

## How to build

```
$ ./configure && make
```

## How to run

```
$ sudo ./scan localhost
```

We need to be as root for RAW socket.

## How to test

```
$ make test
```

## How to play asciicast locally

```
$ asciinema play scan.json
```

Happy hacking!
