
What is this?
=============

CGO Go bindings to the CTIDH reference implementation.
CTIDH is a post quantum cryptographic primitive called a NIKE,
a noninteractive key exchange.

Learn more about CTIDH: https://ctidh.isogeny.org/


Build
=====

Step 1
------

Get the latest CTIDH reference implementation from it's canonical source:

https://ctidh.isogeny.org/

For example:

```
wget -m https://ctidh.isogeny.org/high-ctidh-latest-version.txt
version=$(cat ctidh.isogeny.org/high-ctidh-latest-version.txt)
wget -m https://ctidh.isogeny.org/high-ctidh-$version.tar.gz
tar -xzf ctidh.isogeny.org/high-ctidh-$version.tar.gz
```

Step 2
------

Build the CTIDH C shared library:

```
cd high-ctidh-20210523$
patch -p1 < ../ctidh-shared-library-000.patch
./autogen
make libhighctidh_512.so
cd ..
```

Step 3
------

Build your Go application. This also demonstrates how to run the unit tests:

In order to run the unit tests or build a Go project against this library
you'll have to set the CGO CFLAGS and LDFLAGS to indicate the absolute path
to the library and header files. Here's an example using the LD_LIBRARY_PATH
environment variable:

```
export CGO_CFLAGS="-g -I/home/human/code/ctidh_cgo/high-ctidh-20210523 -DBITS=512"
export CGO_LDFLAGS="-L/home/human/code/ctidh_cgo/high-ctidh-20210523 -l:libhighctidh_512.so"
export LD_LIBRARY_PATH="/home/human/code/ctidh_cgo/high-ctidh-20210523"
go test -v
```

It's also possible to compile your cgo binary using a set rpath which
instructs it to load libraries from a relative path instead of setting
LD_LIBRARY_PATH:

```
export CGO_CFLAGS="-g -I/home/human/code/ctidh_cgo/high-ctidh-20210523 -DBITS=512"
export CGO_LDFLAGS="-L/home/human/code/ctidh_cgo/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_512"
go test -v
```


License
=======

This is public domain.
