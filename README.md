
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

Build the CTIDH C shared library files:

```
cd high-ctidh-20210523
patch -p1 < ../autogen-memoized.patch
./autogen
make libhighctidh_511.so libhighctidh_512.so libhighctidh_1024.so libhighctidh_2048.so
cd ..
```


Step 3
------

Build your Go application. I've templatized binding.h with jinja2. All
it does is replace a named token with the selected CTIDH public key
bit size; below we refer to this with the bash environment variable
${CTIDH_BITS}. Firstly, install the jinja2 cli tool:

```
pip install jinja2-cli
```

The build process doesn't lend itself to using `go generate` because
of all the bash environment variables.

In order to run the unit tests or build a Go project against this
library you'll have to set the CGO CFLAGS and LDFLAGS to indicate the
absolute path to the library and header files. Here's an example using
the LD_LIBRARY_PATH environment variable:

```
export CTIDH_BITS=512
jinja2 -D CTIDH_BITS=${CTIDH_BITS} binding.h.j2 -o binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -l:libhighctidh_${CTIDH_BITS}.so"
export LD_LIBRARY_PATH="${PWD}/high-ctidh-20210523"
go test -v
```

It's also possible to compile your cgo binary using a set rpath which
instructs it to load libraries from a relative path instead of setting
LD_LIBRARY_PATH:

```
export CTIDH_BITS=512
jinja2 -D CTIDH_BITS=${CTIDH_BITS} binding.h.j2 -o binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_${CTIDH_BITS}"
go test -v
```

Here's trying different public key sizes:

```
export CTIDH_BITS=1024
jinja2 -D CTIDH_BITS=${CTIDH_BITS} binding.h.j2 -o binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_${CTIDH_BITS}"
go test -v
```

```
export CTIDH_BITS=2048
jinja2 -D CTIDH_BITS=${CTIDH_BITS} binding.h.j2 -o binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_${CTIDH_BITS}"
go test -v
```


License
=======

This is public domain.
