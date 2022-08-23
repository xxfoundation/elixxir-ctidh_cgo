
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

Build your Go application.

I've created several header files one for each key size: binding511.h, binding512.h, binding1024.h and binding2048.h
You'll have to copy one of these to `binding.h`. Below the bash examples
do it like this:

```
export CTIDH_BITS=512
cp binding${CTIDH_BITS}.h binding.h
```

In order to run the unit tests or build a Go project against this
library you'll have to set the CGO CFLAGS and LDFLAGS to indicate the
absolute path to the library and header files. Here's an example using
the LD_LIBRARY_PATH environment variable:

```
export CTIDH_BITS=512
cp binding${CTIDH_BITS}.h binding.h
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
cp binding${CTIDH_BITS}.h binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_${CTIDH_BITS}"
go test -v
```

benchmarks
----------

Benchmark the DeriveSecret function for each public key size:

```
VALID_BIT_SIZES=('511' '512' '1024' '2048')
for bits in "${VALID_BIT_SIZES[@]}"
do
export CTIDH_BITS=$bits
cp binding${CTIDH_BITS}.h binding.h
export PWD=`pwd`
export CGO_CFLAGS="-g -I${PWD}/high-ctidh-20210523 -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${PWD}/high-ctidh-20210523 -Wl,-rpath,./high-ctidh-20210523 -lhighctidh_${CTIDH_BITS}"
go test -bench=DeriveSecret
done

```


License
=======

This is public domain.
