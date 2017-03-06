# php-bin\_prot

## Introduction

This extension provides bindings to the [libbin\_prot](https://github.com/andrenth/libbin_prot)
library, allowing usage of [bin\_prot](https://github.com/janestreet/bin_prot)
serialization from PHP scripts.
PHP version 5.3 or newer are supported, including PHP 7.

## Installation

You can build php-bin\_prot by typing `make` and install it with `make install`
(likely with `sudo` in front of the latter).

You can also build a `deb` package (tested on Ubuntu 16.04) with `make deb`.
If you need a package for Ubuntu 12.04, use `make deb-precise`.

## Usage

Serialization and RPC functions live in their own namespace: `\bin_prot\read`
for readers, `\bin_prot\write` for writers, `\bin_prot\size` for sizers,
`\bin_prot\rpc` for RPC and `\bin_prot\type_class` for type classes.

All functions raise an exception on error.

### Readers

Readers live in the `\bin_prot\read` namespace and are of the form below:

```php
array bin_read_<type>(string $buf, int $pos)
```

meaning the appropriate type will be read from buffer `$buf` at position `$pos`.
The return value from read functions is always a two-element array where the
first element is the unserialized data read from the buffer, and the second
element is the updated position to be used in further reads.

### Writers

Writers live in the `\bin_prot\write` namespace and are of the form below:

```php
int bin_write_<type>(string $buf, int $pos, <type> $val)
```

This writes the value `$val`, which is expected to be of the correct type for
a given writer, into buffer `$buf` at position `$pos`. Writers return an updated
position, to be used in further writes.

### Sizers

Sizers live in the `\bin_prot\size` namespace and are of the form below:

```php
int bin_size_<type>(<type> $val)
```

They return the size in bytes of the value `$val`, which is expected to be of
the correct type for the given sizer.

### Type classes

Type classes are implemented in pure PHP, so to use them you must do something
like

```php
require_once('bin_prot/type_class.php');
```

Type classes are classes whose instances contain a reader, a writer and a sizer
for each type. They are mostly useful as query and response arguments to the
`\bin_prot\rpc\bin_rpc_create` function.

To obtain a type class, simply instantiate the appropriate class:

```php
$my_type_class = \bin_prot\type_class\bin_<type>();
```

replacing `<type>` with the type you want.

### Higher order readers, writers and type classes.

Serialization functions for container types such as arrays, hash tables or
tuples take one or more extra arguments which specify readers, writers or sizers
for the elements of the container.

For example, for hash tables (associative arrays in PHP), the reader function
look like this:

```php
array bin_read_hashtbl(callable $read_key, callable $read_value, string $buf,
                       int $pos)
```

so to read an associative array that maps strings to integers, one would call

```php
list($assoc, $pos) = \bin_prot\read\bin_read_hashtbl('\bin_prot\read\string',
                                                     '\bin_prot\read\int',
                                                     $buf, $pos);
```

Writers and sizers are analogous. To instantiate a hash table type class, pass
the appropriate key and value type classes to the constructor:

```php
$bin_hashtbl =
  \bin_prot\type_class\bin_hashtbl('\bin_prot\type_class\bin_string',
                                   '\bin_prot\type_class\bin_int');
```

### RPC

An RPC client can be built by calling the three functions provided in the
`\bin_prot\rpc` namespace:

```php
resource bin_rpc_create(string $tag, int $ver,
                        type_class $bin_query, type_class $bin_response)
```

This function returns an RPC resource for the call identified by `$tag` with
version `$ver`, with queries serialized by the `$bin_query` type class and
responses serialized by the `$bin_response` type class.


```php
resource bin_rpc_client(resource $sock, string $descr)
```

This function takes a connected socket `$sock` and a description `$descr` and
returns an RPC connection resource.


```php
mixed bin_rpc_dispatch(resource $rpc, resource $conn, mixed $query)
```

This function takes an RPC resource, an RPC connection resource and a query
and returns the RPC server response.

An example of RPC usage can be found in the `examples` directory, which includes
an OCaml RPC server and a PHP RPC client. The server can be built with
`make examples` in the repository root.
