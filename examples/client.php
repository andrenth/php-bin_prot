<?php

require_once("bin_prot/type_class.php");

use bin_prot\read as read;
use bin_prot\write as write;
use bin_prot\rpc as rpc;
use bin_prot\type_class as type_class;

function incr_rpc($conn)
{
    $bin_int = new type_class\bin_int();
    $rpc = rpc\bin_rpc_create("incr", 0, $bin_int, $bin_int);
    if (!$rpc)
            die("bin_rpc_create\n");

    $ret = rpc\bin_rpc_dispatch($rpc, $conn, 42);
    var_dump($ret);
}

function hello_rpc($conn)
{
    $bin_string = new type_class\bin_string();
    $rpc = rpc\bin_rpc_create("hello-world", 0, $bin_string, $bin_string);
    if (!$rpc)
        die("bin_rpc_create\n");

    $ret = rpc\bin_rpc_dispatch($rpc, $conn, "Hello");
    var_dump($ret);
}

$opts = getopt("p::r:");
$port = array_key_exists('p', $opts) ? $opts['p'] : 8124;

if (!array_key_exists('r', $opts))
    die("need to specify an RPC\n");

switch ($opts['r']) {
case "incr":
    $rpc = 'incr_rpc';
    break;
case "hello":
    $rpc = 'hello_rpc';
    break;
default:
    die("unknown RPC '{$opts['r']}'\n");
}

$sock = socket_create(AF_INET, SOCK_STREAM, 0);
if (!socket_connect($sock, "localhost", $port))
    die("socket_connect: " . socket_last_error($sock) . "\n");

$conn = rpc\bin_rpc_client($sock, "my php client");
if (!$conn)
    die("bin_rpc_client\n");

$rpc($conn);
