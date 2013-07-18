JavaCrypt decoder
==================

This is script to unpack JavaCrypt javascript encoder, found somewhere in the wild.

It is a very nice and fun encryptor, using consistency checks and attempting
escape from the debugger: you might want to try unpacking it yourself. There
are two actual samples in the "samples" folder, in case you want to try them
out yourself.

The "v1" is an older version of encryption, e.g it has problems running under Chrome — those are later fixed in the v2 by the unknown authors of the unknown tool.


# Usage

## Web

Open [spicausis.lv/js.decrypt.javacrypt](http://spicausis.lv/js.decrypt.javacrypt/).

## PHP

``` php
require_once('js.decrypt.javacrypt.php');
$decrypted = decrypt_javacrypt($encrypted);
```

There aren't any options supported, and the function will just return false if
it can't determine packer or the unpacked results seems way off.

## Command-line

You may run the script from the command-line as well, using the php interpreter, obviously:

``` shell
php js.decrypt.javacrypt.php encrypted_file.js
```

