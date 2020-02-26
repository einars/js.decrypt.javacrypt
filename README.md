Decoder for JavaCrypt encoder
=============================

This is a script to decode files obfuscated by JavaCrypt javascript encoder. I don't know which tool produces the encrypted files: if you know, please, let me know.

It is a very nice and fun encryptor, using consistency checks and attempting
escape from the debugger: you might want to try unpacking it yourself. There
are two actual samples in the "samples" folder, in case you want to try them
out yourself.

The "v1" is an older version of encryption, e.g it has problems running under Chrome — those are later fixed in the v2 by the unknown authors of the unknown tool.


## Browser/web

<del>Open [spicausis.lv/js.decrypt.javacrypt](https://spicausis.lv/js.decrypt.javacrypt/).</del>


## PHP

``` php
require_once('js.decrypt.javacrypt.php');
$decrypted = decrypt_javacrypt($encrypted);
```

The function will just return false if it can't determine packer — or if the unpacked results seem way off.


## Command-line

You may run the script from the command-line using the php interpreter:

``` shell
php js.decrypt.javacrypt.php encrypted_file.js
```


## Future

It might be neat to rewrite the decoder to javascript and add its support to jsbeautifier.org.
