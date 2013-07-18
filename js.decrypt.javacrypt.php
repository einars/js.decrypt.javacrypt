<?php

# javacrypt decryptor
# --------------------------------
# written by Einar Lielmanis, 2013
# MIT licence
#
# web: http://spicausis.lv/js.decrypt.javacrypt
# commandline: php js.decrypt.javacrypt.php packed_file
# your own use (why would you?): $decrypted = decrypt_javacrypt($encrypted)
#
# Yes, this might be cool to add to jsbeautifier.org.
# You’re welcome to port this to javascript, should be easy.

if ( ! isset($_SERVER['REQUEST_URI']) and isset($argv[1])) {
    // run from command-line
    echo decrypt_javacrypt(file_get_contents($argv[1]));
}

function decrypt_javacrypt($source)
{
    $decryptor_source = null;
    $encrypted = null;
    $cryptkey = null;

    $quote='["\']';
    $maybe_quote='["\']?';

    if (preg_match('/JavaCrypt\(' . $quote . '([\da-zA-Z]+)' . $quote . ',\s*' 
        . $maybe_quote . '([\da-zA-Z]+)' . $maybe_quote . '\)/', $source, $matches)) {
        $encrypted = $matches[1];
        $cryptkey = $matches[2];
    }
    if (preg_match('/(func' . 'tion JavaC.*?;return;})/', $source, $matches)) {
        $decryptor_source = $matches[1];
    }

    if ( ! $decryptor_source or ! $encrypted or ! $cryptkey) return false;

    if (strpos($decryptor_source, '\\x2f\\x2a\\x2a\\x2f') === false) {
        $version = 'v1';
    } else {
        $version = 'v2';
    }

    $cryptkey = (int)($cryptkey & 0xffffffff);


    $table = array();
    for ($w = 0; $w < 256; $w++) {
        $a = $w;
        for($y = 8; $y > 0; $y--) {
            $x = ($a & 1) ? 0xedb88320 : 0;
            if ($version === 'v1') $a = ($a >> 1) ^ $x;
            if ($version === 'v2') $a = rsh($a, 1) ^ $x;
        }
        if ($version === 'v1') $table[ $w ] = $a;
        if ($version === 'v2') $table[ $w ] = sgn_normalize($a);
    }

    $caller_source = $decryptor_source;

    for ($iteration = 0; $iteration < 6; $iteration++) {

        $initial_cryptkey = $cryptkey;
        $caller_source = preg_replace('/\s+/', '', $caller_source);
        $caller_source = str_replace('"', '', $caller_source);
        $caller_source = str_replace('anonymous', '', $caller_source);
        $caller_source = str_replace('});r', '}));r', $caller_source);
        $caller_source = str_replace('n;})', 'n;}', $caller_source);

        $caller_source = str_replace('/**/', '', $caller_source);


        if ($version == 'v2') {
            $caller_source = str_replace('func' . 'tionJ', 'func' . 'tion J', $caller_source);
            $caller_source = str_replace("\x0a", '', $caller_source);
        }

        for ($w = 0; $w < strlen($caller_source); $w += 2) {
            $cryptkey = ($cryptkey >> 8) ^ $table[ ($cryptkey ^ ord($caller_source[$w])) & 255 ];
        }

        if ($version == 'v1') $cryptkey = $cryptkey ^ 0xffffffff;
        if ($version == 'v2') $cryptkey = sgn_normalize($cryptkey ^ 0x7ffffffe);

        $caller_source = sprintf('fun' . 'ction(%s){%s}'
            , $iteration == 0 ? 'obj' : sprintf('f%x', $initial_cryptkey)
            , substr(
                $decryptor_source,
                $start = strpos($decryptor_source, 'arguments'),
                strpos($decryptor_source, 'return') + 7 - $start
            ));
    }

    $cryptkey = sprintf('%08X', $cryptkey);

    $sog = array();
    for($i = 0; $i < 8; $i++) {
        $sog[$i] = ord($cryptkey[$i]);
    }
    $output = '';
    $output_h = '';

    $looks_good = true;
    for($i = 0, $a = 0; $i < strlen($encrypted); $i += 2) {
        $snip = substr($encrypted, $i, 2);
        $aw = hexdec($snip) - $sog[$a];
        if ($aw < 0) $aw += 256;
        if ($aw > 256) $aw -= 256;
        $output .= chr($aw);
        if ($aw < 32 and $aw != 10 and $aw != 13 and $aw != 9) {
            $looks_good = false;
        }
        $a = ($a + 1) % 8;
    }

    if ( ! $looks_good) {
        return false;
    } else {
        return $output;
    }

}


function rsh($a, $n)
{
    // alt. 32-bit shift right, keeping sign
    return ($a >> 1) | ($a & 0x80000000);
}

function sgn_normalize($n)
{
    if ($n & 0x80000000) {
        return ($n & 0x7fffffff) - 1;
    } else {
        return $n;
    }
}
