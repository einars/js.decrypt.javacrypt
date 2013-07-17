<?php


$config = array();
require_once('/services/web/localhost/rabbid/rabbid.php');

$lines = file($argv[1]);
$callersource = null;

$encrypted = null;
$cryptkey = null;
foreach($lines as $line) {
    $quote='["\']';
    $maybe_quote='["\']?';
    if (preg_match('/JavaCrypt\(' . $quote . '([\da-zA-Z]+)' . $quote . ',\s*' . $maybe_quote . '([\da-zA-Z]+)' . $maybe_quote . '\)/', $line, $matches)) {
        $encrypted = $matches[1];
        $cryptkey = $matches[2];
    }
    if (preg_match('/(func' . 'tion JavaC.*return;})/', $line, $matches)) {
        $callersource = $matches[1];
    }
}

printf("enclen: %d, cryptkey: %s, sourcelen=%d\n"
    , strlen($encrypted)
    , $cryptkey
    , strlen($callersource)
);

file_put_contents('o.callersource', $callersource);

$struct = (object)array(
    'encrypted' => $encrypted,
    'cryptkey' => (int)($cryptkey & 0xffffffff),
    'orig_source' => $callersource,
    'callersource' => $callersource,
    'sog' => array(),
    'iteration' => 0,
    'version' => 'v1',
);

if (strpos($callersource, '\\x2f\\x2a\\x2a\\x2f') !== false) {
    $struct->version = 'v2';
}

iterate($struct);
iterate($struct);
iterate($struct);
iterate($struct);
iterate($struct);
iterate($struct);

$cryptkey = sprintf('%08X', $struct->cryptkey);
$sog = array();
for($i = 0; $i < 8; $i++) {
    $sog[$i] = ord($cryptkey[$i]);
}
$output = '';
$output_h = '';

for($i = 0, $a = 0; $i < strlen($encrypted); $i += 2) {
    $snip = substr($encrypted, $i, 2);
    $aw = hexdec($snip) - $sog[$a];
    if ($aw < 0) $aw += 256;
    if ($aw > 256) $aw -= 256;
    $output .= chr($aw);
    $a = ($a + 1) % 8;
}
file_put_contents('o.encrypted', $encrypted);
file_put_contents('o.decrypted', $output);
echo "outputs stored\n";

system('od -Ax -tx1z -v o.decrypted | head -n 5');

function rsh($a, $n)
{
    // alt. 32-bit shift right, keeping sign
    $sgn = $a & 0x80000000;
    return ($a >> 1) | $sgn;
}

function sgn_normalize($n, $debug = false)
{
    if ($n & 0x80000000) {
        if ($debug) {
            printf("Normalizing %10x to %10x\n"
                , $n
                , ($n & 0x7fffffff) - 1
            );
            printf("            %10d to %10d\n"
                , $n
                , ($n & 0x7fffffff) - 1
            );
        }
        return ($n & 0x7fffffff) - 1;
    } else {
        return $n;
    }
}

function iterate(&$s) {

    printf("Iteration %d\n", $s->iteration);

    $s->callersource = preg_replace('/\s+/', '', $s->callersource);
    $s->callersource = str_replace('"', '', $s->callersource);
    $s->callersource = str_replace('anonymous', '', $s->callersource);
    $s->callersource = str_replace('});r', '}));r', $s->callersource);
    $s->callersource = str_replace('n;})', 'n;}', $s->callersource);

    $s->callersource = str_replace('/**/', '', $s->callersource);

    if ($s->version == 'v2') {
        $s->callersource = str_replace('func' . 'tionJ', 'func' . 'tion J', $s->callersource);
        $s->callersource = str_replace("\x0a", '', $s->callersource);
    }

    $check_file = 'pristine.' . $s->version . '.' . $s->iteration;
    if (file_exists($check_file)) {
        $pristine = trim(file_get_contents($check_file));
        if ($pristine != $s->callersource) {
            echo "IMPURITIES!\n[$pristine]\n[{$s->callersource}]\n";
            die();
        }
        echo "pristine-check passed for iteration $s->iteration\n";
    }


    $initial_cryptkey = $s->cryptkey;

    echo 'version: ' . $s->version . "\n";

    for ($w = 0; $w < 256; $w++) {
        $a = $w;
        for($y = 8; $y > 0; $y--) {
            $x = ($a & 1) ? 0xedb88320 : 0;
            if ($s->version === 'v1') $a = ($a >> 1) ^ $x;
            if ($s->version === 'v2') $a = rsh($a, 1) ^ $x;
        }
        if ($s->version === 'v1') $s->sog[ $w ] = $a;
        if ($s->version === 'v2') $s->sog[ $w ] = sgn_normalize($a);

        // printf("sog[%02d] = %d\n", $w, $s->sog[ $w ]);
    }


    for ($w = 0; $w < strlen($s->callersource); $w += 2) {
        $deb = $s->iteration == 3 && ($w > 2800);
        $deb and printf("/ cryptkey it %d sta %08x, %d\n", $w, $s->cryptkey, $s->cryptkey);
        $deb and printf("| cc: %d\n", ord($s->callersource[$w]));
        $deb and printf("| sog: %d, %d\n"
            , ($s->cryptkey ^ ord($s->callersource[$w])) & 255
            , $s->sog[ ($s->cryptkey ^ ord($s->callersource[$w])) & 255 ]
        );

        $s->cryptkey = ($s->cryptkey >> 8) ^ $s->sog[ ($s->cryptkey ^ ord($s->callersource[$w])) & 255 ];

        $deb and printf("\ cryptkey end %08x, %d\n", $s->cryptkey, $s->cryptkey);
    }

    if ($s->version == 'v1') $s->cryptkey = $s->cryptkey ^ 0xffffffff;
    if ($s->version == 'v2') $s->cryptkey = sgn_normalize($s->cryptkey ^ 0x7ffffffe);
    $s->iteration++;

    printf("cryptkey now is %08x, %d\n", $s->cryptkey, $s->cryptkey);

    if ($s->iteration == 1) {
        $param = 'obj';
    } else {
        // $param = 'f' . sprintf('%x', $initial_cryptkey) . '/**/';
        $param = 'f' . sprintf('%x', $initial_cryptkey);
    }
    $s->callersource = 'function(' . $param . '){' . substr($s->orig_source,
        $start = strpos($s->orig_source, 'arguments'),
        strpos($s->orig_source, 'return') + 7 - $start
    ) . '}';

}



