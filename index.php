<?php

$message = null;
$result = null;

if (isset($_REQUEST['packed_source'])) {
    $source = $_REQUEST['packed_source'];

    if ($source) {
        require_once('js.decrypt.javacrypt.php');

        $result = decrypt_javacrypt($source);

        if ($result === false) {
            $result = $source;
            $message = "This doesn’t look like JavaCrypt’ed file.";
            if ($source and false !== strpos('JavaCrypt', $source)) {
                $message = "Failed to unpack this file; would you please send me it for the examination?";
            }
        }
    }

}


?>

<html>
<head>
<meta charset="utf-8">
<title>JavaCrypt unpacker</title>
<style type="text/css">

* {
  margin: 0;
  padding: 0;
}

html {
  font-size: 62.5%;
}
body {
  font-family: "Lucida Grande", "Lucida Sans Unicode", Verdana, Arial, Helvetica, sans-serif;
  font-size: 14px; font-size: 1.4rem;
  line-height: 150%;
}
textarea, input {
  font-family: "Droid Mono", "Monaco", "Lucida Console", "Courier New", monospace;
}
h1, button {
  font-family: "Lucida Grande", "Lucida Sans Unicode", Verdana, Arial, Helvetica, sans-serif;
  font-size: 24px; font-size: 2.4rem;
}

body {
    background-color: #f4f4f4;
}

button {
    width: 100%;
    line-height: 150%;
    cursor: pointer;
}

.source-input {
    display: block;
    border: 1px solid #ccc;
    width: 100%;
    height: 50%;
    margin-top: 14px;
    padding: 7px;
    background-color: #ffe;
}

.unpacker-plate {
    margin: 20px 40px;
    border-radius: 10px;
    border: 1px solid #aaa;
    background-color: white;
    padding: 20px;
    box-shadow: 0 4px 10px 0 #ccc;
}

.message {
    padding-top: 14px;
    color: #933;
}


.submit {
    margin-top: 7px;
}
.unpacker-form {
    margin-bottom: 14px;
}
.footer {
    color: #888;
}
.footer a {
    color: #555;
}

</style>
</head>

<body>

<div class="unpacker-plate">
<p>This is an automatic JavaCrypt unpacker. I don’t know what packer produces this: packed objects were found in the wild.</p>
<p>Paste yor javacrypted source inside the textarea.</p>

<?php
if ($message) {
    printf('<p class="message">%s</p>', $message);
}
?>

<form class="unpacker-form" method="post" action="?">
<textarea spellcheck="false" name="packed_source" class="source-input js-focus"><?php echo htmlspecialchars($result); ?></textarea>
<button class="submit" type="submit">Unpack</button>
</form>

<p class="footer">Written by Einar Lielmanis, einar@jsbeautifier.org<br>The source code is available on <a href="https://github.com/einars/js.decrypt.javacrypt">github</a>.</p>
</div>

<script>
    if (document.getElementsByClassName) {
        var elts = document.getElementsByClassName('js-focus');
        elts[0].focus();
    }
</script>
</body>
</html>


