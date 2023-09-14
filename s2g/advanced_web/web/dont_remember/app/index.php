<pre>
<?php
$res = file_get_contents($_GET['file']);
if (str_contains($res, 'S2G')) {
    die('Nope');
}
echo $res;
?>
</pre>
