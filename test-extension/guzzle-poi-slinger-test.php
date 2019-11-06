<?php
/*
On a PHP enabled web server, download and extract Guzzle 6.2.2 - I'm using Alpine + Nginx + PHP-FPM
  mkdir -p /var/www/html/guzzle-test/
  cd /var/www/html/guzzle-test/
  wget https://github.com/guzzle/guzzle/releases/download/6.2.2/guzzle.zip
  unzip guzzle.zip
Create this PHP file on the same directory
  vim /var/www/html/guzzle-test/guzzle-poi-slinger-test.php
Use the vulnerable PHP file with the following GET parameters, to test the extension with Burp:
  https://webserver/guzzle-test/guzzle-poi-slinger-test.php?chain-nonencoded=[payload-has-is]&chain-encoded=[payload-base64-encoded]
*/
require '/var/www/html/guzzle-test/autoloader.php';
unserialize(base64_decode($_GET["chain-encoded"]));
unserialize($_GET["chain-nonencoded"]);
?>
