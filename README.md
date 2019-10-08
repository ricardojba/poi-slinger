# PHP Object Injection Slinger

This is an extension for Burp Suite designed to help you scan for [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection) vulnerabilities on popular PHP Frameworks and some of their dependencies.


### Contribute
Testing and issue reporting is welcome.


### Credits
The payloads for this extension are all from the excellent Ambionics project [PHPGGC](https://github.com/ambionics/phpggc).
PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.
You will need it for further exploiting any vulnerabilities found by this extension.

This extention works best if combined with the `PHP Object Injection Check` extension from [Securify](https://github.com/securifybv/PHPUnserializeCheck).


### Compile
Build with `gradle fatJar`

Tested on
 * `OSX Mojave 10.14.6`
 * `java version "11.0.4" 2019-07-16 LTS`
 * `Gradle 5.6.2 (brew install gradle)`


### Install
Load the jar manually, in Burp Suite (community or pro), use "`Extender -> Extensions -> Add`"" to load "`poi-slinger/build/libs/poi-slinger-all.jar`""

`You can also install this is in Burp Suite, via Extender -> BApp Store - If PortSwigger accepts and publishes this extension on their BApp Store :)`


### Use
Right click on a request and click "`Send To POI Slinger`". This will also highlight the request and set the comment `Sent to POI Slinger`
You can watch the debug messages on the extension's output pane under "`Extender->Extensions->PHP Object Injection Slinger`".

If you're using Burp Pro, any findings will also be reported as scan issues.

![alt tag](https://raw.githubusercontent.com/ricardojba/POI-Slinger/master/img/report-example.png)
