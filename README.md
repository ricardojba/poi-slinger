# PHP Object Injection Slinger

This is an extension for Burp Suite Professional, designed to help you scan for [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection) vulnerabilities on popular PHP Frameworks and some of their dependencies.
It will send a serialized PHP Object to the web application designed to force the web server to perform a DNS lookup to a Burp Collaborator Callback Host.


### Contribute
Feedback, testing and issue reporting is welcome.


### Credits
The payloads for this extension are all from the excellent [Ambionics](https://ambionics.io/blog) project [`PHPGGC`](https://github.com/ambionics/phpggc).
`PHPGGC` is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically.
You will need it for further exploiting any vulnerabilities found by this extension.

You should combine your testing with the [`PHP Object Injection Check`](https://github.com/securifybv/PHPUnserializeCheck) extension from [Securify](https://securify.nl) so you can identify other possible PHP Object Injection issues that this extension does not pick up.


### Compile

Tested on:
 * `OSX Mojave 10.14.6`
 * `java version "11.0.4" 2019-07-16 LTS`
 * `Gradle 5.6.2`

Build the extension on OSX:
 * Install [`Homebrew`](https://docs.brew.sh/Installation)
 * After installing `Homebrew` run on a terminal `brew install gradle`
 * Clone the repository `git clone https://github.com/ricardojba/poi-slinger.git`
 * Inside the cloned repository directory, build the Jar with `gradle fatJar`
 * Jar location `poi-slinger/build/libs/poi-slinger-all.jar`


### Install
Load the jar manually, in Burp Suite Pro, use `Extender -> Extensions -> Add` to load the jar file `poi-slinger-all.jar`

You may find the built Jar on the `bin` directory of this repository.

`You can also install the extension in Burp Suite Pro, via Extender -> BApp Store > PHP Object Injection Slinger`.


### Use
On the Proxy/Target/Intruder/Repeater Tab, right click on the desired HTTP Request and click `Send To POI Slinger`. This will also highlight the HTTP Request and set the comment `Sent to POI Slinger`
You can watch the debug messages on the extension's output pane under `Extender->Extensions->PHP Object Injection Slinger`.


Any findings will be reported as scan issues:
![alt tag](https://raw.githubusercontent.com/ricardojba/POI-Slinger/master/img/report-example.png)
