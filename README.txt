---------------
OVERVIEW
---------------
fserv is a fast HTTP server for Linux, FreeBSD and Windows.

---------------
MODULES
---------------
Default modules:
	. log.so: log
	. cache.so: mem
	. net.so: connect, listen, resolve
	. http.so: http, static-file, dir-index, errdoc, gzip, status
	. http-proxy.so: proxy
External modules are loaded from mod/ directory.

---------------
HOW TO CONFIGURE
---------------
To run fserv you have to set its root directory in the configuration file.
By default, the configuration file is "conf/fserv.conf".  Set "root" to the directory you unpacked fserv to.

For example, on Linux it may look like:
root "/usr/local/fserv"

And on Windows:
root "C:/Program Files/fserv"

---------------
HOMEPAGE
---------------
http://fserv.firmdev.com/
