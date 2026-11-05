`zbus-trust` is a low-level binding over the D-Bus API to communicate with the trust broker.  The
API itself is quite simple, but you might still want to take a look at the `libzbus` crate which
offers a higher level API, and offers transparent request caching making it usually even lighter.
