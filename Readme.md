# self-signed: Create self signed certificates with multiple Domain Names (SANs) with style

self-signed is a python tool to make it easy to generate self signed certificates with multiple domain names (SAN - Subject Alternative Names).

While it is relatively simple to generate a self signed certificate for a single domain name with the openssl shell, creating one for multiple domain names is _signifficantly_ harder. You have to create / change configuration files for that, something I always forgot and had to look up. Also, the `openssl` shell is just not really a nice and focused experience to create self signed certificates.

That is where this package helps, one command, nice `--help` output and a job quickly done.

# What does this tool do?

- It allows you to create a certificate request with multiple SANs
- It allows you to optionally self sign that request
