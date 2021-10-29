# self-signed: Create self signed certificates with multiple Domain Names (SANs) with style

self-signed is a python tool to make it easy to generate self signed certificates with multiple domain names (SAN - Subject Alternative Names).

While it is relatively simple to generate a self signed certificate for a single domain name with the openssl shell, creating one for multiple domain names is _signifficantly_ harder. You have to create / change configuration files for that, something I always forgot and had to look up. Doubly so, if you want to support utf8 names in there. Also, the `openssl` shell is just not really a nice and focused experience to create self signed certificates.

That is where this package helps, one command, nice `--help` output and a job quickly done.

# What does this tool do?

- It allows you to create a certificate request with multiple SANs
- It allows you to optionally self sign that request
- Sets the right defaults to create certificate signing requests and certificates with utf8 fields

# Demo time

```shell
% openssl genrsa -out private.key 4096
Generating RSA private key, 4096 bit long modulus
......................................................................................................................................................................................................................................................................................................................++
.....++
e is 65537 (0x10001)
% self-signed --batch --key private.key --csr-out request.pem --certificate-out certificate.pem --domains foo.example.com bar.example.com -v
# openssl req -new -sha256 -key private.key -reqexts SAN -config /path/to/generated/config -batch -out request.pem
# openssl x509 -req -sha256 -days 365 -extfile /path/to/generated/config -in request.pem -signkey private.key -nameopt oneline,-esc_msb -out certificate.pem
Signature ok
subject=C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = foo.example.com, emailAddress = haecker@example.com
Getting Private key
% self-signed --introspect private.key |head
# openssl rsa -in private.key -noout -text
Private-Key: (4096 bit)
modulus:
    00:da:8a:ad:19:fe:fc:3e:66:b2:87:d9:9f:39:05:
    2b:0f:b6:37:f9:68:91:32:ff:75:bf:85:0f:2d:8e:
    6d:08:da:01:82:44:7e:c2:aa:bd:21:c8:79:ea:f1:
    66:1d:90:8d:2b:c6:40:cc:21:7c:b7:bd:f2:77:86:
    8b:1b:0d:9c:6b:3e:15:6a:74:af:5b:19:0d:94:b6:
    cf:df:b9:e6:3b:45:cf:e5:26:f9:d6:88:28:80:8c:
    4e:8f:3b:45:7d:23:df:bf:e5:15:44:25:b6:d1:ef:
    8f:13:15:43:10:6e:28:3d:3d:61:0b:b8:2c:6a:47:
% self-signed --introspect request.pem |head 
# openssl req -in request.pem -noout -text -nameopt oneline,-esc_msb
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = foo.example.com, emailAddress = haecker@example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:da:8a:ad:19:fe:fc:3e:66:b2:87:d9:9f:39:05:
                    2b:0f:b6:37:f9:68:91:32:ff:75:bf:85:0f:2d:8e:
% self-signed --introspect certificate.pem |head -n 15
# openssl x509 -in certificate.pem -noout -text -nameopt oneline,-esc_msb
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 10970618610503198012 (0x983f77805d55253c)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = foo.example.com, emailAddress = haecker@example.com
        Validity
            Not Before: Oct 29 08:50:52 2021 GMT
            Not After : Oct 29 08:50:52 2022 GMT
        Subject: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = foo.example.com, emailAddress = haecker@example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:da:8a:ad:19:fe:fc:3e:66:b2:87:d9:9f:39:05:
```