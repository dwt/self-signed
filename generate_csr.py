#!/usr/bin/env python
# encoding: utf-8
# Tested with Pythons 2.7 and 3.4

# Licensed under the BSD 2-Clause License <https://opensource.org/licenses/BSD-2-Clause>
# Authors:
# - Robert Buchholz rbu goodpoint de
# - Martin Häcker mhaecker ät mac dot com


import argparse
import os
import codecs
import sys
from subprocess import check_call, check_output, run
from tempfile import NamedTemporaryFile
from pathlib import Path

PY3 = sys.version_info[0] == 3

# SSL certificate defaults.
# Fill in if you copy this script or export as environment variables.
DEFAULTS = dict(
    REQ_COUNTRY='DE',
    REQ_PROVINCE='Berlin',
    REQ_CITY='Berlin',
    REQ_ORG='Häckertools',
    REQ_OU='DevOps',
    REQ_EMAIL='häcker@example.com',
)

def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate and optionaly sign SSL CSRs with Subject Alternative Names')
    parser.add_argument('--batch', dest='batch', action='store_true',
        default=False, help='Batch mode, supress interaction and go with defaults.')
    parser.add_argument('--key', dest='key', metavar='PRIVATE_KEY_FILE',
        help="""Path to a private key file to generate a CSR for.
            To generate a key, consider calling 'openssl genrsa -out private.key 4096'
        """)
    parser.add_argument('--csr-out', dest='csr_out', default=None,
        help='Path to file to save csr in')
    parser.add_argument('--signed-out', dest='signed_out', default=None,
        help='Path to file to save signed csr in')
    parser.add_argument('--config', dest='config_path', default='.env', 
        help='Optional path to .env like file with default values for REQ_COUNTRY,'
            ' REQ_PROVINCE, REQ_CITY, REQ_ORG, REQ_OU, REQ_EMAIL. Is parsed as python code.'
            ' Defaults can also be set by environment variables of these names.'
            ' Default: .env')
    parser.add_argument('domains', metavar='DOMAIN', nargs='+',
        help='Domain names to request. First domain is the common name.')
    return parser.parse_args()

def environment(optional_config_path):
    env = DEFAULTS.copy()
    env.update(read_defaults(optional_config_path))
    env.update(os.environ.copy())
    return env

def ensure_text(maybe_text):
    text_type = str if PY3 else unicode
    if isinstance(maybe_text, text_type):
        return maybe_text
    return maybe_text.decode('utf-8')

def write_openssl_config_to(fd, domains, config_tempmlate=None, is_ca=False):
    if config_tempmlate is None:
        config_tempmlate = OPEN_SSL_CONF
    
    fd.write(config_tempmlate)
    fd.write(u'commonName_default=%s\n\n' % ensure_text(domains[0]))
    fd.write(u'[SAN]\n')
    fd.write(u'subjectAltName=')
    fd.write(u','.join(map(lambda domain: u'DNS:%s' % ensure_text(domain), domains)))
    fd.write(u'\n')
    if is_ca:
        fd.write(u'basicConstraints=critical,CA:TRUE,pathlen:1')
    fd.flush()

def main():
    arguments = parse_args()
    with NamedTemporaryFile() as config_fd:
        config_fd = codecs.getwriter('utf-8')(config_fd)
        write_openssl_config_to(config_fd, arguments.domains)
        batch_params = ['-batch'] if arguments.batch else []
        csr_out_params = arguments.csr_out and ['-out', arguments.csr_out] or []
        # Workaround for https://github.com/OpenVPN/easy-rsa/issues/74 libressl doesn't support passing in values via ENV
        openssl = 'openssl'
        if 'darwin' == sys.platform:
            openssl = check_output("brew list openssl@1.1|grep 'openssl$'", shell=True).strip()
        run([
                openssl,
                'req', '-new', '-sha256', #'-x509',
                '-key', arguments.key,
                '-reqexts', 'SAN',
                '-config', config_fd.name,
            ] + batch_params + csr_out_params,
            env=environment(arguments.CONFIG_PATH),
        )
    if arguments.signed_out:
        with NamedTemporaryFile() as config_fd:
            config_fd = codecs.getwriter('utf-8')(config_fd)
            write_openssl_config_to(config_fd, arguments.domains, config_tempmlate=OPEN_SSL_SIGN_CONF, is_ca=True)
            signed_out_params = arguments.signed_out and ['-out', arguments.signed_out] or []
            run([
                    openssl, 'x509', 
                    '-req', '-sha256', '-days', '365', 
                    '-extfile', config_fd.name,
                    # '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1',
                    '-in', arguments.csr_out,
                    '-signkey', arguments.key,
                ] + signed_out_params,
                env=environment(arguments.CONFIG_PATH),
            )

def read_defaults(path):
    default_values = {}
    
    path = Path(path)
    if not path.is_file():
        return {}
    
    exec(path.read_text(), None, default_values)
    return default_values

OPEN_SSL_CONF = u"""
HOME			= .
RANDFILE		= $ENV::HOME/.rnd

[ req ]
default_bits		= 2048
default_md		= sha256
default_keyfile 	= privkey.pem
distinguished_name	= distinguished_name
# The extentions to add to the self signed cert
x509_extensions	= v3_ca
req_extensions      = v3_ca
extensions          = v3_ca
string_mask = utf8only

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true

[ distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= $ENV::REQ_COUNTRY
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= $ENV::REQ_PROVINCE

localityName			= Locality Name (eg, city)
localityName_default		= $ENV::REQ_CITY

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= $ENV::REQ_ORG

organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default	= $ENV::REQ_OU

commonName			= Common Name (eg, your name or your server\'s hostname)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64
emailAddress_default		= $ENV::REQ_EMAIL
"""

OPEN_SSL_SIGN_CONF = u"""
default_bits        = 2048
default_md		= sha256

distinguished_name  = distinguished_name
x509_extensions     = SAN
req_extensions      = SAN
extensions          = SAN
prompt              = no
    
[ distinguished_name ]
countryName         = $ENV::REQ_COUNTRY
stateOrProvinceName = $ENV::REQ_PROVINCE
localityName        = $ENV::REQ_CITY
organizationName    = $ENV::REQ_ORG
"""

if __name__ == '__main__':
    main()

## Unit Tests

def test_parse_dotenv(tmp_path, monkeypatch):
    from textwrap import dedent
    env_path = tmp_path / '.env'
    env_path.write_text(dedent('''
        REQ_COUNTRY='DE'
        REQ_PROVINCE='Berlin'
        REQ_CITY='Berlin'
        REQ_ORG='Publishing House'
        REQ_OU=''
        REQ_EMAIL='admin@example.com'
    '''))
    with monkeypatch.context() as context:
        context.chdir(tmp_path)
        defaults = read_defaults('.env')
        assert defaults['REQ_COUNTRY'] == 'DE'
        assert defaults['REQ_ORG'] == 'Publishing House'
        assert defaults['REQ_EMAIL'] == 'admin@example.com'

def test_parse_missing_dotenv(tmp_path, monkeypatch):
    with monkeypatch.context() as context:
        context.chdir(tmp_path)
        defaults = read_defaults('.env')
        assert defaults == {}

def test_overwrite_dotennv_with_environment_variables(tmp_path, monkeypatch):
    env_file = tmp_path / '.env'
    env_file.write_text('REQ_EMAIL = "fnord@fnord"')
    with monkeypatch.context() as context:
        context.chdir(tmp_path)
        context.setenv('REQ_EMAIL', 'fnord@example.com')
        
        defaults = environment('.env')
        assert defaults['REQ_EMAIL'] == 'fnord@example.com'

def test_hardcode_environment_config_into_openssl_config(tmp_path):
    pass