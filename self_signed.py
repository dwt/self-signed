#!/usr/bin/env python
# encoding: utf-8

# Licensed under the BSD 2-Clause License <https://opensource.org/licenses/BSD-2-Clause>
# Authors:
# - Robert Buchholz rbu goodpoint de
# - Martin Häcker mhaecker ät mac dot com

from __future__ import unicode_literals

import argparse
import os
import codecs
import sys
from textwrap import dedent
from string import Template
from subprocess import check_call, check_output, run, PIPE
from tempfile import NamedTemporaryFile
from pathlib import Path
from contextlib import contextmanager

PY3 = sys.version_info[0] == 3

# SSL certificate defaults.
# Fill in if you copy this script or export as environment variables.
DEFAULTS = dict(
    REQ_COUNTRY='DE',
    REQ_PROVINCE='Berlin',
    REQ_CITY='Berlin',
    REQ_ORG='Häckertools',
    REQ_OU='DevOps',
    REQ_EMAIL='haecker@example.com',
)

def parse_args(argv=sys.argv):
    parser = argparse.ArgumentParser(
        description="Generate and optionaly sign SSL CSRs with Subject Alternative Names")
    
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
        help="Prints openssl commands used.")
    
    self_sign_arguments = parser.add_argument_group("Signing", "Create self signed certificates")
    self_sign_arguments.add_argument('--config', dest='config_path', default='.env', 
        help="""Optional path to .env like file with default values for REQ_COUNTRY,
            REQ_PROVINCE, REQ_CITY, REQ_ORG, REQ_OU, REQ_EMAIL. Is parsed as python code.
            Defaults can also be set by environment variables of these names.
            Default: .env
        """)
    self_sign_arguments.add_argument('--batch', dest='batch', action='store_true', default=False,
        help='Batch mode, supress interaction and go with defaults.')
    self_sign_arguments.add_argument('--key', dest='key', metavar='PRIVATE_KEY_FILE',
        help="""Path to a private key file to generate a CSR for.
            To generate a key, consider calling 'openssl genrsa -out private.key 4096'
        """)
    self_sign_arguments.add_argument('--csr-out', dest='csr_out', default=None,
        help="Path to file to save csr in")
    self_sign_arguments.add_argument('--certificate-out', dest='certificate_out', default=None,
        help="Path to file to save signed csr in")
    self_sign_arguments.add_argument('--domains', dest='domains', metavar='DOMAIN', nargs='+',
        help="Domain names to request. First domain is the common name.")
    
    introspect_arguments = parser.add_argument_group("Introspection", "Decode created files")
    introspect_arguments.add_argument('--introspect', dest='introspect_path', type=Path, default=None,
        help="Path to a private key, certificate signing request or certificate. If given, ignores all other arguments.")

    return parser.parse_args(argv[1:])

def default_variables(optional_config_path):
    env = DEFAULTS.copy()
    env.update(read_defaults(optional_config_path))
    env.update(dict(HOME=Path.home().as_posix()))
    env.update(os.environ.copy())
    return env

def ensure_text(maybe_text):
    text_type = str if PY3 else unicode
    if isinstance(maybe_text, text_type):
        return maybe_text
    return maybe_text.decode('utf-8')

def main(argv=sys.argv):
    arguments = parse_args(argv)
    
    if arguments.introspect_path:
        print(introspect(arguments.introspect_path, verbose=arguments.verbose))
        return
    
    variables = dict(
        default_variables(arguments.config_path),
        **sans_from_domains(arguments.domains)
    )
    with temporary_openssl_config(csr_creation_configuration_template(), variables) as path_to_config:
        batch_params = ['-batch'] if arguments.batch else []
        csr_out_params = arguments.csr_out and ['-out', arguments.csr_out] or []
        verbose_run([
                'openssl', 'req',
                '-new', '-sha256', #'-x509',
                '-key', arguments.key,
                '-reqexts', 'SAN',
                '-config', path_to_config,
            ] + batch_params + csr_out_params,
            verbose=arguments.verbose,
        )
    if arguments.certificate_out:
        with temporary_openssl_config(csr_sign_configuration_template(), variables) as path_to_config:
            certificate_out_params = arguments.certificate_out and ['-out', arguments.certificate_out] or []
            verbose_run([
                    'openssl', 'x509', 
                    '-req', '-sha256', '-days', '365', 
                    '-extfile', path_to_config,
                    '-in', arguments.csr_out,
                    '-signkey', arguments.key,
                     '-nameopt', 'oneline,-esc_msb',
                ] + certificate_out_params,
                verbose=arguments.verbose,
            )

def read_defaults(path):
    default_values = {}
    
    path = Path(path)
    if not path.is_file():
        return {}
    
    exec(path.read_text(), None, default_values)
    return default_values

def csr_creation_configuration_template():
    return  dedent("""
        HOME			= .
        RANDFILE		= $HOME/.rnd

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
        utf8 = yes

        [ v3_ca ]
        subjectKeyIdentifier=hash
        authorityKeyIdentifier=keyid:always,issuer
        basicConstraints = CA:true

        [ distinguished_name ]
        countryName			= Country Name (2 letter code)
        countryName_default		= $REQ_COUNTRY
        countryName_min			= 2
        countryName_max			= 2

        stateOrProvinceName		= State or Province Name (full name)
        stateOrProvinceName_default	= $REQ_PROVINCE

        localityName			= Locality Name (eg, city)
        localityName_default		= $REQ_CITY

        0.organizationName		= Organization Name (eg, company)
        0.organizationName_default	= $REQ_ORG

        organizationalUnitName		= Organizational Unit Name (eg, section)
        organizationalUnitName_default	= $REQ_OU

        commonName			= Common Name (eg, your name or your server\'s hostname)
        commonName_max			= 64

        emailAddress			= Email Address
        emailAddress_max		= 64
        emailAddress_default	= $REQ_EMAIL
        commonName_default		= $COMMON_NAME

        [SAN]
        subjectAltName			= $SUBJECT_ALT_NAMES
        """
    )

def csr_sign_configuration_template():
    return dedent("""
        default_bits		= 2048
        default_md			= sha256

        distinguished_name	= distinguished_name
        x509_extensions		= SAN
        req_extensions		= SAN
        extensions			= SAN
        prompt				= no
        
        [ distinguished_name ]
        countryName			= $REQ_COUNTRY
        stateOrProvinceName	= $REQ_PROVINCE
        localityName		= $REQ_CITY
        organizationName	= $REQ_ORG
        commonName_default	= $COMMON_NAME

        [SAN]
        subjectAltName		= $SUBJECT_ALT_NAMES
        basicConstraints	= critical,CA:TRUE,pathlen:1
        """
    )

@contextmanager
def temporary_openssl_config(template, variables):
    template = Template(template)
    templated_string = template.substitute(variables)
    
    with NamedTemporaryFile() as config_fd:
        config_fd = codecs.getwriter('utf-8')(config_fd)
        config_fd.write(templated_string)
        config_fd.flush()
        
        yield config_fd.name

def sans_from_domains(domains):
    assert len(domains) >= 1
    return dict(
        COMMON_NAME=ensure_text(domains[0]),
        SUBJECT_ALT_NAMES=','.join('DNS:%s' % ensure_text(domain) for domain in domains)
    )

def introspect(path, verbose=True):
    text = path.read_text()
    command = []
    if 'BEGIN RSA PRIVATE KEY' in text:
        command = ['openssl', 'rsa', '-in', path.as_posix(), '-noout', '-text']
    elif 'BEGIN CERTIFICATE REQUEST' in text:
        command = ['openssl', 'req', '-in', path.as_posix(), '-noout', '-text', '-nameopt', 'oneline,-esc_msb']
    elif 'BEGIN CERTIFICATE' in text:
        command = ['openssl', 'x509', '-in', path.as_posix(), '-noout', '-text', '-nameopt', 'oneline,-esc_msb']
    else:
        assert False, 'Unknown filetype, only support rsa private key, certificate request or certificate'
    
    return verbose_run(command, capture_output=True, verbose=verbose)

def verbose_run(command, capture_output=False, verbose=False):
    if verbose:
        print('#', ' '.join(command), file=sys.stderr, flush=True)
    
    # capture_output is only supported from python 3.7
    backwards_compatible_capture_output_args = {}
    if capture_output:
        backwards_compatible_capture_output_args = dict(stdout=PIPE, stderr=PIPE)
    
    result = run(command, **backwards_compatible_capture_output_args)
    if capture_output:
        return result.stdout.decode('utf8')
    
    return ''

if __name__ == '__main__':
    main()

## Unit Tests

def test_parse_dotenv(tmp_path, monkeypatch):
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
        
        defaults = default_variables('.env')
        assert defaults['REQ_EMAIL'] == 'fnord@example.com'

def test_hardcode_environment_config_into_openssl_config(tmp_path):
    # libressl doesn't support configs with environment variables
    # And since it is nowadays the default openssl binary on macos, it's nice to support it
    with temporary_openssl_config('foo="$baz"', variables=dict(baz='bar')) as path_to_config:
        assert 'foo="bar"' in Path(path_to_config).read_text()

def test_prepare_domain_names():
    variables = sans_from_domains(['fnord.example.com', 'fnord.example.org'])
    assert variables['COMMON_NAME'] == 'fnord.example.com'
    assert variables['SUBJECT_ALT_NAMES'] == 'DNS:fnord.example.com,DNS:fnord.example.org'

def test_check_certificate_sign_request_config(tmp_path):
    variables = dict(
        default_variables('.env'),
        REQ_COUNTRY='fnord',
        **sans_from_domains(['fnord.example.com', 'fnord.example.org'])
    )
    with temporary_openssl_config(csr_creation_configuration_template(), variables) as path_to_config:
        config = Path(path_to_config).read_text()
        assert 'countryName_default		= fnord' in config
        assert 'subjectAltName			= DNS:fnord.example.com,DNS:fnord.example.org'
    with temporary_openssl_config(csr_sign_configuration_template(), variables) as path_to_config:
        config = Path(path_to_config).read_text()
        assert 'countryName			= fnord' in config
        assert 'subjectAltName		= DNS:fnord.example.com,DNS:fnord.example.org' in config
        assert 'basicConstraints	= critical,CA:TRUE,pathlen:1' in config

def test_create_self_signed_certificate(tmp_path, monkeypatch):
    with monkeypatch.context() as context:
        context.chdir(tmp_path)
        
        key_path = tmp_path / 'private.key'
        run(['openssl', 'genrsa', '-out', key_path.as_posix(), '4096'])
        assert key_path.is_file()
        assert 'BEGIN RSA PRIVATE KEY' in key_path.read_text()
        assert 'Private-Key: (4096 bit)' in introspect(key_path)
        csr_path = tmp_path / 'certificate_signing_request.csr'
        certificate_path = tmp_path / 'certificate.pem'
        main([ 'tool-name',
            '--batch', '--key', key_path.as_posix(), '--csr-out', csr_path.as_posix(), 
            '--certificate-out', certificate_path.as_posix(),
            '--domains', 'fnord.example.com', 'fnord.example.org'
        ])
        
        assert csr_path.is_file()
        assert 'BEGIN CERTIFICATE REQUEST' in csr_path.read_text()
        csr_introspection = introspect(csr_path)
        assert 'Subject: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = fnord.example.com, emailAddress = haecker@example.com' in csr_introspection
        assert 'X509v3 Subject Alternative Name: \n                DNS:fnord.example.com, DNS:fnord.example.org' in csr_introspection
        
        assert certificate_path.is_file()
        assert 'BEGIN CERTIFICATE' in certificate_path.read_text()
        certificate_introspection = introspect(certificate_path)
        assert 'Signature Algorithm: sha256WithRSAEncryption' in certificate_introspection
        assert 'Issuer: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = fnord.example.com, emailAddress = haecker@example.com' in certificate_introspection
        assert 'Subject: C = DE, ST = Berlin, L = Berlin, O = Häckertools, OU = DevOps, CN = fnord.example.com, emailAddress = haecker@example.com' in certificate_introspection
        assert 'X509v3 extensions:\n            X509v3 Subject Alternative Name: \n                DNS:fnord.example.com, DNS:fnord.example.org' in certificate_introspection
        assert 'X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:1' in certificate_introspection
        
