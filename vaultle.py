#!/usr/bin/env python3

import os
import sys
import datetime
import requests
import subprocess
import hvac
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID

le_directory = '/etc/letsencrypt/live'


# ======================================================
# File operations
# ======================================================
def read_file(cert_name, file_name):
    f = open('/'.join((le_directory, cert_name, file_name)), 'r')
    contents = f.read()
    f.close()
    return contents


def get_cert_expires(cert_name):
    cert_pem = read_file(cert_name, 'cert.pem')
    cert_x509 = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
    return cert_x509.not_valid_after.isoformat() + 'Z'


def get_cert_sans(cert_name):
    cert_pem = read_file(cert_name, 'cert.pem')
    cert_x509 = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
    ext = cert_x509.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    sans = ext.value.get_values_for_type(x509.DNSName)
    sans.insert(0, sans.pop(sans.index(cert_name)))
    return ','.join(sans)


# ======================================================
# LE operations
# ======================================================
def le_request_certificate(cert_sans):
    certbot_args = ['certbot', 'certonly', '--dns-route53']
    for san in cert_sans:
        certbot_args.append('-d')
        certbot_args.append(san)

    subprocess.run(certbot_args)


# ======================================================
# Vault operations
# ======================================================
def vault_create_client(options):
    vault = hvac.Client(url=options['address'])

    try:
        if options['token'] is not None:
            vault.token = options['token']
            assert vault.is_authenticated()
        else:
            vault.auth_approle(role_id=options['role_id'], secret_id=options['secret_id'])
    except requests.exceptions.ConnectionError as err:
        print("Error: Connection to Vault server at {addr} could not be established.\n{err}"
              .format(addr=options['address'], err=err))
        sys.exit(7)
    except AssertionError:
        print("Error: Cannot authenticate with Vault token.")
        sys.exit(8)
    except hvac.v1.exceptions.InvalidRequest as err:
        print("Error: Authentication to Vault server at {addr} failed.\n{err}"
              .format(addr=options['address'], err=err))
        sys.exit(8)

    try:
        kv = dict(vault.sys.read_mount_configuration(path=options['mount_point']))['options']['version']
    except hvac.v1.exceptions.Forbidden:
        print("Error: Permission denied when trying to read information about mount point {mount}/."
              .format(mount=options['mount_point']))
        sys.exit(9)
    except hvac.v1.exceptions.InvalidRequest:
        print("Error: Could not read information about mount point {mount}/."
              .format(mount=options['mount_point']))
        sys.exit(10)
    vault.secrets.kv.default_kv_version = kv

    return vault


def vault_get_certs(vault, options, expires_less_than_days=None):
    kv = vault.secrets.kv.default_kv_version
    cert = None
    now = datetime.datetime.now()

    certificates = {}
    secrets = vault.secrets.kv.list_secrets(
        mount_point=options['mount_point'],
        path=options['path']
    )['data']['keys']

    for secret in secrets:
        cert_name = secret.replace('_', '.')
        if kv == "1":
            cert = vault.secrets.kv.read_secret(
                mount_point=options['mount_point'],
                path='/'.join([options['path'], secret])
            )['data']
        elif kv == "2":
            cert = vault.secrets.kv.read_secret_version(
                mount_point=options['mount_point'],
                path='/'.join([options['path'], secret])
            )['data']['data']

        cert['sans'] = cert['sans'].split(',')

        if 'updated' in cert and 'expires' in cert:
            if expires_less_than_days is None:
                certificates[cert_name] = cert
            else:
                expires = datetime.datetime.strptime(cert['expires'], '%Y-%m-%dT%H:%M:%SZ')
                expires_delta = expires - now
                if expires_delta.days < expires_less_than_days:
                    certificates[cert_name] = cert



    return certificates


def vault_upload_cert(vault, options, cert_name):
    if not os.path.isdir('/'.join((le_directory, cert_name))):
        print("Error: Certificate at {le}/{cert} does not exist.".format(le=le_directory, cert=cert_name))
        sys.exit(6)

    full_path = '/'.join((options['path'], cert_name.replace('.', '_')))

    cert_data = {
        'updated': datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z',
        'certificate': read_file(cert_name, 'cert.pem'),
        'chain': read_file(cert_name, 'chain.pem'),
        'fullchain': read_file(cert_name, 'fullchain.pem'),
        'private_key': read_file(cert_name, 'privkey.pem'),
        'expires': get_cert_expires(cert_name),
        'sans': get_cert_sans(cert_name)
    }

    try:
        vault.secrets.kv.create_or_update_secret(
            mount_point=options['mount_point'],
            path=full_path,
            secret=cert_data
        )
    except hvac.v1.exceptions.Forbidden:
        print("Error: Permission denied when writing to {path}.".format(path=full_path))
        sys.exit(11)
