#!/usr/bin/env python3

import os
import sys
import getopt
import datetime
import requests
import hvac
from cryptography import x509
from cryptography.hazmat.backends import default_backend

le_directory = '/etc/letsencrypt/live'


def usage():
    print("usage: {name}\n\t[-a|--address https://vault.mydomain.com]\n\t"
          "[-m|--mount-point secret] [-p|--path ssl-certs]\n\t"
          "[-r|--role-id ROLE_ID] [-s|--secret-id SECRET_ID]\n\t<cert1.mydomain.com> [cert2.mydomain.com] [...]"
          .format(name=sys.argv[0]))


def parse_opts():
    address = mount_point = path = role_id = secret_id = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ha:m:p:r:s:',
                                   ['help', 'address=', 'mount-point=', 'path=', 'role-id=', 'secret-id='])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-a', '--address'):
            address = arg
        elif opt in ('-m', '--mount-point'):
            mount_point = arg
        elif opt in ('-p', '--path'):
            path = arg
        elif opt in ('-r', '--role-id'):
            role_id = arg
        elif opt in ('-s', '--secret-id'):
            secret_id = arg
        else:
            assert False, "unhandled option"

    if address is None:
        address = os.environ.get('VAULT_ADDR', 'http://127.0.0.1')
    if mount_point is None:
        mount_point = 'secret'
    if path is None:
        path = 'ssl-certs'
    if role_id is None:
        try:
            role_id = os.environ['VAULT_ROLE_ID']
        except KeyError:
            print("Error: ROLE_ID must be set via environment variable or -r flag.")
            sys.exit(3)
    if secret_id is None:
        try:
            secret_id = os.environ['VAULT_SECRET_ID']
        except KeyError:
            print("Error: SECRET must be set via environment variable or -s flag.")
            sys.exit(4)

    if len(args) == 0:
        print("Error: Must specify at least one certificate to upload.")
        usage()
        sys.exit(5)
    for arg in args:
        if not os.path.isdir('/'.join((le_directory, arg))):
            print("Error: Certificate at {le}/{cert} does not exist.".format(le=le_directory, cert=arg))
            sys.exit(6)

    return {
        'address': address,
        'mount_point': mount_point,
        'path': path,
        'role_id': role_id,
        'secret_id': secret_id,
        'certs': args
    }


def create_vault_client(options):
    vault = hvac.Client(url=options['address'])

    try:
        vault.auth_approle(role_id=options['role_id'], secret_id=options['secret_id'])
    except requests.exceptions.ConnectionError as err:
        print("Error: Connection to Vault server at {addr} could not be established.\n{err}"
              .format(addr=options['address'], err=err))
        sys.exit(7)
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


def read_file(cert_name, file_name):
    f = open('/'.join((le_directory, cert_name, file_name)), 'r')
    contents = f.read()
    f.close()
    return contents


def get_cert_expires(cert_name):
    cert_pem = read_file(cert_name, 'cert.pem')
    cert_x509 = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
    return cert_x509.not_valid_after.isoformat() + 'Z'


def upload_cert(vault, options, cert_name, cert_data):
    full_path = '/'.join((options['path'], cert_name.replace('.', '-')))
    try:
        vault.secrets.kv.create_or_update_secret(
            mount_point=options['mount_point'],
            path=full_path,
            secret=cert_data
        )
    except hvac.v1.exceptions.Forbidden:
        print("Error: Permission denied when writing to {path}.".format(path=full_path))
        sys.exit(11)


def main():
    options = parse_opts()
    current_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z'
    vault = create_vault_client(options)

    for cert_name in options['certs']:
        cert_data = {
            'updated': current_time,
            'certificate': read_file(cert_name, 'cert.pem'),
            'chain': read_file(cert_name, 'chain.pem'),
            'fullchain': read_file(cert_name, 'fullchain.pem'),
            'private_key': read_file(cert_name, 'privkey.pem'),
            'expires': get_cert_expires(cert_name)
        }

        upload_cert(vault, options, cert_name, cert_data)
        print("Uploaded certificate for {name}.".format(name=cert_name))


if __name__ == "__main__":
    main()
