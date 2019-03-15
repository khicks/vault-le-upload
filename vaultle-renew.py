#!/usr/bin/env python3

import os
import sys
import getopt
import vaultle


def usage():
    print("usage: {name}\n\t[-a|--address https://vault.mydomain.com]\n\t"
          "[-m|--mount-point secret] [-p|--path ssl-certs]\n\t"
          "[-t|--token] [-r|--role-id ROLE_ID] [-s|--secret-id SECRET_ID]"
          .format(name=sys.argv[0]))


def parse_opts():
    address = mount_point = path = token = role_id = secret_id = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'ha:m:p:t:r:s:',
                                   ['help', 'address=', 'mount-point=', 'path=', 'token=', 'role-id=', 'secret-id='])
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
        elif opt in ('-t', '--token'):
            token = arg
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
    if token is None:
        try:
            token = os.environ['VAULT_TOKEN']
        except KeyError:
            pass
    if role_id is None:
        try:
            role_id = os.environ['VAULT_ROLE_ID']
        except KeyError:
            pass
    if secret_id is None:
        try:
            secret_id = os.environ['VAULT_SECRET_ID']
        except KeyError:
            pass

    if token is None and (role_id is None or secret_id is None):
        print("Error: One of the following must be set:\n\t"
              "A Vault token via the VAULT_TOKEN environment variable or -t flag.\n\t"
              "\n\t"
              "- OR -\n\t"
              "\n\t"
              "A Vault AppRole role ID via the VAULT_ROLE_ID environment variable or -r flag, and\n\t"
              "a Vault AppRole secret ID via the VAULT_SECRET_ID environment variable or -s flag.")
        sys.exit(3)

    return {
        'address': address,
        'mount_point': mount_point,
        'path': path,
        'token': token,
        'role_id': role_id,
        'secret_id': secret_id,
        'certs': args
    }


def main():
    options = parse_opts()
    vault = vaultle.vault_create_client(options)
    certs = vaultle.vault_get_certs(vault, options, 100)

    for cert_name, attrs in certs.items():
        vaultle.le_request_certificate(attrs['sans'].split(','))
        vaultle.vault_upload_cert(vault, options, cert_name)
        print("Renewed certificate for {name}".format(name=cert_name))


if __name__ == "__main__":
    main()
