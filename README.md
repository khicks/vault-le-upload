# Vault Let's Encrypt Upload

This script will upload your Let's Encrypt certificates to Vault. You should already have certificates issued to you by Let's Encrypt at `/etc/letsencrypt/live`.

## Installation

You will need hvac, a Python client for Vault.

    # pip3 install hvac
    
You may then clone this repository and optionally install it to your user or system bin directory.

    # cp vault-le-upload/vault-le-upload.py /usr/local/bin/vault-le-upload
    
## Vault Policy

The script needs permissions to read information about the mount point it is writing to in order to determine which KV version it uses. It will also need permission to actually write to the appropriate paths.

These are the minimum permissions required, assuming you are using mount point `secret/` and path `ssl-certs/`. If you choose to use another KV mount or path, adjust accordingly.

    path "sys/mounts/secret/tune" {
      capabilities = ["read"]
    }
    
    # For kv v1 mounts only.
    path "secret/ssl-certs/*" {
      capabilities = ["create", "read", "update"]
    }
    
    # For kv v2 mounts only.
    path "secret/data/ssl-certs/*" {
      capabilities = ["create", "update"]
    }
    
## Usage

This script authenticates to Vault using a token or AppRole.

### Environment Variables

Set these environment variables accordingly:

    # export VAULT_ADDR=https://vault.mydomain.com
    # export VAULT_TOKEN=s.EV4Iqhd3LFS9znYdeiUGURMi
    # export VAULT_ROLE_ID=17fda034-1039-0ead-432c-5b0428658a31
    # export VAULT_SECRET_ID=c1c2a92e-5166-1771-7d4a-09f2300e9596
    
You may also set these in the `-a`, `-t`, `-r`, and `-s` flags respectively, but running commands with inline secrets is not recommended.
    
### Options

The following options are supported:

* `-h|--help`: Show usage information.
* `-a|--address`: The address of the vault server, including protocol, IP/hostname, and port. Default: "`http://127.0.0.1:8200`".
* `-m|--mount-point`: The mount point where the certificates will be stored. Default: "`secret`".
* `-p|--path`: The path where the certificates will be stored. Default: "`ssl-certs`".
* `-t|--token`: The token for authentication. Setting this option is not recommended. Use the `VAULT_TOKEN` environment variable instead.
* `-r|--role-id`: The AppRole Role ID for authentication. Setting this option is not recommended. Use the `VAULT_ROLE_ID` environment variable instead.
* `-s|--secret-id`: The Approle Secret ID for authentication. Setting this option is not recommended. Use the `VAULT_SECRET_ID` environment variable instead.

### Run

If you installed the script to your PATH, you may run the script like so:

    # vault-le-upload <cert1.mydomain.com> [cert2.mydomain.com] [...]
    
Examples:

    # vault-le-upload cert1.mydomain.com
    # vault-le-upload cert1.mydomain.com cert2.myotherdomain.org

You will likely need to run this as root, since the certificates can only be read by the root user.
