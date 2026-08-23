# Certificate Manager - Private Certificates Made Practical

Certificate Manager is a free, local web application for creating and operating a private Public Key Infrastructure (PKI): your own system for issuing and trusting certificates. It helps developers and administrators create a root certificate authority, issue server certificates for encrypted connections, export deployment-ready certificates and keys, and verify the result without assembling a collection of command-line tools.

It is a practical fit for development environments, internal services, lab equipment, and embedded or Internet of Things (IoT) products where you control which clients trust your root certificate. The application runs on [Mako Server](https://makoserver.net/), uses Mako Server's built-in certificate services, and keeps all persistent records in a SQLite database.

For the complete workflow, see [How to act as a Certificate Authority (the Easy Way)](https://realtimelogic.com/articles/How-to-act-as-a-Certificate-Authority-the-Easy-Way).

## What you can do

- Create root authorities using P-256/P-384 elliptic-curve keys or 2048/3072-bit RSA keys.
- Issue server certificates for host names and version 4 Internet Protocol addresses, such as 127.0.0.1. Each certificate uses the same key algorithm as its authority.
- Download certificates in PEM text format, DER binary `.cer` format, complete PEM chains, and SharkSSL trust-list format.
- Export an issued server certificate's matching private key as a PEM file for deployment.
- Start a temporary secure listener available only on this computer and test a certificate before deployment.
- Protect stored private keys with authenticated encryption and either device-bound or portable trust-domain protection.

Certificate Manager is intentionally a local administration tool. Both the application and its temporary certificate-test listener are restricted to this computer.

## Requirements

- Mako Server with its built-in certificate, database, encryption, and private-key protection services.
- A writable Mako Server data directory for `certmgr.sqlite.db`.
- A browser on the same computer as Mako Server.

Make sure the `mako` or `mako.exe` command is available from your command prompt, or replace `mako` in the examples below with the executable's full path.

## Quick start

From the repository root:

```powershell
mako -c mako.conf -l::www
```

Then open `http://127.0.0.1:9357/` using the port configured in `mako.conf`.

The empty name in `-l::www` mounts `www/` as the root application. To mount it below `/certmgr/` instead, use:

```powershell
mako -c mako.conf -lcertmgr::www
```

and open `http://127.0.0.1:9357/certmgr/`.

## `mako.conf`

A complete local configuration can look like this:

```lua
host="127.0.0.1"
port=9357
sslport=0

-- Optional. The directory must already exist.
-- Windows uses Mako's /C/... path form.
-- If omitted, SQLite uses Mako Server's standard data directory.
-- dbdir="/C/ProgramData/RealTimeLogic/CertificateManager"

certmgr={
   keyMode="unique",
   testAddress="127.0.0.1",
   testPort=9000,
   testPortCount=20,
   busyTimeout=3000,
   maxAuthorities=100,
   maxCertificatesPerAuthority=10000
}
```

The first four settings are standard Mako Server options used by this application setup:

| Option | Purpose |
|---|---|
| `host` | Make Mako Server listen only on `127.0.0.1`, keeping Certificate Manager local. |
| `port` | HTTP port used to open the application. |
| `sslport` | Set to `0` when Mako Server's separate secure web listener is not configured. |
| `dbdir` | Optional base directory for SQLite data. It must already exist. Certificate Manager uses its `data/certmgr.sqlite.db` file. |

These are all Certificate Manager-specific options:

| Option | Default | Accepted values and meaning |
|---|---:|---|
| `keyMode` | `"unique"` | `"unique"` binds new encrypted private keys to this computer. `"global"` makes new encrypted keys portable within the same administrator-configured Mako Server trust domain. |
| `testAddress` | `"127.0.0.1"` | This-computer-only address used by the temporary certificate-test listener. External addresses are rejected. |
| `testPort` | `9000` | First secure test port to try; integer from 1024 through 65535. |
| `testPortCount` | `20` | Number of consecutive test ports to try; integer from 1 through 100. The resulting range must not exceed 65535. |
| `busyTimeout` | `3000` | SQLite busy timeout in milliseconds; integer from 100 through 30000. |
| `maxAuthorities` | `100` | Maximum number of authority records; integer from 1 through 10000. |
| `maxCertificatesPerAuthority` | `10000` | Maximum issued-certificate records per authority; integer from 1 through 1000000. |

Changing `keyMode` affects new keys only. Existing records retain the mode used when they were created. For a portable certificate database, select `"global"`, use a new empty `dbdir`, and restart Mako Server before creating the first authority. Global mode does not make the application public; it only changes where encrypted key records can be recovered.

## Package as `certmgr.zip`

From inside the `www` directory, create or update the archive with:

```bash
zip -D -q -u -r -9 ../certmgr .
```

This places the application contents at the ZIP root and creates `certmgr.zip` in the repository root. Mutable SQLite data remains outside the archive. Since `-u` updates an existing archive, remove an old `certmgr.zip` first when files have been deleted and you need a clean package.

From the repository root, run the packaged application with:

```powershell
mako -c mako.conf -l::certmgr.zip
```

The same package can be mounted below `/certmgr/` with `-lcertmgr::certmgr.zip`.

## Key and database safety

Authority and server private keys are protected with authenticated encryption inside SQLite. Authority private keys are never offered for download. Exported server private keys are intentionally unencrypted PEM text files so a server can load them without prompting for a password; move each export to its protected deployment location and remove unnecessary copies.

Do not put `certmgr.sqlite.db`, generated keys, exported credentials, or runtime data inside `www/`, `certmgr.zip`, or source control.
