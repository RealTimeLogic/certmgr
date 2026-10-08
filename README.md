# Certificate Manager - Private Certificates Made Practical

Certificate Manager is a free, local web application for creating and operating a private Public Key Infrastructure (PKI): your own system for issuing and trusting certificates. It helps developers and administrators create a root certificate authority, issue server certificates for encrypted connections, export deployment-ready certificates and keys, and verify the result without assembling a collection of command-line tools.

It is a practical fit for development environments, internal services, lab equipment, and embedded or Internet of Things (IoT) products where you control which clients trust your root certificate. The application runs on [Mako Server](https://makoserver.net/), uses Mako Server's built-in certificate services, and keeps all persistent records in a SQLite database.

For the complete workflow, see [How to act as a Certificate Authority (the Easy Way)](https://realtimelogic.com/articles/How-to-act-as-a-Certificate-Authority-the-Easy-Way).

## What you can do

- Create root authorities using P-256/P-384 elliptic-curve keys or 2048/3072-bit RSA keys. RSA is a widely supported public-key algorithm.
- Issue certificates for server authentication using host names and version 4 Internet Protocol addresses, such as 127.0.0.1. Each certificate uses the same key algorithm as its authority, and Mako Server applies the server purpose and certificate permissions automatically.
- Download certificates in Privacy-Enhanced Mail (PEM) text format, binary `.cer` format, complete PEM chains, and SharkSSL trust-list format.
- Export an issued server certificate's matching private key as a PEM file for deployment.
- Start a temporary secure listener available only on this computer and test a certificate before deployment.
- Keep authority private keys behind Mako Server's key-protection interface or protect them with authenticated encryption, depending on the selected algorithm and configuration.

Certificate Manager is intentionally a local administration tool. Both the application and its temporary certificate-test listener are restricted to this computer.

## Requirements

- Mako Server with Barracuda App Server (BAS) library version 6358 or later. This version provides the explicit certificate-profile API plus the database, encryption, and private-key protection services used by Certificate Manager.
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
| `keyMode` | `"unique"` | `"unique"` keeps new keys bound to this computer and is the recommended choice for a local installation. `"global"` supports planned database portability within the same administrator-configured Mako Server trust domain. See [Key and database safety](#key-and-database-safety). |
| `testAddress` | `"127.0.0.1"` | This-computer-only address used by the temporary certificate-test listener. External addresses are rejected. |
| `testPort` | `9000` | First secure test port to try; integer from 1024 through 65535. |
| `testPortCount` | `20` | Number of consecutive test ports to try; integer from 1 through 100. The resulting range must not exceed 65535. |
| `busyTimeout` | `3000` | SQLite busy timeout in milliseconds; integer from 100 through 30000. |
| `maxAuthorities` | `100` | Maximum number of authority records; integer from 1 through 10000. |
| `maxCertificatesPerAuthority` | `10000` | Maximum issued-certificate records per authority; integer from 1 through 1000000. |

Choose the protection mode before creating the first authority. For a database intended to stay on one computer, keep the default `"unique"` setting. For planned portability, select `"global"`, use a new empty `dbdir`, and restart Mako Server before creating the first authority. Global mode does not make the application remotely accessible.

## Key and database safety

The Certificate Authority (CA) private key is the most sensitive part of a private certificate system. It is the secret that lets an authority sign new certificates. Anyone who obtains it could create certificates that appear to come from that authority.

In the recommended unique mode, a new elliptic-curve authority key can remain behind Mako Server's key-protection interface instead of being stored in the database. Authority keys that must be stored are protected with authenticated encryption. In every case, Certificate Manager uses the authority key only for signing and does not provide a page, action, or download route for it. You can safely distribute the public root certificate without distributing the private key.

### How authority keys are protected

Several safeguards work together:

| Safeguard | What it means |
|---|---|
| No authority-key export | Certificate Manager never offers the authority private key for download. Certificate downloads contain only public information. |
| TPM-backed elliptic-curve authorities | With `keyMode="unique"` and a Mako Server that provides `ba.tpm.createcertificate`, a new elliptic-curve authority key stays behind Mako Server's Trusted Platform Module (TPM) protection interface. SQLite stores only an internal key reference. It does not store the authority private-key bytes. |
| Authenticated encryption for other authority keys | RSA authority keys, global-mode elliptic-curve authority keys, and elliptic-curve authority keys created with an older Mako Server are encrypted before entering SQLite. Mako Server uses authenticated encryption, which both hides the key and detects a modified key record. |
| Use only when signing | An authority key is used only when the authority is created or when you deliberately issue a certificate. A TPM-backed key is selected by its internal name. An encrypted key is decrypted in memory for the signing operation and is not returned to the browser. |
| Local administration boundary | The application rejects connections that do not originate from the same computer. The temporary certificate-test listener is also restricted to the same computer. Keep `host="127.0.0.1"` and the default `testAddress="127.0.0.1"`. |
| Protected browser actions | Operations that change data require a form submitted from the current browser session. Server private-key downloads require the same protection and create an audit event. There is no corresponding authority-key action. |

These controls prevent routine browsing, certificate downloads, database inspection, and accidental form requests from exposing an authority key. Local-only access does not replace operating-system security, so run Mako Server under a trusted account and protect access to the computer.

### Choosing `unique` or `global`

For most local installations, keep the default:

```lua
certmgr={
   keyMode="unique"
}
```

Unique mode binds private-key recovery to this computer:

- New elliptic-curve authority keys use the TPM-backed method when the required Mako Server function is available.
- RSA authority keys, server keys, and compatible encrypted records use encryption derived specifically for this computer.
- Copying the database to a different computer does not produce an operational Certificate Manager installation because that computer cannot recreate or decrypt the protected keys.

Use `keyMode="global"` only when you have deliberately configured multiple Mako Server installations to share the required trust-domain protection. Global mode stores new authority keys as authenticated ciphertext so the database can be moved within that configured trust domain. The database remains sensitive and still requires restricted file access.

### Upgrading Mako Server

An upgrade does not silently replace or convert an existing authority key:

- An elliptic-curve authority created by an older Mako Server remains an encrypted record and continues using its stored unique or global protection mode.
- New elliptic-curve authorities created after upgrading can use TPM-backed protection when `keyMode="unique"` and `ba.tpm.createcertificate` is available.
- A database can therefore contain both older encrypted authorities and newer TPM-backed authorities.

An existing authority cannot be converted to a different private key while preserving the same root certificate. Creating a replacement authority creates a new root certificate, which must be installed on every system that should trust it.

If a database contains a TPM-backed authority, Certificate Manager rejects a later change from `keyMode="unique"` to `keyMode="global"` during startup. To move to global mode, create a new empty database and create new authorities there. The startup message states that the database must be rebuilt.

### Protecting and backing up the database

Certificate Manager stores `certmgr.sqlite.db` in Mako Server's configured data directory. The database contains public certificates, issuance records, audit events, encrypted private keys, and TPM key references. Treat it as an administrative security file even though private-key records are protected.

For a dependable backup:

1. Stop Mako Server so the SQLite database is not being updated.
2. Copy the complete `certmgr.sqlite.db` file to storage with restricted access.
3. Preserve the Mako Server computer identity or configured trust-domain protection required by the selected `keyMode`.
4. Test restoration in an isolated environment before relying on the backup.

A unique-mode database is suitable for recovery on the same protected computer, but it is not a portable disaster-recovery copy for another computer. If cross-computer recovery is a requirement, configure global mode with a new database before creating the first authority.

### Handling exported server private keys

Authority private keys cannot be exported. An issued server certificate is different because the destination server needs its matching private key. Certificate Manager therefore provides a separate, explicit server-key download from the certificate detail page.

The downloaded PEM file is intentionally not password-protected so a server can load it without waiting for someone to enter a password. Save it directly to the protected deployment location, restrict access to the server account, and remove unnecessary copies from browser download folders, transfer media, email, and backups.

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
