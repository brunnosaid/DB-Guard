# DB-Guard

Initial MVP for bulk-checking domain names against the Spamhaus Domain Blocklist (DBL) and generating an Excel report.

## What it does

1. Reads a TXT file containing one domain per line.
2. Normalizes and deduplicates domains.
3. Queries Spamhaus DBL via DNS.
4. Interprets official DBL return codes.
5. Writes `DB-Guard_Report.xlsx` with:
   - red rows for **LISTED** domains;
   - green rows for **NOT LISTED** domains;
   - yellow rows for **ERROR** conditions;
   - a summary worksheet.

## Spamhaus DBL return-code handling

Listings:

- `127.0.1.2` — Spam domain
- `127.0.1.4` — Phishing domain
- `127.0.1.5` — Malware domain
- `127.0.1.6` — Botnet C&C domain
- `127.0.1.102` — Abused legitimate domain / spam
- `127.0.1.103` — Abused/spammed redirector
- `127.0.1.104` — Abused legitimate domain / phishing
- `127.0.1.105` — Abused legitimate domain / malware
- `127.0.1.106` — Abused legitimate domain / botnet C&C

Errors/not-listings:

- NXDOMAIN / no A record — **NOT LISTED**
- `127.0.1.255` — IP query prohibited
- `127.255.255.252` — DNSBL name error
- `127.255.255.254` — query through public/open resolver
- `127.255.255.255` — excessive query volume

The `127.255.255.x` responses are treated as **ERROR**, never as malicious listings.

## Build

Install the Rust toolchain and run:

```bash
cargo build --release
```

The executable will be available under `target/release/`.

## Usage

Default:

```bash
cargo run --release -- --input Domains.txt
```

Custom output:

```bash
cargo run --release -- --input Domains.txt --output results.xlsx
```

Recommended production mode using Spamhaus DQS:

```bash
cargo run --release -- --input Domains.txt --dqs-key YOUR_DQS_KEY
```

You can also provide the key through the environment variable:

```bash
SPAMHAUS_DQS_KEY=YOUR_DQS_KEY cargo run --release -- --input Domains.txt
```

On Windows PowerShell:

```powershell
$env:SPAMHAUS_DQS_KEY="YOUR_DQS_KEY"
cargo run --release -- --input .\Domains.txt --output .\DB-Guard_Report.xlsx
```

## TXT format

```text
example.com
dbltest.com
some-domain.tld
```

Blank lines and lines beginning with `#` are ignored. IP addresses are rejected because Spamhaus DBL is domain-only.

## Notes

For automated or production use, prefer Spamhaus DQS instead of relying on the public zone. The application deliberately caps concurrency (`--concurrency`, default 10) rather than issuing uncontrolled parallel requests.

Official references:

- https://www.spamhaus.org/blocklists/domain-blocklist/
- https://docs.spamhaus.com/

## Input sanitization

The input loader normalizes each non-empty line before querying Spamhaus. It accepts plain domains, email addresses, and common URL/host forms. For example:

```text
bounce-776092e70d5348f5e3bd65fbe069bed3@envios.suantc.com -> envios.suantc.com
<User@MAIL.Example.COM> -> mail.example.com
https://sub.example.com/path -> sub.example.com
```

Normalization happens **before deduplication**, so multiple mailbox addresses under the same domain cause only one DBL query.
