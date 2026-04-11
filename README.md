# WebGitDumper

A Python tool for downloading exposed `.git` directories from web servers, with an
optional **24/7 watch mode** that hunts for newly issued certificates and dumps
exposed git repositories the moment they appear.

**For authorized security testing, CTF challenges, and educational purposes only.**

## Features

- **Two modes**:
  - `dump` — manually download a single exposed `.git` directory
  - `watch` — monitor a Certificate Transparency stream and auto-dump every exposed `.git` it finds
- **Multi-threaded downloads** - Configurable thread count for parallel downloads
- **Proxy support** - HTTP, HTTPS, and SOCKS5 proxy support
- **Progress display** - Real-time progress with download statistics
- **Resume capability** - Skip already downloaded files
- **Retry logic** - Configurable retries with exponential backoff
- **Custom User-Agent** - Randomized or custom UA strings
- **Timeout handling** - Configurable connection/read timeouts
- **SSL verification toggle** - Option to disable for self-signed certificates
- **Smart discovery** - Automatically discovers and downloads git objects by parsing refs, index, pack files, and object contents
- **Secret scanning** - Optional post-download scan with [trufflehog](https://github.com/trufflesecurity/trufflehog) across the full git history

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/WebGitDumper.git
cd WebGitDumper

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x webgitdumper.py
```

## Usage

WebGitDumper has two subcommands: `dump` (one target) and `watch` (auto-discover via CT logs).

> **Breaking change**: Previous versions used `webgitdumper.py URL OUTPUT_DIR`. The
> equivalent now is `webgitdumper.py dump URL OUTPUT_DIR`.

### `dump` — single target

```bash
# Download a .git directory
python webgitdumper.py dump http://example.com/.git/ ./output

# Or just provide the base URL
python webgitdumper.py dump http://example.com/ ./output
```

#### Options

```
Usage: webgitdumper.py dump [OPTIONS] URL OUTPUT_DIR

  URL: Target URL (e.g., http://example.com/.git/ or http://example.com/)
  OUTPUT_DIR: Directory to save the downloaded repository

Options:
  -t, --threads INTEGER    Number of download threads (default: 10)
  -p, --proxy TEXT         Proxy URL (http://host:port or socks5://host:port)
  --timeout INTEGER        Request timeout in seconds (default: 30)
  -r, --retries INTEGER    Number of retries per file (default: 3)
  -u, --user-agent TEXT    Custom user agent string
  --no-verify              Disable SSL verification
  -v, --verbose            Verbose output
  -q, --quiet              Minimal output
  --scan-secrets           Run trufflehog against the dumped repo after download
  --help                   Show this message and exit
```

#### Examples

```bash
# Use a proxy (e.g., Burp Suite or thermoptic)
python webgitdumper.py dump http://target.com/.git/ ./repo --proxy http://127.0.0.1:8080

# Use SOCKS5 proxy
python webgitdumper.py dump http://target.com/.git/ ./repo --proxy socks5://127.0.0.1:1080

# More threads for faster downloads
python webgitdumper.py dump http://target.com/.git/ ./repo --threads 20

# Custom user agent
python webgitdumper.py dump http://target.com/.git/ ./repo --user-agent "CustomBot/1.0"

# Disable SSL verification for self-signed certs
python webgitdumper.py dump https://target.com/.git/ ./repo --no-verify

# Verbose output for debugging
python webgitdumper.py dump http://target.com/.git/ ./repo --verbose

# Quiet mode (errors only)
python webgitdumper.py dump http://target.com/.git/ ./repo --quiet

# Scan dumped repo for secrets across the full git history
python webgitdumper.py dump http://target.com/.git/ ./repo --scan-secrets
```

### `watch` — 24/7 credential harvester

`watch` subscribes to a Certificate Transparency stream, probes every newly issued
domain for `/.git/HEAD`, and on each hit runs the full dumper + trufflehog pipeline.
Findings are persisted as JSONL and the raw repo is deleted after scanning, so the
output stays small even when running for days.

#### Required infrastructure

You need a running [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go)
instance. The original public Calidog feed (`wss://certstream.calidog.io`) has been broken
for years and Calidog themselves describe it as "demo only". Self-host with one command:

```bash
docker run -d --name certstream -p 8080:8080 0rickyy0/certstream-server-go:latest
```

#### Pipeline

```
certstream WS  →  [check_queue]   →  N GET-probes  →  [dump_queue]   →  M dumpers + trufflehog
   producer       (bounded ~10k)     /.git/HEAD       (bounded 500)     → secrets.jsonl, raw deleted
```

- **Producer**: WebSocket-Thread with auto-reconnect and 30s ping keepalive. Drops domains
  if the queue is full (we can't keep up anyway).
- **Probe workers**: GET `https://{domain}/.git/HEAD` with a short timeout, match
  `ref: refs/heads/` in the body. False-positive-resistant against catch-all SPAs.
- **Dump workers**: Run the existing `GitDumper` against hits, then trufflehog with
  `--no-verification`. Findings are appended to `secrets.jsonl`, raw repo deleted.
- **Dedup**: In-memory set, configurable TTL (default 24h), so the same domain isn't
  re-checked endlessly when it appears in many certs.

#### Output files

- `hits.jsonl` — every domain where `/.git/HEAD` matched, regardless of whether secrets were found
- `secrets.jsonl` — every trufflehog finding (one JSON object per line)

#### Examples

```bash
# Default: watch local certstream-server-go on port 8080
python webgitdumper.py watch ./loot

# Custom certstream URL and tuned worker counts
python webgitdumper.py watch ./loot \
  --certstream-url ws://localhost:8765/full-stream \
  --check-workers 80 \
  --dump-workers 5

# Shorter dedup window for testing
python webgitdumper.py watch ./loot --dedup-ttl 3600
```

#### Options

```
Usage: webgitdumper.py watch [OPTIONS] OUTPUT_DIR

Options:
  --certstream-url TEXT    WebSocket URL of a certstream-server instance
                           (default: ws://localhost:8080/full-stream)
  --check-workers INTEGER  Parallel GET probes for /.git/HEAD (default: 55)
  --dump-workers INTEGER   Parallel full dumps + trufflehog scans (default: 3)
  --check-timeout INTEGER  Timeout for the /.git/HEAD probe in seconds (default: 5)
  --dedup-ttl INTEGER      Skip already-seen domains for N seconds (default: 86400)
  -v, --verbose            Verbose output
  --help                   Show this message and exit
```

### Secret Scanning

With `--scan-secrets`, WebGitDumper invokes [trufflehog](https://github.com/trufflesecurity/trufflehog)
against the dumped `.git` directory after the download finishes. The scan covers the
**entire commit history**, not just the current tree — old commits often hold the most
interesting leaks.

Verification is **explicitly disabled** (`--no-verification`) so trufflehog never sends
discovered credentials to third-party APIs. This avoids leaking secrets to upstream
providers, triggering alerts at the target, or leaving traces in external logs.
Findings must be reviewed manually.

Requires the `trufflehog` binary in `PATH` (`brew install trufflehog`). If not present,
the scan is skipped with a warning instead of failing.

### After Downloading (`dump` mode)

Once the download is complete, you can restore the repository:

```bash
cd ./output
git checkout .
```

Or view the commit history:

```bash
cd ./output
git log --oneline
```

## How It Works

1. **Initial Discovery** - Starts by downloading known git files (HEAD, config, index, refs, etc.)
2. **SHA1 Extraction** - Parses downloaded files for SHA1 hashes (40 hex characters)
3. **Object Discovery** - Queues discovered objects (`objects/XX/XXXXX...`)
4. **Pack File Parsing** - Downloads and parses pack files and their indexes
5. **Recursive Discovery** - Decompresses objects to find additional references
6. **Resume Support** - Skips files that already exist locally

## Technical Details

### Parsed File Types

- **HEAD, refs/** - Branch and tag references
- **index** - Git index file (staged files)
- **packed-refs** - Packed references
- **objects/info/packs** - Pack file listing
- **\*.idx** - Pack index files
- **objects/XX/\*** - Loose objects (decompressed for more refs)

### Object Decompression

The tool decompresses git objects using zlib to:
- Extract SHA1 references from commit and tree objects
- Parse tree objects for file blob references
- Discover the complete object graph

## Legal Disclaimer

This tool is intended for:
- Authorized penetration testing
- CTF (Capture The Flag) competitions
- Security research
- Educational purposes

**Do not use this tool against systems you do not have permission to test.**

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
