# WebGitDumper

A Python tool for downloading exposed `.git` directories from web servers.

**For authorized security testing, CTF challenges, and educational purposes only.**

## Features

- **Multi-threaded downloads** - Configurable thread count for parallel downloads
- **Proxy support** - HTTP, HTTPS, and SOCKS5 proxy support
- **Progress display** - Real-time progress with download statistics
- **Resume capability** - Skip already downloaded files
- **Retry logic** - Configurable retries with exponential backoff
- **Custom User-Agent** - Randomized or custom UA strings
- **Timeout handling** - Configurable connection/read timeouts
- **SSL verification toggle** - Option to disable for self-signed certificates
- **Smart discovery** - Automatically discovers and downloads git objects by parsing refs, index, pack files, and object contents

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

### Basic Usage

```bash
# Download a .git directory
python webgitdumper.py http://example.com/.git/ ./output

# Or just provide the base URL
python webgitdumper.py http://example.com/ ./output
```

### Command Line Options

```
Usage: webgitdumper.py [OPTIONS] URL OUTPUT_DIR

  WebGitDumper - Download exposed .git directories from web servers.

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
  --help                   Show this message and exit
```

### Examples

```bash
# Use a proxy (e.g., Burp Suite or thermoptic)
python webgitdumper.py http://target.com/.git/ ./repo --proxy http://127.0.0.1:8080

# Use SOCKS5 proxy
python webgitdumper.py http://target.com/.git/ ./repo --proxy socks5://127.0.0.1:1080

# More threads for faster downloads
python webgitdumper.py http://target.com/.git/ ./repo --threads 20

# Custom user agent
python webgitdumper.py http://target.com/.git/ ./repo --user-agent "CustomBot/1.0"

# Disable SSL verification for self-signed certs
python webgitdumper.py https://target.com/.git/ ./repo --no-verify

# Verbose output for debugging
python webgitdumper.py http://target.com/.git/ ./repo --verbose

# Quiet mode (errors only)
python webgitdumper.py http://target.com/.git/ ./repo --quiet
```

### After Downloading

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
