#!/usr/bin/env python3
"""
WebGitDumper - A tool for downloading exposed .git directories from web servers.

For authorized security testing, CTF challenges, and educational purposes only.
"""

import hashlib
import logging
import os
import queue
import random
import re
import struct
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urljoin, urlparse

import click
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.logging import RichHandler

# User agent strings for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]

# Known git files to start with
INITIAL_FILES = [
    "HEAD",
    "config",
    "description",
    "index",
    "packed-refs",
    "COMMIT_EDITMSG",
    "FETCH_HEAD",
    "ORIG_HEAD",
    "refs/heads/master",
    "refs/heads/main",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/stash",
    "logs/HEAD",
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/remotes/origin/HEAD",
    "logs/refs/remotes/origin/master",
    "logs/refs/remotes/origin/main",
    "info/refs",
    "info/exclude",
    "objects/info/packs",
]

# Regex for SHA1 hashes (40 hex characters)
SHA1_PATTERN = re.compile(r"\b([a-f0-9]{40})\b", re.IGNORECASE)

console = Console()


@dataclass
class Stats:
    """Statistics for the download process."""
    downloaded: int = 0
    skipped: int = 0
    errors: int = 0
    queued: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)
    error_types: dict = field(default_factory=dict)
    _shown_errors: set = field(default_factory=set)

    def increment_downloaded(self):
        with self.lock:
            self.downloaded += 1

    def increment_skipped(self):
        with self.lock:
            self.skipped += 1

    def add_error(self, category: str, path: str, detail: str = ""):
        with self.lock:
            self.errors += 1
            if category not in self.error_types:
                self.error_types[category] = []
            self.error_types[category].append((path, detail))

    def should_show_error(self, category: str) -> bool:
        """Return True if this error category hasn't been shown yet."""
        with self.lock:
            if category not in self._shown_errors:
                self._shown_errors.add(category)
                return True
            return False

    def set_queued(self, count: int):
        with self.lock:
            self.queued = count


class GitDumper:
    """Main class for downloading exposed .git directories."""

    def __init__(
        self,
        url: str,
        output_dir: str,
        threads: int = 10,
        proxy: Optional[str] = None,
        timeout: int = 30,
        retries: int = 3,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.base_url = self._normalize_url(url)
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.quiet = quiet

        self.stats = Stats()
        self.downloaded_files: Set[str] = set()
        self.queued_files: Set[str] = set()
        self.file_queue: queue.Queue = queue.Queue()
        self.lock = threading.Lock()

        self._setup_logging()
        self._setup_session()

    def _normalize_url(self, url: str) -> str:
        """Normalize the URL to point to the .git directory."""
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        path = parsed.path.rstrip("/")

        if not path.endswith(".git"):
            if path:
                path = path + "/.git"
            else:
                path = "/.git"

        return f"{parsed.scheme}://{parsed.netloc}{path}/"

    def _setup_logging(self):
        """Configure logging based on verbosity settings."""
        if self.quiet:
            level = logging.ERROR
        elif self.verbose:
            level = logging.DEBUG
        else:
            level = logging.INFO

        logging.basicConfig(
            level=level,
            format="%(message)s",
            handlers=[RichHandler(console=console, show_time=False, show_path=False)],
        )
        self.logger = logging.getLogger("webgitdumper")

    def _setup_session(self):
        """Configure the requests session with retries and proxy."""
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Configure proxy
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # Configure SSL verification
        self.session.verify = self.verify_ssl

    def _get_user_agent(self) -> str:
        """Get the user agent string."""
        if self.user_agent:
            return self.user_agent
        return random.choice(USER_AGENTS)

    def _download_file(self, path: str) -> tuple:
        """Download a single file from the git directory.

        Returns (content, error_category, error_detail) tuple.
        On success: (bytes, None, None). On failure: (None, category, detail).
        """
        url = urljoin(self.base_url, path)

        try:
            headers = {"User-Agent": self._get_user_agent()}
            response = self.session.get(
                url, headers=headers, timeout=self.timeout, allow_redirects=False
            )

            if response.status_code == 200:
                return (response.content, None, None)
            elif response.status_code == 404:
                self.logger.debug(f"Not found: {path}")
                return (None, "HTTP 404 (Not Found)", "")
            else:
                self.logger.debug(f"HTTP {response.status_code} for {path}")
                return (None, f"HTTP {response.status_code}", "")

        except requests.exceptions.ConnectionError as e:
            self.logger.debug(f"Connection error for {path}: {e}")
            return (None, "Connection Error", str(e)[:120])
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout for {path}")
            return (None, "Timeout", f">{self.timeout}s")
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Error downloading {path}: {e}")
            return (None, "Request Error", str(e)[:120])

    def _save_file(self, path: str, content: bytes) -> bool:
        """Save downloaded content to a file."""
        file_path = self.output_dir / ".git" / path

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)
            return True
        except OSError as e:
            self.logger.error(f"Error saving {path}: {e}")
            return False

    def _file_exists(self, path: str) -> bool:
        """Check if a file already exists (for resume capability)."""
        file_path = self.output_dir / ".git" / path
        return file_path.exists() and file_path.stat().st_size > 0

    def _extract_sha1_hashes(self, content: bytes) -> Set[str]:
        """Extract SHA1 hashes from content."""
        hashes = set()
        try:
            text = content.decode("utf-8", errors="ignore")
            matches = SHA1_PATTERN.findall(text)
            hashes.update(h.lower() for h in matches)
        except Exception:
            pass
        return hashes

    def _sha1_to_path(self, sha1: str) -> str:
        """Convert a SHA1 hash to an object path."""
        return f"objects/{sha1[:2]}/{sha1[2:]}"

    def _parse_index_file(self, content: bytes) -> Set[str]:
        """Parse a git index file to extract SHA1 hashes."""
        hashes = set()
        try:
            if len(content) < 12:
                return hashes

            # Check signature
            if content[:4] != b"DIRC":
                return hashes

            # Parse header
            version = struct.unpack(">I", content[4:8])[0]
            num_entries = struct.unpack(">I", content[8:12])[0]

            self.logger.debug(f"Index version: {version}, entries: {num_entries}")

            offset = 12
            for _ in range(min(num_entries, 10000)):  # Limit to prevent infinite loops
                if offset + 62 > len(content):
                    break

                # Extract SHA1 (at offset 40 from entry start)
                sha1_offset = offset + 40
                if sha1_offset + 20 <= len(content):
                    sha1 = content[sha1_offset : sha1_offset + 20].hex()
                    hashes.add(sha1)

                # Skip to filename
                if version >= 4:
                    # Version 4 uses variable-length encoding
                    offset += 62
                    while offset < len(content) and content[offset] != 0:
                        offset += 1
                    offset += 1
                else:
                    # Version 2/3
                    name_offset = offset + 62
                    name_end = content.find(b"\x00", name_offset)
                    if name_end == -1:
                        break
                    entry_len = name_end - offset + 1
                    # Pad to 8-byte boundary
                    offset += (entry_len + 7) & ~7

        except Exception as e:
            self.logger.debug(f"Error parsing index: {e}")

        return hashes

    def _parse_pack_index(self, content: bytes) -> Set[str]:
        """Parse a pack index file to extract SHA1 hashes."""
        hashes = set()
        try:
            if len(content) < 8:
                return hashes

            # Check for v2 signature
            if content[:4] == b"\xff\x74\x4f\x63":
                version = struct.unpack(">I", content[4:8])[0]
                if version == 2:
                    # Skip fanout table (256 * 4 bytes)
                    offset = 8 + 256 * 4
                    # Get total object count from last fanout entry
                    total_objects = struct.unpack(">I", content[8 + 255 * 4 : 8 + 256 * 4])[0]

                    # Extract SHA1s
                    for i in range(min(total_objects, 100000)):
                        sha1_start = offset + i * 20
                        if sha1_start + 20 <= len(content):
                            sha1 = content[sha1_start : sha1_start + 20].hex()
                            hashes.add(sha1)
        except Exception as e:
            self.logger.debug(f"Error parsing pack index: {e}")

        return hashes

    def _parse_packed_refs(self, content: bytes) -> Set[str]:
        """Parse packed-refs file for SHA1 hashes and refs."""
        hashes = set()
        refs = set()

        try:
            text = content.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("^"):
                    # Peeled ref
                    sha1 = line[1:].strip()
                    if len(sha1) == 40:
                        hashes.add(sha1.lower())
                else:
                    parts = line.split()
                    if len(parts) >= 2:
                        sha1 = parts[0]
                        ref = parts[1]
                        if len(sha1) == 40:
                            hashes.add(sha1.lower())
                        if ref.startswith("refs/"):
                            refs.add(ref)
        except Exception as e:
            self.logger.debug(f"Error parsing packed-refs: {e}")

        return hashes, refs

    def _parse_objects_info_packs(self, content: bytes) -> Set[str]:
        """Parse objects/info/packs for pack file names."""
        packs = set()
        try:
            text = content.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("P "):
                    pack_name = line[2:].strip()
                    if pack_name.endswith(".pack"):
                        packs.add(f"objects/pack/{pack_name}")
                        idx_name = pack_name[:-5] + ".idx"
                        packs.add(f"objects/pack/{idx_name}")
        except Exception:
            pass
        return packs

    def _decompress_object(self, content: bytes) -> Optional[bytes]:
        """Decompress a git object and extract referenced SHA1s."""
        hashes = set()
        try:
            decompressed = zlib.decompress(content)
            # Extract SHA1s from decompressed content
            hashes = self._extract_sha1_hashes(decompressed)

            # Parse tree objects for additional refs
            if decompressed.startswith(b"tree "):
                null_idx = decompressed.find(b"\x00")
                if null_idx != -1:
                    tree_data = decompressed[null_idx + 1 :]
                    offset = 0
                    while offset < len(tree_data):
                        # Find mode/name separator
                        space_idx = tree_data.find(b" ", offset)
                        if space_idx == -1:
                            break
                        null_idx = tree_data.find(b"\x00", space_idx)
                        if null_idx == -1:
                            break
                        # Extract SHA1 (20 bytes after null)
                        sha1_start = null_idx + 1
                        if sha1_start + 20 <= len(tree_data):
                            sha1 = tree_data[sha1_start : sha1_start + 20].hex()
                            hashes.add(sha1)
                        offset = sha1_start + 20

        except zlib.error:
            pass
        except Exception as e:
            self.logger.debug(f"Error decompressing object: {e}")

        return hashes

    def _queue_file(self, path: str):
        """Add a file to the download queue if not already queued."""
        with self.lock:
            if path not in self.queued_files and path not in self.downloaded_files:
                self.queued_files.add(path)
                self.file_queue.put(path)
                self.stats.set_queued(self.file_queue.qsize())

    def _process_file(self, path: str, content: bytes):
        """Process downloaded content to discover new files."""
        new_hashes = set()
        new_files = set()

        # Extract SHA1 hashes from text content
        new_hashes.update(self._extract_sha1_hashes(content))

        # Special handling for specific files
        if path == "index":
            new_hashes.update(self._parse_index_file(content))
        elif path == "packed-refs":
            hashes, refs = self._parse_packed_refs(content)
            new_hashes.update(hashes)
            new_files.update(refs)
        elif path == "objects/info/packs":
            new_files.update(self._parse_objects_info_packs(content))
        elif path.endswith(".idx"):
            new_hashes.update(self._parse_pack_index(content))
        elif path.startswith("objects/") and not path.endswith((".pack", ".idx")):
            new_hashes.update(self._decompress_object(content))

        # Queue discovered objects
        for sha1 in new_hashes:
            obj_path = self._sha1_to_path(sha1)
            self._queue_file(obj_path)

        # Queue discovered files
        for file_path in new_files:
            self._queue_file(file_path)

    def _print_error(self, progress: Progress, category: str, path: str, detail: str = ""):
        """Print a styled error line for the first occurrence of each error category."""
        ERROR_STYLES = {
            "HTTP 404 (Not Found)": ("dim red", "?"),
            "Connection Error": ("bold red", "!"),
            "Timeout": ("yellow", "~"),
            "Save Failed": ("bold magenta", "!"),
            "Worker Exception": ("bold red", "!"),
            "Request Error": ("red", "!"),
        }
        # Match HTTP status codes generically
        if category.startswith("HTTP ") and category not in ERROR_STYLES:
            style, icon = ("red", "x")
        else:
            style, icon = ERROR_STYLES.get(category, ("red", "x"))

        if self.stats.should_show_error(category):
            detail_str = f" - {detail}" if detail else ""
            count_later = ""
        else:
            # For repeated categories, only show every 10th to avoid spam
            with self.stats.lock:
                cat_count = len(self.stats.error_types.get(category, []))
            if cat_count <= 5 or cat_count % 25 == 0:
                detail_str = f" - {detail}" if detail else ""
                count_later = f" [dim](#{cat_count})[/dim]"
            else:
                return

        progress.console.print(
            f"  [{style}]{icon} {category}[/{style}]: {path}{detail_str}{count_later}"
        )

    def _worker(self, progress: Progress, task: TaskID):
        """Worker thread for downloading files."""
        while True:
            try:
                path = self.file_queue.get(timeout=1)
            except queue.Empty:
                continue

            if path is None:
                break

            try:
                # Check if file already exists (resume)
                if self._file_exists(path):
                    self.logger.debug(f"Skipping existing file: {path}")
                    self.stats.increment_skipped()
                    with self.lock:
                        self.downloaded_files.add(path)

                    # Still process existing files for new refs
                    file_path = self.output_dir / ".git" / path
                    try:
                        content = file_path.read_bytes()
                        self._process_file(path, content)
                    except Exception:
                        pass
                else:
                    # Download the file
                    content, err_cat, err_detail = self._download_file(path)

                    if content is not None:
                        if self._save_file(path, content):
                            self.stats.increment_downloaded()
                            with self.lock:
                                self.downloaded_files.add(path)
                            self._process_file(path, content)
                            self.logger.debug(f"Downloaded: {path}")
                        else:
                            self.stats.add_error("Save Failed", path, "Could not write file to disk")
                            self._print_error(progress, "Save Failed", path, "Could not write file to disk")
                    else:
                        self.stats.add_error(err_cat, path, err_detail)
                        self._print_error(progress, err_cat, path, err_detail)

            except Exception as e:
                self.stats.add_error("Worker Exception", path, str(e)[:120])
                self._print_error(progress, "Worker Exception", path, str(e)[:120])
            finally:
                self.file_queue.task_done()
                self.stats.set_queued(self.file_queue.qsize())
                progress.update(
                    task,
                    description=f"[cyan]Downloaded: {self.stats.downloaded} | Skipped: {self.stats.skipped} | Queued: {self.stats.queued} | Errors: {self.stats.errors}",
                )

    def run(self):
        """Main entry point for the git dumper."""
        if not self.quiet:
            console.print(f"[bold blue]WebGitDumper[/bold blue]")
            console.print(f"Target: {self.base_url}")
            console.print(f"Output: {self.output_dir}")
            console.print(f"Threads: {self.threads}")
            if self.proxy:
                console.print(f"Proxy: {self.proxy}")
            console.print()

        # Create output directory
        (self.output_dir / ".git").mkdir(parents=True, exist_ok=True)

        # Queue initial files
        for path in INITIAL_FILES:
            self._queue_file(path)

        # Start workers with progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Starting...", total=None
            )

            # Start worker threads
            workers = []
            for _ in range(self.threads):
                t = threading.Thread(target=self._worker, args=(progress, task))
                t.daemon = True
                t.start()
                workers.append(t)

            # Wait for queue to be empty
            while True:
                time.sleep(0.5)
                if self.file_queue.empty() and all(
                    not t.is_alive() or self.file_queue.unfinished_tasks == 0
                    for t in workers
                ):
                    # Double-check after a brief pause
                    time.sleep(1)
                    if self.file_queue.empty() and self.file_queue.unfinished_tasks == 0:
                        break

            # Signal workers to stop
            for _ in workers:
                self.file_queue.put(None)

            # Wait for workers to finish
            for t in workers:
                t.join(timeout=5)

        # Print summary
        if not self.quiet:
            console.print()
            console.print("[bold green]Download complete![/bold green]")
            console.print(f"  Downloaded: {self.stats.downloaded}")
            console.print(f"  Skipped: {self.stats.skipped}")
            console.print(f"  Errors: {self.stats.errors}")

            if self.stats.error_types:
                console.print()
                console.print("[bold red]Error breakdown:[/bold red]")
                for category, entries in sorted(
                    self.stats.error_types.items(),
                    key=lambda x: len(x[1]),
                    reverse=True,
                ):
                    count = len(entries)
                    console.print(f"  [red]{category}[/red]: {count}")
                    # Show up to 3 example paths for each category
                    examples = entries[:3]
                    for path, detail in examples:
                        detail_str = f" ({detail})" if detail else ""
                        console.print(f"    [dim]- {path}{detail_str}[/dim]")
                    if count > 3:
                        console.print(f"    [dim]... and {count - 3} more[/dim]")

            console.print()
            console.print(f"[dim]Try running 'cd {self.output_dir} && git checkout .' to restore files[/dim]")


@click.command()
@click.argument("url")
@click.argument("output_dir")
@click.option("--threads", "-t", default=10, help="Number of download threads (default: 10)")
@click.option("--proxy", "-p", help="Proxy URL (http://host:port or socks5://host:port)")
@click.option("--timeout", default=30, help="Request timeout in seconds (default: 30)")
@click.option("--retries", "-r", default=3, help="Number of retries per file (default: 3)")
@click.option("--user-agent", "-u", help="Custom user agent string")
@click.option("--no-verify", is_flag=True, help="Disable SSL verification")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def main(
    url: str,
    output_dir: str,
    threads: int,
    proxy: Optional[str],
    timeout: int,
    retries: int,
    user_agent: Optional[str],
    no_verify: bool,
    verbose: bool,
    quiet: bool,
):
    """
    WebGitDumper - Download exposed .git directories from web servers.

    URL: Target URL (e.g., http://example.com/.git/ or http://example.com/)

    OUTPUT_DIR: Directory to save the downloaded repository

    For authorized security testing only.
    """
    # Suppress SSL warnings if verification is disabled
    if no_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        dumper = GitDumper(
            url=url,
            output_dir=output_dir,
            threads=threads,
            proxy=proxy,
            timeout=timeout,
            retries=retries,
            user_agent=user_agent,
            verify_ssl=not no_verify,
            verbose=verbose,
            quiet=quiet,
        )
        dumper.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
