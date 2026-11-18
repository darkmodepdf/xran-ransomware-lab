"""Fetch the publisher's log archives by verified byte ranges."""

import argparse
import concurrent.futures
import hashlib
from pathlib import Path
import time
import urllib.request


RECORD = 'https://zenodo.org/api/records/18218588/files'
ARCHIVES = {
    'benign': (83_376_646, 'c6667140e2eb181dd40a7cfe041328cb'),
    'ransomware': (1_236_098_725, '7cca7a5c61b0300e867874a5115d0872'),
    'rat': (933_356_069, '2f9215e20261042c7f62fd6e7a8201cd'),
    'spyware': (348_639_305, '1e3f2a05b4eeb936357f2ebb7c7e750a'),
}
CHUNK_BYTES = 16 * 1024 * 1024


def fetch_chunk(url, start, end, size, output):
    expected = end - start + 1
    if output.exists() and output.stat().st_size == expected:
        return output
    temporary = output.with_suffix('.part')
    for attempt in range(3):
        try:
            request = urllib.request.Request(
                f'{url}?chunk={start}-{end}',
                headers={'Range': f'bytes={start}-{end}', 'Accept-Encoding': 'identity'},
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                if response.status != 206 or response.headers.get('Content-Range') != f'bytes {start}-{end}/{size}':
                    raise ValueError('Publisher returned an unexpected byte range')
                written = 0
                with temporary.open('wb') as file:
                    while block := response.read(1024 * 1024):
                        written += len(block)
                        if written > expected:
                            raise ValueError('Publisher returned more bytes than requested')
                        file.write(block)
                if written != expected:
                    raise ValueError(f'Short byte range {start}-{end}: {written}')
            temporary.replace(output)
            return output
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def download(name, root, workers):
    size, expected_md5 = ARCHIVES[name]
    output = root / f'{name}.7z'
    if output.exists():
        with output.open('rb') as source:
            if hashlib.file_digest(source, 'md5').hexdigest() == expected_md5:
                print(f'{output}: publisher checksum verified', flush=True)
                return
        raise ValueError(f'Existing archive has a different checksum: {output}')
    parts = root / f'{name}.chunks'
    parts.mkdir(exist_ok=True)
    url = f'{RECORD}/{name}.7z/content'
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(fetch_chunk, url, start, min(start + CHUNK_BYTES, size) - 1, size, parts / f'{start:012d}.bin')
            for start in range(0, size, CHUNK_BYTES)
        ]
        for index, future in enumerate(concurrent.futures.as_completed(futures), 1):
            future.result()
            if index % 10 == 0 or index == len(futures):
                print(f'{name}: {index}/{len(futures)} ranges verified', flush=True)
    digest = hashlib.md5()
    temporary = output.with_suffix('.assembling')
    with temporary.open('wb') as destination:
        for chunk in (future.result() for future in futures):
            with chunk.open('rb') as source:
                while block := source.read(1024 * 1024):
                    destination.write(block)
                    digest.update(block)
    if temporary.stat().st_size != size or digest.hexdigest() != expected_md5:
        raise ValueError(f'Assembled archive failed the publisher checksum: {name}')
    temporary.replace(output)
    for future in futures:
        future.result().unlink()
    parts.rmdir()
    print(f'{output}: publisher checksum verified', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=range(1, 9), default=6)
    parser.add_argument('archives', nargs='+', choices=ARCHIVES)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name in args.archives:
        download(name, args.out, args.workers)


if __name__ == '__main__':
    main()
