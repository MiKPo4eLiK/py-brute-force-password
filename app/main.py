import time
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict

PASSWORDS_TO_BRUTE_FORCE = [
    "b4061a4bcfe1a2cbf78286f3fab2fb578266d1bd16c414c650c5ac04dfc696e1",
    "cf0b0cfc90d8b4be14e00114827494ed5522e9aa1c7e6960515b58626cad0b44",
    "e34efeb4b9538a949655b788dcb517f4a82e997e9e95271ecd392ac073fe216d",
    "c15f56a2a392c950524f499093b78266427d21291b7d7f9d94a09b4e41d65628",
    "4cd1a028a60f85a1b94f918adb7fb528d7429111c52bb2aa2874ed054a5584dd",
    "40900aa1d900bee58178ae4a738c6952cb7b3467ce9fde0c3efa30a3bde1b5e2",
    "5e6bc66ee1d2af7eb3aad546e9c0f79ab4b4ffb04a1bc425a80e6a4b0f055c2e",
    "1273682fa19625ccedbe2de2817ba54dbb7894b7cefb08578826efad492f51c9",
    "7e8f0ada0a03cbee48a0883d549967647b3fca6efeb0a149242f19e4b68d53d6",
    "e5f3ff26aa8075ce7513552a9af1882b4fbc2a47a3525000f6eb887ab9622207",
]
TARGET_HASHES = frozenset(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def worker_range(start: int, end: int, target_hashes: frozenset,
                 found_proxy: Dict[str, str], stop_event) -> int:
    found_here = 0
    for i in range(start, end):
        if stop_event.is_set():
            break
        pwd = f"{i:08d}"
        h = sha256_hash_str(pwd)
        if h in target_hashes and h not in found_proxy:
            found_proxy[h] = pwd
            found_here += 1
            if len(found_proxy) >= len(target_hashes):
                stop_event.set()
                break
    return found_here


def main() -> None:
    start_time = time.time()

    TOTAL = 10 ** 8
    CHUNK_SIZE = 1_000_000
    max_workers = None

    manager = multiprocessing.Manager()
    found_passwords = manager.dict()
    stop_event = manager.Event()

    ranges = []
    for s in range(0, TOTAL, CHUNK_SIZE):
        e = min(s + CHUNK_SIZE, TOTAL)
        ranges.append((s, e))

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(worker_range, s, e, TARGET_HASHES, found_passwords, stop_event)
            for s, e in ranges
        ]

        try:
            for fut in as_completed(futures):
                _ = fut.result()
                if stop_event.is_set():
                    break
        except KeyboardInterrupt:
            stop_event.set()
            raise

    end_time = time.time()
    total_time = end_time - start_time

    print("\nTotal execution time:", total_time)
    if len(found_passwords) != len(TARGET_HASHES):
        print(f"\nWarning: found {len(found_passwords)} of {len(TARGET_HASHES)} targets.")
    else:
        print("\nAll targets found.")

    print("\nAll found passwords:")
    for hash_val in sorted(found_passwords.keys()):
        pwd = found_passwords[hash_val]
        print(f"Hash: {hash_val} -> Password: {pwd}")


if __name__ == "__main__":
    main()
