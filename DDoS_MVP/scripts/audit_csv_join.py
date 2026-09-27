"""Report which client/server log rows can be joined without ambiguous IDs."""

import argparse
import csv
from collections import Counter
from pathlib import Path


def keyed_rows(path):
    with Path(path).open(newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    keys = Counter(
        (row.get("run_id", ""), row.get("request_id", ""))
        for row in rows
        if row.get("run_id") and row.get("request_id")
    )
    return rows, keys


def audit(client_path, server_path):
    client_rows, client_keys = keyed_rows(client_path)
    server_rows, server_keys = keyed_rows(server_path)
    unique_matches = {
        key for key, count in client_keys.items()
        if count == 1 and server_keys[key] == 1
    }
    ambiguous = {
        key for key in client_keys.keys() | server_keys.keys()
        if client_keys[key] > 1 or server_keys[key] > 1
    }
    return {
        "client_rows": len(client_rows),
        "server_rows": len(server_rows),
        "unique_matches": len(unique_matches),
        "ambiguous_keys": len(ambiguous),
        "client_only_keys": len(client_keys.keys() - server_keys.keys()),
        "server_only_keys": len(server_keys.keys() - client_keys.keys()),
        "missing_client_ids": sum(not row.get("run_id") or not row.get("request_id") for row in client_rows),
        "missing_server_ids": sum(not row.get("run_id") or not row.get("request_id") for row in server_rows),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="data/client_sent.csv")
    parser.add_argument("--server", default="data/requests.csv")
    args = parser.parse_args()
    for name, count in audit(args.client, args.server).items():
        print(f"{name}: {count}")
