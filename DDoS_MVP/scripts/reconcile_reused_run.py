"""Reconcile two historical test runs that reused one run ID in both logs."""

import argparse
import csv
from datetime import datetime
import os
from pathlib import Path
import shutil
import tempfile
import time


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return reader.fieldnames, list(reader)


def write_csv(path, header, rows):
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8",
                                     dir=path.parent, delete=False) as file:
        temporary_path = Path(file.name)
        writer = csv.DictWriter(file, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary_path, path)


def reconcile(client_path, server_path, excluded_path, run_id):
    client_path, server_path, excluded_path = map(Path, (client_path, server_path, excluded_path))
    client_header, client_rows = read_csv(client_path)
    server_header, server_rows = read_csv(server_path)
    excluded_header, excluded_rows = read_csv(excluded_path)
    if client_header != excluded_header or any(row["run_id"] != run_id for row in excluded_rows):
        raise ValueError("Excluded rows must contain only the selected run and match the client schema")

    client_groups = {}
    server_groups = {}
    for row in client_rows + excluded_rows:
        if row["run_id"] == run_id:
            client_groups.setdefault(row["request_id"], []).append(row)
    for row in server_rows:
        if row["run_id"] == run_id:
            server_groups.setdefault(row["request_id"], []).append(row)
    if not client_groups or client_groups.keys() != server_groups.keys():
        raise ValueError("Client and server request IDs do not match")

    for request_id in client_groups:
        clients = sorted(client_groups[request_id], key=lambda row: row["actual_start_time"])
        servers = sorted(server_groups[request_id], key=lambda row: row["timestamp"])
        if len(clients) != 2 or len(servers) != 2:
            raise ValueError(f"Expected two client and server rows for request {request_id}")
        for index, (client, server) in enumerate(zip(clients, servers), 1):
            client_time = datetime.fromisoformat(client["actual_start_time"])
            server_time = datetime.fromisoformat(server["timestamp"])
            if abs((server_time - client_time).total_seconds()) > 2:
                raise ValueError(f"Timestamp match is uncertain for request {request_id}")
            new_id = f"{run_id}_part{index}"
            client["run_id"] = new_id
            server["run_id"] = new_id

    restored_client_rows = client_rows + excluded_rows
    keys = [(row["run_id"], row["request_id"]) for row in restored_client_rows]
    if len(keys) != len(set(keys)):
        raise ValueError("Reconciliation would leave duplicate client keys")
    server_keys = [(row["run_id"], row["request_id"]) for row in server_rows if row["run_id"]]
    if len(server_keys) != len(set(server_keys)):
        raise ValueError("Reconciliation would leave duplicate server keys")

    stamp = time.time_ns()
    for path in (client_path, server_path):
        shutil.copy2(path, path.with_name(f"{path.name}.bak_{stamp}"))
    write_csv(client_path, client_header, restored_client_rows)
    write_csv(server_path, server_header, server_rows)
    return len(excluded_rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default="data/client_sent.csv")
    parser.add_argument("--server", default="data/requests.csv")
    parser.add_argument("--excluded", default="data/client_sent_duplicates.csv")
    parser.add_argument("--run-id", default="test_run_a0")
    args = parser.parse_args()
    count = reconcile(args.client, args.server, args.excluded, args.run_id)
    print(f"Restored {count} client rows and reconciled both runs; original files were backed up.")
