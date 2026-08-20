#!/usr/bin/env python3
"""Local stand-in for the stow edge worker.

Serves artifact bundles out of a `stow-mock-registry populate` output
(registry root + records.json) so the CLI can be exercised end to end
without Cloudflare. Implements only the routes the CLI calls.
"""
import collections
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REG_ROOT = sys.argv[1]
RECORDS = sys.argv[2]
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 8787

GHCR_PREFIX = "ghcr.io/stow-rs/cache/"


def sha256_prefixed(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def blob(digest):
    with open(os.path.join(REG_ROOT, "blobs", digest.replace(":", "_")), "rb") as f:
        return f.read()


def manifest_bytes(reference):
    rest = reference[len(GHCR_PREFIX):]
    repo, tag = rest.split(":", 1)
    with open(os.path.join(REG_ROOT, "manifests", repo, tag), "rb") as f:
        return f.read(), repo


def build_bundle_tar(record):
    """Assemble the tar the CLI expects for one artifact record."""
    ref = record["oci_reference"]
    mbytes, repo = manifest_bytes(ref)
    digest = sha256_prefixed(mbytes)
    oci = json.loads(mbytes)
    config_bytes = blob(oci["config"]["digest"])
    config = json.loads(config_bytes)

    files = {
        "oci/manifest.json": mbytes,
        "oci/config.json": config_bytes,
    }
    # outputs first, then the native archive when the config declares one —
    # the order CI pushes the layers in.
    expected = list(config["outputs"])
    if config.get("native_archive"):
        expected.append(config["native_archive"])
    for layer, out in zip(oci["layers"], expected):
        files["files/" + out["file_name"]] = blob(layer["digest"])

    # cosign signature manifest, written by populate as <digest with : -> ->.sig
    sig_ref = digest.replace(":", "-") + ".sig"
    sig_path = os.path.join(REG_ROOT, "manifests", repo, sig_ref)
    sigs = []
    with open(sig_path, "rb") as f:
        sig_manifest = json.load(f)
    for i, layer in enumerate(sig_manifest["layers"]):
        payload = blob(layer["digest"])
        payload_path = "sigstore/payload-%d.json" % i
        files[payload_path] = payload
        ann = layer.get("annotations", {})
        sigs.append({
            "payload_path": payload_path,
            "signature": ann["dev.cosignproject.cosign/signature"],
            "certificate_pem": ann.get("dev.sigstore.cosign/certificate", "mock-local"),
            "rekor_bundle_json": None,
        })

    bundle_manifest = {
        "oci_reference": ref,
        "oci_digest": digest,
        "config": config,
        "sigstore_signatures": sigs,
    }
    files["manifest.json"] = json.dumps(bundle_manifest).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Index:
    def __init__(self, records):
        self.by_exact = {}
        self.by_crate = {}
        for r in records:
            key = (r["target"], r["rustc_version"], r["c_metadata"])
            self.by_exact[key] = r
            self.by_crate.setdefault((r["crate_name"], str(r["version"])), []).append(r)
        self.cache = collections.OrderedDict()
        self.cache_bytes = 0
        self.lock = threading.Lock()

    # Bounded: caching every bundle a large project serves kept gigabytes of
    # rlib bytes resident, which starved the concurrent cargo builds.
    CACHE_MAX_BYTES = 512 * 1024 * 1024

    def bundle(self, record):
        key = record["c_metadata"]
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        data = build_bundle_tar(record)
        with self.lock:
            while self.cache_bytes + len(data) > self.CACHE_MAX_BYTES and self.cache:
                _, evicted = self.cache.popitem(last=False)
                self.cache_bytes -= len(evicted)
            self.cache[key] = data
            self.cache_bytes += len(data)
        return data


with open(RECORDS) as f:
    INDEX = Index(json.load(f))

ARTIFACT_RE = re.compile(r"^/api/v1/artifacts/([^/]+)/([^/]+)/([^/?]+)")

STATS = {"exact_hit": 0, "exact_miss": 0, "batch_hit": 0, "batch_miss": 0,
         "semantic_hit": 0, "semantic_miss": 0}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _trace(self, what):
        sys.stderr.write("[edge] %s\n" % what)
        sys.stderr.flush()

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def do_HEAD(self):
        m = ARTIFACT_RE.match(self.path)
        if not m:
            return self._send(404)
        rec = INDEX.by_exact.get((m.group(1), m.group(2), m.group(3)))
        self._send(200 if rec else 404)

    def do_GET(self):
        if self.path.startswith("/__stats"):
            return self._send(200, json.dumps(STATS).encode())
        self._trace("GET %s" % self.path)
        m = ARTIFACT_RE.match(self.path)
        if not m:
            return self._send(404)
        rec = INDEX.by_exact.get((m.group(1), m.group(2), m.group(3)))
        if not rec:
            STATS["exact_miss"] += 1
            return self._send(404)
        STATS["exact_hit"] += 1
        self._send(200, INDEX.bundle(rec), "application/vnd.stow.bundle.v1+tar")

    def do_POST(self):
        body = self._read_body()
        self._trace("POST %s (%d bytes)" % (self.path, len(body)))
        if self.path.endswith("/api/v1/catalog/graph"):
            return self._graph(body)
        if self.path.endswith("/api/v1/catalog/resolve-lockfile"):
            return self._send(200, json.dumps({
                "lockfile_toml": None, "uncovered_direct": [],
                "candidates_considered": 0, "seed_diagnostics": []}).encode())
        if self.path.endswith("/api/v1/artifacts/batch"):
            return self._batch(body)
        if self.path.endswith("/api/v1/artifacts/semantic"):
            return self._semantic(body)
        self._send(404)

    def _graph(self, body):
        req = json.loads(body)
        if os.environ.get("STUB_DUMP_GRAPH"):
            with open(os.environ["STUB_DUMP_GRAPH"], "wb") as f:
                f.write(body)
        target, rustc = req["target"], req["rustc_version"]
        entries = []
        for dep in req["entries"]:
            arts = [{"c_metadata": c} for c in sorted({
                r["c_metadata"]
                for r in INDEX.by_crate.get((dep["crate_name"], str(dep["version"])), [])
                if r["target"] == target and r["rustc_version"] == rustc})]
            entries.append({"dependency": dep, "current_artifact_count": len(arts),
                            "current_artifacts": arts, "recommended": None})
        expanded, prefetch = [], []
        seen = set()
        for e in req.get("expanded_entries") or []:
            recs = [r for r in INDEX.by_crate.get((e["crate_name"], str(e["version"])), [])
                    if r["target"] == target and r["rustc_version"] == rustc]
            if recs:
                expanded.append({"crate_name": e["crate_name"], "version": e["version"],
                                 "features": e["features"]})
            for r in recs:
                k = (r["crate_name"], r["c_metadata"])
                if k not in seen:
                    seen.add(k)
                    prefetch.append({"crate_name": r["crate_name"], "c_metadata": r["c_metadata"]})
        prefetch.sort(key=lambda e: (e["crate_name"], e["c_metadata"]))
        self._send(200, json.dumps({
            "entries": entries,
            "expanded_cached": len(expanded),
            "expanded_total": len(req.get("expanded_entries") or []),
            "expanded_entries": expanded,
            "prefetch_artifacts": prefetch,
        }).encode())

    def _batch(self, body):
        req = json.loads(body)
        target, rustc = req["target"], req["rustc_version"]
        manifest_entries, bundles = [], {}
        for e in req["entries"]:
            rec = INDEX.by_exact.get((target, rustc, e["c_metadata"]))
            if rec and rec["crate_name"] == e["crate_name"]:
                path = "bundles/%s.tar" % e["c_metadata"]
                bundles[path] = INDEX.bundle(rec)
                manifest_entries.append({"crate_name": e["crate_name"],
                                         "c_metadata": e["c_metadata"], "bundle_path": path})
                STATS["batch_hit"] += 1
            else:
                manifest_entries.append({"crate_name": e["crate_name"],
                                         "c_metadata": e["c_metadata"], "bundle_path": None})
                STATS["batch_miss"] += 1
        manifest = json.dumps({"target": target, "rustc_version": rustc,
                               "entries": manifest_entries}).encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("batch-manifest.json")
            info.size = len(manifest)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(manifest))
            for name in sorted(bundles):
                data = bundles[name]
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mtime = 0
                tar.addfile(info, io.BytesIO(data))
        self._send(200, buf.getvalue(), "application/vnd.stow.batch.v1+tar")

    def _semantic(self, body):
        req = json.loads(body)
        cands = INDEX.by_crate.get((req["crate_name"], str(req["version"])), [])
        for r in cands:
            if (r["target"] == req["target"] and r["rustc_version"] == req["rustc_version"]
                    and r["features_json"] == req["features_json"]
                    and r["dependency_c_metadata_json"] == req["dependency_c_metadata_json"]):
                STATS["semantic_hit"] += 1
                return self._send(200, INDEX.bundle(r), "application/vnd.stow.bundle.v1+tar")
        STATS["semantic_miss"] += 1
        self._send(404)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("edge stub on %d, %d records" % (PORT, len(INDEX.by_exact)), flush=True)
    srv.serve_forever()
