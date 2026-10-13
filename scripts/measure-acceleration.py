#!/usr/bin/env python3
"""Measure what a developer gains from stow on one project (stow#627).

Builds the project several times under plain cargo and under stow, each
arm in a fresh target directory, and records every sample: wall clock,
CPU time of everything the command started, and how many dependencies
stow served.

The arms, run in this order in every round:

  cargo        `cargo build` with the runner's linker
  cargo-mold   `cargo build` with the linker selection `stow setup` writes,
               so the linker's share is separated from the cache's
  stow-miss    `stow build` with a fresh local cache and the registry and
               the edge refused: every unit compiles under stow's wrapper
  stow-cold    `stow build` with a fresh local cache against the public cache
  stow-warm    `stow build` again with stow-cold's local cache and a fresh
               target directory

After the full build of cargo, cargo-mold and stow-warm, the incremental
round touches one workspace source file and rebuilds in the same target
directory, `--increments` times.

Linux only. CPU time is read from a cgroup the script moves itself into,
so a process a command leaves behind is counted too: a sample's `cpu_ms`
is what ran until the command returned, `settle_cpu_ms` what ran after
that until its last process exited.

The plain-cargo arms and the stow arms use separate `CARGO_HOME`s:
`stow setup` writes its `rustc-wrapper` and linker selection into the
global cargo config, and a cargo arm sharing that file would not be
plain cargo.
"""

import argparse
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import tomllib

CGROUP = pathlib.Path("/sys/fs/cgroup/stow-measure")
SETTLE_DEADLINE_S = 120
SETTLE_POLL_S = 0.05
BUILD_DEADLINE_S = 4 * 3600
SERVED = re.compile(r"stow: served (\d+) of (\d+) cacheable dependencies")
COMPILING = re.compile(r"^\s+Compiling ", re.MULTILINE)
LINUX_TABLE = 'cfg(target_os = "linux")'
# What a developer's shell does not carry but a CI job's environment does:
# each of these changes what the build compiles or how, so none may leak
# from the runner into an arm.
SCRUBBED = (
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_INCREMENTAL",
    "CARGO_PROFILE_DEV_DEBUG",
    "CARGO_TARGET_DIR",
    "RUST_LOG",
)


def die(message):
    sys.exit(f"measure-acceleration: {message}")


def enter_cgroup():
    """Move this process into its own cgroup; every child inherits it."""
    subprocess.run(["sudo", "mkdir", "-p", str(CGROUP)], check=True)
    subprocess.run(
        ["sudo", "tee", str(CGROUP / "cgroup.procs")],
        input=f"{os.getpid()}\n",
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    membership = pathlib.Path("/proc/self/cgroup").read_text().strip()
    if not membership.endswith("/" + CGROUP.name):
        die(f"not in {CGROUP}: {membership}")


def cpu_usec():
    """`(user, system)` microseconds the cgroup has consumed so far."""
    fields = dict(line.split() for line in (CGROUP / "cpu.stat").read_text().splitlines())
    return int(fields["user_usec"]), int(fields["system_usec"])


def other_pids():
    own = os.getpid()
    return [int(pid) for pid in (CGROUP / "cgroup.procs").read_text().split() if int(pid) != own]


def command_line(pid):
    try:
        raw = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes()
    except FileNotFoundError:
        return ""
    return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def settle():
    """Wait for everything the last command started to exit.

    Returns the seconds waited and the command lines of what was still
    running at the deadline; those processes are killed so they cannot
    run into the next sample.
    """
    started = time.monotonic()
    while other_pids():
        if time.monotonic() - started > SETTLE_DEADLINE_S:
            leftovers = {pid: command_line(pid) for pid in other_pids()}
            for pid in leftovers:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while other_pids():
                time.sleep(SETTLE_POLL_S)
            return time.monotonic() - started, sorted(leftovers.values())
        time.sleep(SETTLE_POLL_S)
    return time.monotonic() - started, []


class Lab:
    def __init__(self, args):
        self.stow = args.stow
        self.project = pathlib.Path(args.project).resolve()
        self.cargo_args = args.cargo_args
        self.touch = self.project / args.touch
        if not self.touch.is_file():
            die(f"--touch names no file: {self.touch}")
        self.increments = args.increments
        self.out = pathlib.Path(args.out).resolve()
        self.logs = self.out / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.work = self.out / "work"
        self.work.mkdir()
        self.samples = (self.out / "samples.jsonl").open("w")
        self.rows = []

        base = dict(os.environ)
        for name in list(base):
            if name in SCRUBBED or name.startswith("STOW_"):
                del base[name]
        base["RUSTUP_TOOLCHAIN"] = args.rustc
        base["CARGO_TERM_COLOR"] = "never"
        self.base = base
        self.cargo_home = self.work / "cargo-home-plain"
        self.stow_home = self.work / "cargo-home-stow"
        self.counter = 0

    def fresh(self, label):
        self.counter += 1
        path = self.work / f"{label}-{self.counter}"
        path.mkdir()
        return path

    def env(self, cargo_home, target, **extra):
        return dict(self.base, CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target), **extra)

    def prepare(self):
        """Everything a sample must not pay for: sources and stow's setup."""
        for home in (self.cargo_home, self.stow_home):
            home.mkdir()
            subprocess.run(
                ["cargo", "fetch"],
                cwd=self.project,
                env=dict(self.base, CARGO_HOME=str(home)),
                check=True,
                timeout=1800,
            )
        subprocess.run(
            [self.stow, "setup"],
            cwd=self.project,
            env=dict(self.base, CARGO_HOME=str(self.stow_home)),
            check=True,
            timeout=900,
        )
        settle()
        config = tomllib.loads((self.stow_home / "config.toml").read_text())
        rustflags = config["target"][LINUX_TABLE]["rustflags"]
        compiler_path = config["env"]["COMPILER_PATH"]
        # The linker selection `stow setup` wrote, handed to the
        # cargo-mold arm on its command line: the same flags and the same
        # mold, without stow's wrapper.
        self.mold_config = [
            "--config",
            f"target.'{LINUX_TABLE}'.rustflags={json.dumps(rustflags)}",
            "--config",
            f"env.COMPILER_PATH.value={json.dumps(compiler_path['value'])}",
            "--config",
            f"env.COMPILER_PATH.force={json.dumps(compiler_path['force'])}",
        ]

    def facts(self, args):
        def output(argv, **kwargs):
            return subprocess.run(
                argv, capture_output=True, text=True, check=True, timeout=120, **kwargs
            ).stdout.strip()

        env = dict(self.base, CARGO_HOME=str(self.cargo_home))
        return {
            "project": args.project_name,
            "project_commit": output(["git", "rev-parse", "HEAD"], cwd=self.project),
            "cargo_args": self.cargo_args,
            "touch": args.touch,
            "rounds": args.rounds,
            "increments": args.increments,
            "cpus": os.cpu_count(),
            "rustc": output(["rustc", "-vV"], env=env),
            "cargo": output(["cargo", "-V"], env=env),
            "stow": output([self.stow, "--version"]),
            "stow_commit": os.environ.get("GITHUB_SHA", ""),
            "mold_config": self.mold_config,
            "runner": output(["uname", "-srm"]),
        }

    def sample(self, arm, kind, round_number, index, argv, env):
        name = f"{arm}-{kind}-r{round_number}-{index}"
        stdout_path = self.logs / f"{name}.stdout"
        stderr_path = self.logs / f"{name}.stderr"
        user_before, system_before = cpu_usec()
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            # The exit is waited for with a blocking wait under a timer, not
            # `subprocess.run(timeout=…)`: that one polls for the exit with
            # sleeps of up to 50 ms, and every wall time would carry the
            # quantum.
            overdue = threading.Event()
            started = time.monotonic_ns()
            build = subprocess.Popen(
                argv,
                cwd=self.project,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
            )
            deadline = threading.Timer(BUILD_DEADLINE_S, lambda: (overdue.set(), build.kill()))
            deadline.start()
            exit_code = build.wait()
            ended = time.monotonic_ns()
            deadline.cancel()
        if overdue.is_set():
            die(f"{name} was killed at its {BUILD_DEADLINE_S} s deadline")
        user_after, system_after = cpu_usec()
        settle_seconds, leftovers = settle()
        user_settled, system_settled = cpu_usec()
        stdout_text = stdout_path.read_text(errors="replace")
        stderr_text = stderr_path.read_text(errors="replace")
        served = SERVED.search(stdout_text)
        row = {
            "arm": arm,
            "kind": kind,
            "round": round_number,
            "index": index,
            "exit_code": exit_code,
            "wall_ms": (ended - started) / 1e6,
            "cpu_user_ms": (user_after - user_before) / 1e3,
            "cpu_system_ms": (system_after - system_before) / 1e3,
            "settle_ms": settle_seconds * 1e3,
            "settle_cpu_ms": (user_settled + system_settled - user_after - system_after) / 1e3,
            "left_running": leftovers,
            "compiling_lines": len(COMPILING.findall(stderr_text)),
            "served": int(served[1]) if served else None,
            "cacheable": int(served[2]) if served else None,
        }
        self.samples.write(json.dumps(row) + "\n")
        self.samples.flush()
        self.rows.append(row)
        print(json.dumps(row), flush=True)
        if exit_code != 0:
            sys.stderr.write(stderr_text[-4000:])
            die(f"{name} failed with exit code {exit_code}")
        return row

    def full_then_incremental(self, arm, round_number, argv, env, increments):
        self.sample(arm, "full", round_number, 0, argv, env)
        for index in range(1, increments + 1):
            os.utime(self.touch)
            self.sample(arm, "incremental", round_number, index, argv, env)

    def round(self, number):
        cargo = ["cargo", "build", *self.cargo_args]
        stow = [self.stow, "build", *self.cargo_args]

        target = self.fresh("target")
        self.full_then_incremental(
            "cargo", number, cargo, self.env(self.cargo_home, target), self.increments
        )
        shutil.rmtree(target)

        target = self.fresh("target")
        self.full_then_incremental(
            "cargo-mold",
            number,
            cargo + self.mold_config,
            self.env(self.cargo_home, target),
            self.increments,
        )
        shutil.rmtree(target)

        target, cache = self.fresh("target"), self.fresh("cache")
        refused = refused_origin()
        self.full_then_incremental(
            "stow-miss",
            number,
            stow,
            self.env(
                self.stow_home,
                target,
                STOW_CACHE_DIR=str(cache),
                STOW_EDGE_URL=refused,
                STOW_REGISTRY_BASE_URL=f"{refused}/water-rs/stow",
            ),
            0,
        )
        shutil.rmtree(target)
        shutil.rmtree(cache)

        target, cache = self.fresh("target"), self.fresh("cache")
        self.full_then_incremental(
            "stow-cold",
            number,
            stow,
            self.env(self.stow_home, target, STOW_CACHE_DIR=str(cache)),
            0,
        )
        shutil.rmtree(target)

        target = self.fresh("target")
        self.full_then_incremental(
            "stow-warm",
            number,
            stow,
            self.env(self.stow_home, target, STOW_CACHE_DIR=str(cache)),
            self.increments,
        )
        shutil.rmtree(target)
        shutil.rmtree(cache)


def refused_origin():
    """An origin nothing listens on: every connection is refused at once."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


def summary(rows, facts):
    """The medians as a Markdown table; `samples.jsonl` holds every sample."""
    lines = [
        f"## {facts['project']} at `{facts['project_commit'][:12]}`",
        "",
        f"`cargo build {shlex.join(facts['cargo_args'])}` on {facts['cpus']} CPUs, "
        f"{facts['rustc'].splitlines()[0]}, {facts['stow']}.",
        "",
        "| arm | build | samples | wall s (median) | wall s (min–max) | CPU s (median) | CPU s after return | served / cacheable |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    groups = {}
    for row in rows:
        groups.setdefault((row["arm"], row["kind"]), []).append(row)
    for (arm, kind), group in groups.items():
        walls = [row["wall_ms"] / 1e3 for row in group]
        cpus = [(row["cpu_user_ms"] + row["cpu_system_ms"]) / 1e3 for row in group]
        settles = [row["settle_cpu_ms"] / 1e3 for row in group]
        served = sorted({(row["served"], row["cacheable"]) for row in group if row["served"] is not None})
        lines.append(
            f"| {arm} | {kind} | {len(group)} | {statistics.median(walls):.2f} | "
            f"{min(walls):.2f}–{max(walls):.2f} | {statistics.median(cpus):.2f} | "
            f"{statistics.median(settles):.2f} | "
            f"{', '.join(f'{have} / {total}' for have, total in served) or '—'} |"
        )

    def median_cpu(arm):
        group = groups.get((arm, "full"), [])
        return statistics.median(row["cpu_user_ms"] + row["cpu_system_ms"] for row in group)

    units = statistics.median(row["compiling_lines"] for row in groups[("stow-miss", "full")])
    overhead = (median_cpu("stow-miss") - median_cpu("cargo-mold")) / units
    lines += [
        "",
        f"An all-miss stow build spends {overhead:.1f} ms of CPU per compiled unit over "
        f"cargo with the same linker ({units:.0f} units).",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--stow", required=True, help="path of the stow-cli binary")
    parser.add_argument("--project", required=True, help="checkout of the project to build")
    parser.add_argument("--project-name", required=True, help="owner/name, for the report")
    parser.add_argument("--rustc", required=True, help="toolchain every arm builds with")
    parser.add_argument("--touch", required=True, help="source file touched per incremental build")
    parser.add_argument("--rounds", type=int, required=True)
    parser.add_argument("--increments", type=int, required=True)
    parser.add_argument("--out", required=True, help="directory for samples, logs and work dirs")
    parser.add_argument("--summary", help="file the Markdown summary is appended to")
    parser.add_argument("--cargo-args", type=shlex.split, default=[], help="arguments after `cargo build`")
    args = parser.parse_args()

    if sys.platform != "linux":
        die("Linux only: CPU time is read from a cgroup")
    enter_cgroup()
    lab = Lab(args)
    lab.prepare()
    facts = lab.facts(args)
    (lab.out / "facts.json").write_text(json.dumps(facts, indent=2) + "\n")
    for number in range(1, args.rounds + 1):
        lab.round(number)
    report = summary(lab.rows, facts)
    (lab.out / "summary.md").write_text(report)
    if args.summary:
        with open(args.summary, "a") as sink:
            sink.write(report)
    print(report)
    shutil.rmtree(lab.work)


if __name__ == "__main__":
    main()
