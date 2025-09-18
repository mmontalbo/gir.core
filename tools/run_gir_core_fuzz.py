#!/usr/bin/env python3
"""Helper for instrumenting and fuzzing Gir.Core's SourceFunc harness."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = Path(os.environ.get("GIR_CORE_ROOT", SCRIPT_DIR.parent))
PROJECT_PATH = REPO_ROOT / "src/Tests/Fuzzing/SourceFuncFuzzer/SourceFuncFuzzer.csproj"
PROPS_FILE = REPO_ROOT / "properties/GirCore.Fuzzing.props"
GENERATED_IMPORT_RESOLVER = REPO_ROOT / "src/Libs/GObject-2.0/Internal/ImportResolver.Generated.cs"
PUBLISH_ROOT = REPO_ROOT / "src/Tests/Fuzzing/SourceFuncFuzzer/bin/Release"
PUBLISH_DIR = PUBLISH_ROOT / "publish"
INSTRUMENTED_DIR = PUBLISH_ROOT / "instrumented"
ASSEMBLY_NAME = "SourceFuncFuzzer.dll"
ASSEMBLY_PATH = INSTRUMENTED_DIR / ASSEMBLY_NAME
DEFAULT_CORPUS_DIR = REPO_ROOT / "src/Tests/Fuzzing/SourceFuncFuzzer/corpus"
DEFAULT_FINDINGS_DIR_BASE = REPO_ROOT / "src/Tests/Fuzzing/SourceFuncFuzzer/findings"
DEFAULT_TESTCACHE = 200

SECONDARY_VARIANTS = [
    ("mopt", ["-L", "0", "-p", "fast"], {}),
    ("trim-explore", ["-p", "explore"], {"AFL_DISABLE_TRIM": "1"}),
    ("trim-exploit", ["-p", "exploit"], {"AFL_DISABLE_TRIM": "1"}),
    ("trim-rare", ["-p", "rare"], {"AFL_DISABLE_TRIM": "1"}),
    ("trim-lin", ["-p", "lin"], {"AFL_DISABLE_TRIM": "1"}),
    ("oldqueue", ["-Z", "-p", "coe"], {"AFL_DISABLE_TRIM": "1"}),
    ("ascii", ["-a", "ascii", "-p", "explore"], {}),
    ("binary", ["-a", "binary", "-p", "exploit"], {}),
    ("fast", ["-p", "fast"], {"AFL_DISABLE_TRIM": "1"}),
    ("quad", ["-p", "quad"], {}),
]


@dataclass
class CrashEntry:
    path: Path
    afl_id_raw: Optional[str]
    afl_id: Optional[int]
    signal_raw: Optional[str]
    signal_num: Optional[int]
    fields: Dict[str, str]
    size: int
    modified: dt.datetime
    fuzzer_name: str

    @property
    def relative_path(self) -> Path:
        try:
            return self.path.relative_to(REPO_ROOT)
        except ValueError:
            return self.path


def die(message: str, exit_code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(exit_code)


def ensure_project_paths() -> None:
    if not PROJECT_PATH.is_file():
        die(f"Unable to locate the SourceFuncFuzzer project at {PROJECT_PATH}.")

    if not PROPS_FILE.is_file():
        die(f"Unable to locate {PROPS_FILE}.")


def require_command(command: str, message: str) -> str:
    path = shutil.which(command)
    if path:
        return path
    die(message)
    return ""


def read_sharpfuzz_version() -> str:
    try:
        props_text = PROPS_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        die(f"Failed to read {PROPS_FILE}: {exc}")

    match = re.search(r"<SharpFuzzVersion>([^<]+)</SharpFuzzVersion>", props_text)
    if not match:
        die(f"Failed to read SharpFuzzVersion from {PROPS_FILE}.")

    return match.group(1).strip()


def instrument_harness(print_hint: bool = True) -> None:
    ensure_project_paths()

    if not GENERATED_IMPORT_RESOLVER.is_file():
        die(
            "Generated bindings are required but "
            f"{GENERATED_IMPORT_RESOLVER} was not found.\n"
            "Run 'dotnet fsi scripts/GenerateLibs.fsx' before instrumenting the harness."
        )

    sharpfuzz_version = read_sharpfuzz_version()
    dotnet_path = require_command(
        "dotnet",
        "The dotnet CLI is required. Install the .NET SDK (9.0 or later) and ensure 'dotnet' is on your PATH.",
    )
    sharpfuzz_path = require_command(
        "sharpfuzz",
        "SharpFuzz.CommandLine is required. Install or update it with "
        f"'dotnet tool update --global SharpFuzz.CommandLine --version {sharpfuzz_version}' "
        "(run with 'install' instead of 'update' if needed).",
    )

    print("Building SourceFuncFuzzer harness...")
    subprocess.run(
        [dotnet_path, "publish", str(PROJECT_PATH), "-c", "Release", "-o", str(PUBLISH_DIR)],
        check=True,
    )

    print("Preparing instrumented output directory...")
    if INSTRUMENTED_DIR.exists():
        shutil.rmtree(INSTRUMENTED_DIR)
    INSTRUMENTED_DIR.mkdir(parents=True, exist_ok=True)

    for item in PUBLISH_DIR.iterdir():
        destination = INSTRUMENTED_DIR / item.name
        if item.is_dir():
            shutil.copytree(item, destination)
        else:
            shutil.copy2(item, destination)

    if not ASSEMBLY_PATH.is_file():
        die(f"The published assembly could not be found at {ASSEMBLY_PATH}.")

    print(f"Instrumenting {ASSEMBLY_NAME} with SharpFuzz...")
    subprocess.run([sharpfuzz_path, str(ASSEMBLY_PATH), "GirCore.Fuzzing.SourceFuncFuzzer"], check=True)

    print("Instrumentation complete.")
    print(f"Instrumented assembly: {ASSEMBLY_PATH}")
    print(f"Use the files in {INSTRUMENTED_DIR} as the harness when running your fuzzer.")
    if print_hint:
        print("Run 'tools/run_gir_core_fuzz.py afl' to start AFL++ with the default configuration.")


def ensure_seed_corpus(corpus_dir: Path, default_seed: Path) -> None:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    if not default_seed.exists() or default_seed.stat().st_size == 0:
        default_seed.write_bytes(b"seed")


def ensure_env(var: str, value: str, message: str) -> None:
    if var not in os.environ:
        os.environ[var] = value
        print(message, file=sys.stderr)


def maybe_warn_core_pattern() -> None:
    core_pattern_path = Path("/proc/sys/kernel/core_pattern")
    try:
        pattern = core_pattern_path.read_text(encoding="utf-8").strip()
    except OSError:
        return

    if pattern.startswith("|"):
        print(
            f"Warning: {core_pattern_path} pipes core dumps to an external handler.",
            file=sys.stderr,
        )
        print(
            "         AFL++ may treat crashes as timeouts until this is adjusted.",
            file=sys.stderr,
        )

        if "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES" not in os.environ:
            os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
            print(
                "         Setting AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 for this session.",
                file=sys.stderr,
            )
            print(
                f"         To handle crashes immediately instead, run 'echo core | sudo tee {core_pattern_path}' before fuzzing.",
                file=sys.stderr,
            )
        else:
            value = os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"]
            print(f"         AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES={value}.", file=sys.stderr)
            print(
                f"         Consider adjusting {core_pattern_path} to write core files directly.",
                file=sys.stderr,
            )


def parse_memory_limit(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str) and value == "none":
        return "none"
    if isinstance(value, int):
        if value < 0:
            die("--memory requires a non-negative integer or 'none'.")
        return str(value)
    die("--memory requires a non-negative integer or 'none'.")
    return None


def format_size(num_bytes: int) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < step or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= step
    return f"{num_bytes} B"


def format_signal(signal_num: Optional[int]) -> str:
    if signal_num is None:
        return "?"
    try:
        signal_name = signal.Signals(signal_num).name
        return f"{signal_name} ({signal_num})"
    except ValueError:
        return str(signal_num)


def parse_crash_name(name: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for part in name.split(","):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        fields[key] = value
    return fields


def gather_crashes(run_dir: Path) -> List[CrashEntry]:
    crashes: List[CrashEntry] = []
    if not run_dir.is_dir():
        return crashes

    for root, dirs, files in os.walk(run_dir):
        if Path(root).name != "crashes":
            continue
        crash_dir = Path(root)
        fuzzer_name = crash_dir.parent.name
        for name in sorted(files):
            if name.startswith("README"):
                continue
            path = crash_dir / name
            if not path.is_file():
                continue
            fields = parse_crash_name(name)
            afl_id_raw = fields.get("id")
            afl_id = None
            if afl_id_raw and afl_id_raw.isdigit():
                try:
                    afl_id = int(afl_id_raw)
                except ValueError:
                    afl_id = None
            signal_raw = fields.get("sig")
            signal_num = None
            if signal_raw and signal_raw.isdigit():
                try:
                    signal_num = int(signal_raw)
                except ValueError:
                    signal_num = None
            try:
                stat = path.stat()
                modified = dt.datetime.fromtimestamp(stat.st_mtime)
                size = stat.st_size
            except OSError:
                continue
            crashes.append(
                CrashEntry(
                    path=path,
                    afl_id_raw=afl_id_raw,
                    afl_id=afl_id,
                    signal_raw=signal_raw,
                    signal_num=signal_num,
                    fields=fields,
                    size=size,
                    modified=modified,
                    fuzzer_name=fuzzer_name,
                )
            )

    crashes.sort(key=lambda c: (c.afl_id if c.afl_id is not None else sys.maxsize, c.path.name))
    return crashes


def list_findings_runs(base_dir: Path) -> List[Path]:
    if not base_dir.exists():
        return []
    runs: List[Path] = []
    for child in base_dir.iterdir():
        if child.is_dir():
            runs.append(child)
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs


def resolve_findings_directory(value: Optional[str]) -> Path:
    base_dir = DEFAULT_FINDINGS_DIR_BASE
    if value:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        if not candidate.is_dir():
            die(f"Unable to locate findings directory {candidate}.")
        return candidate

    runs = list_findings_runs(base_dir)
    if not runs:
        die(f"No findings directories were found under {base_dir}.")
    return runs[0]


def format_metadata(fields: Dict[str, str], omit: Iterable[str]) -> str:
    parts: List[str] = []
    for key in sorted(fields):
        if key in omit:
            continue
        parts.append(f"{key}={fields[key]}")
    return ", ".join(parts)


def hexdump(data: bytes, width: int = 16) -> str:
    lines: List[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3 - 1}}  {ascii_part}")
    return "\n".join(lines)


def resolve_crash_identifier(
    crashes: Sequence[CrashEntry], identifier: str, run_dir: Path
) -> CrashEntry:
    token = identifier.strip()
    if not token:
        die("An empty crash identifier was provided.")

    if token.startswith("#"):
        token = token[1:]

    if token.startswith("id:"):
        target = token[3:]
        for entry in crashes:
            if entry.afl_id_raw == target:
                return entry
        die(f"No crash with id:{target} was found in {run_dir}.")

    if token.isdigit():
        index = int(token)
        if 1 <= index <= len(crashes):
            return crashes[index - 1]
        die(f"Crash index {index} is out of range (1-{len(crashes)}).")

    candidate = Path(token)
    if not candidate.is_absolute():
        candidate = (run_dir / candidate).resolve()
    for entry in crashes:
        if entry.path.resolve() == candidate:
            return entry
    die(f"Unable to match crash identifier '{identifier}' to a known crash in {run_dir}.")
    raise AssertionError("unreachable")


def show_crash_details(entry: CrashEntry, run_dir: Path, max_bytes: int) -> None:
    print(f"Crash detail: {entry.path}")
    if entry.afl_id_raw:
        print(f"  AFL id      : {entry.afl_id_raw}")
    if entry.signal_num is not None:
        print(f"  Signal      : {format_signal(entry.signal_num)}")
    print(f"  Size        : {entry.size} bytes")
    print(f"  Modified    : {entry.modified.isoformat(sep=' ', timespec='seconds')}")
    print(f"  Fuzzer      : {entry.fuzzer_name}")
    metadata = format_metadata(entry.fields, {"id", "sig"})
    if metadata:
        print("  Metadata    : " + metadata)

    if max_bytes > 0:
        try:
            data = entry.path.read_bytes()[:max_bytes]
        except OSError as exc:
            print(f"  Hexdump     : failed to read crash file ({exc})")
            return
        if data:
            print(f"  Hexdump     : first {len(data)} byte(s)")
            print(textwrap.indent(hexdump(data), "    "))
        else:
            print("  Hexdump     : (empty input)")

    relative = entry.path
    try:
        relative = entry.path.relative_to(REPO_ROOT)
    except ValueError:
        pass
    assembly_rel = ASSEMBLY_PATH
    try:
        assembly_rel = ASSEMBLY_PATH.relative_to(REPO_ROOT)
    except ValueError:
        pass
    print("  Reproduce   :")
    print(
        textwrap.indent(
            f"dotnet {assembly_rel} < {relative}",
            "    ",
        )
    )
    print(
        textwrap.indent(
            f"./tools/run_gir_core_fuzz.py analyze --replay {relative}",
            "    ",
        )
    )


def replay_crash(entry: CrashEntry) -> None:
    if not ASSEMBLY_PATH.is_file():
        die(
            f"The instrumented harness was not found at {ASSEMBLY_PATH}. "
            "Run the script with 'instrument' before replaying crashes."
        )

    dotnet_path = require_command(
        "dotnet",
        "The dotnet CLI is required to execute the harness. Install the .NET SDK (9.0 or later).",
    )

    print(f"Replaying crash {entry.afl_id_raw or entry.path.name}...")
    try:
        with entry.path.open("rb") as crash_file:
            result = subprocess.run(
                [dotnet_path, str(ASSEMBLY_PATH)],
                stdin=crash_file,
                capture_output=True,
                text=True,
                check=False,
            )
    except OSError as exc:
        die(f"Failed to execute the harness: {exc}")

    return_code = result.returncode
    if return_code < 0:
        sig_num = -return_code
        print(f"Harness terminated by signal {format_signal(sig_num)}")
    else:
        print(f"Harness exited with code {return_code}")

    if result.stdout:
        print("--- harness stdout ---")
        print(result.stdout.rstrip())
    if result.stderr:
        print("--- harness stderr ---")
        print(result.stderr.rstrip())


def analyze_findings(args: argparse.Namespace) -> None:
    if args.list_runs:
        runs = list_findings_runs(DEFAULT_FINDINGS_DIR_BASE)
        if not runs:
            print(f"No findings directories were found under {DEFAULT_FINDINGS_DIR_BASE}.")
            return
        print("Available findings runs:")
        for path in runs:
            try:
                mtime = dt.datetime.fromtimestamp(path.stat().st_mtime)
                timestamp = mtime.isoformat(sep=" ", timespec="seconds")
            except OSError:
                timestamp = "unknown"
            try:
                relative = path.relative_to(DEFAULT_FINDINGS_DIR_BASE)
            except ValueError:
                relative = path
            print(f"  {relative}\t({timestamp})")
        return

    run_dir = resolve_findings_directory(args.findings)
    try:
        relative_run = run_dir.relative_to(DEFAULT_FINDINGS_DIR_BASE)
    except ValueError:
        relative_run = run_dir
    print(f"Analyzing findings in {relative_run}")

    crashes = gather_crashes(run_dir)
    if not crashes:
        print("No crash files were found.")
        return

    total = len(crashes)
    signal_counts = collections.Counter(entry.signal_num for entry in crashes)

    print(f"Total crashes: {total}")
    known_signals = {k: v for k, v in signal_counts.items() if k is not None}
    unknown_count = signal_counts.get(None, 0)
    if known_signals or unknown_count:
        print("Signal distribution:")
        for sig, count in sorted(known_signals.items(), key=lambda item: item[0]):
            print(f"  {format_signal(sig):<18} {count}")
        if unknown_count:
            print(f"  Unknown            {unknown_count}")

    limit = args.limit
    if limit == 0 or limit > total:
        limit = total

    print()
    print(f"Listing {limit} crash(es):")
    for index, entry in enumerate(crashes[:limit], start=1):
        meta = format_metadata(entry.fields, {"id", "sig"})
        if meta:
            meta = f" [{meta}]"
        try:
            rel_path = entry.path.relative_to(run_dir)
        except ValueError:
            rel_path = entry.path
        modified = entry.modified.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"[{index:>2}] id={entry.afl_id_raw or '??????'} "
            f"sig={format_signal(entry.signal_num):<18} "
            f"size={format_size(entry.size):<8} "
            f"fuzzer={entry.fuzzer_name:<16} "
            f"time={modified} -> {rel_path}{meta}"
        )

    if args.show:
        print()
        entry = resolve_crash_identifier(crashes, args.show, run_dir)
        show_crash_details(entry, run_dir, args.max_bytes)

    if args.replay:
        entry = resolve_crash_identifier(crashes, args.replay, run_dir)
        print()
        replay_crash(entry)


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return number


def memory_option(value: str) -> object:
    if value == "none":
        return "none"
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer or 'none'") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value must be non-negative or 'none'")
    return number


def build_parser() -> argparse.ArgumentParser:
    description = textwrap.dedent(
        """\
        Instrument the Gir.Core SourceFunc harness and orchestrate AFL++ campaigns.

        Commands:
          instrument   Build and instrument the SourceFunc harness (default).
          afl          Instrument (unless --skip-instrument) and launch AFL++.
          analyze      Inspect crash artefacts produced by AFL++ runs.
        """
    )

    parser = argparse.ArgumentParser(
        prog="run_gir_core_fuzz.py",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")
    parser.set_defaults(command="instrument")

    instrument_parser = subparsers.add_parser(
        "instrument", help="Build and instrument the SourceFunc harness"
    )
    instrument_parser.set_defaults(command="instrument")

    afl_parser = subparsers.add_parser(
        "afl", help="Instrument the harness (unless skipped) and run AFL++"
    )
    afl_parser.add_argument(
        "--skip-instrument",
        action="store_true",
        help="Reuse the existing instrumented binaries instead of rebuilding",
    )
    afl_parser.add_argument(
        "--single",
        action="store_true",
        help="Launch a single AFL++ instance instead of a multi-worker campaign",
    )
    afl_parser.add_argument(
        "--serious",
        action="store_true",
        help="Use one AFL++ worker per core (default behaviour)",
    )
    afl_parser.add_argument(
        "--workers",
        type=positive_int,
        help="Override the total number of AFL++ workers (master + secondary)",
    )
    afl_parser.add_argument(
        "--memory",
        type=memory_option,
        help="Override the AFL++ memory limit in megabytes or use 'none' to disable",
    )
    afl_parser.add_argument(
        "--timeout",
        type=positive_int,
        help="Override the AFL++ execution timeout in milliseconds",
    )
    afl_parser.add_argument(
        "--testcache",
        type=non_negative_int,
        help="Set AFL_TESTCACHE_SIZE in megabytes (defaults to 200 when unset)",
    )
    afl_parser.add_argument(
        "afl_args",
        nargs=argparse.REMAINDER,
        help="Additional afl-fuzz arguments (use '--' before the first option)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Summarise and replay crashes from AFL++ findings",
    )
    analyze_parser.add_argument(
        "--findings",
        help="Path to the findings directory (defaults to the latest run)",
    )
    analyze_parser.add_argument(
        "--list-runs",
        action="store_true",
        help="List all available findings runs and exit",
    )
    analyze_parser.add_argument(
        "--limit",
        type=non_negative_int,
        default=10,
        help="Number of crashes to show in the summary (0 to show all)",
    )
    analyze_parser.add_argument(
        "--show",
        metavar="CRASH",
        help="Show detailed information for a crash (index, id:<n>, or path)",
    )
    analyze_parser.add_argument(
        "--replay",
        metavar="CRASH",
        help="Execute the harness against a crash (index, id:<n>, or path)",
    )
    analyze_parser.add_argument(
        "--max-bytes",
        type=non_negative_int,
        default=64,
        help="Maximum number of bytes to include in crash hex dumps",
    )

    return parser


def run_afl(args: argparse.Namespace) -> None:
    ensure_project_paths()

    dotnet_path = require_command(
        "dotnet",
        "The dotnet CLI is required to execute the harness. Install the .NET SDK (9.0 or later).",
    )
    require_command(
        "afl-fuzz",
        "afl-fuzz was not found on PATH. Install AFL++ or enter the provided Nix shell.",
    )

    ensure_env("AFL_SKIP_CPUFREQ", "1", "Setting AFL_SKIP_CPUFREQ=1 to ignore CPU frequency checks.")
    if "AFL_SKIP_BIN_CHECK" not in os.environ:
        os.environ["AFL_SKIP_BIN_CHECK"] = "1"
        print("Setting AFL_SKIP_BIN_CHECK=1 so AFL++ accepts the managed harness.", file=sys.stderr)
    if "AFL_IMPORT_FIRST" not in os.environ:
        os.environ["AFL_IMPORT_FIRST"] = "1"
        print("Setting AFL_IMPORT_FIRST=1 so synchronized queues are imported first.", file=sys.stderr)
    if "AFL_IGNORE_SEED_PROBLEMS" not in os.environ:
        os.environ["AFL_IGNORE_SEED_PROBLEMS"] = "1"
        print("Setting AFL_IGNORE_SEED_PROBLEMS=1 to skip crashing seeds during warmup.", file=sys.stderr)
    if "AFL_INPUT_LEN_MIN" not in os.environ:
        os.environ["AFL_INPUT_LEN_MIN"] = "1"
        print("Setting AFL_INPUT_LEN_MIN=1 so SourceFunc inputs remain non-empty.", file=sys.stderr)

    if "AFL_TESTCACHE_SIZE" not in os.environ:
        cache_target = args.testcache if args.testcache is not None else DEFAULT_TESTCACHE
        if cache_target > 0:
            os.environ["AFL_TESTCACHE_SIZE"] = str(cache_target)
            print(
                f"Setting AFL_TESTCACHE_SIZE={cache_target} to cache test cases in memory.",
                file=sys.stderr,
            )

    maybe_warn_core_pattern()

    if not args.skip_instrument:
        instrument_harness(print_hint=False)
    elif not ASSEMBLY_PATH.is_file():
        die(
            "--skip-instrument was specified but the instrumented assembly was not found at "
            f"{ASSEMBLY_PATH}. Run the script with 'instrument' first."
        )

    corpus_dir = DEFAULT_CORPUS_DIR
    findings_dir = DEFAULT_FINDINGS_DIR_BASE / f"run-{dt.datetime.now():%Y%m%d-%H%M%S}"
    DEFAULT_FINDINGS_DIR_BASE.mkdir(parents=True, exist_ok=True)
    findings_dir.mkdir(parents=True, exist_ok=True)
    default_seed = corpus_dir / "seed-default"
    ensure_seed_corpus(corpus_dir, default_seed)

    harness_tail = ["--", dotnet_path, str(ASSEMBLY_PATH)]

    extra_args = list(args.afl_args or [])
    if extra_args and extra_args[0] == "--":
        extra_args = extra_args[1:]

    memory_limit = parse_memory_limit(args.memory)

    if extra_args:
        print("Launching AFL++ with custom arguments: " + " ".join(extra_args))
        afl_cmd = ["afl-fuzz"]
        if memory_limit is not None:
            if memory_limit == "none":
                print("Disabling AFL++ memory limit (-m none).")
                afl_cmd.extend(["-m", "none"])
            else:
                print(f"Setting AFL++ memory limit to {memory_limit} MB.")
                afl_cmd.extend(["-m", memory_limit])
        afl_cmd.extend(extra_args)
        afl_cmd.extend(harness_tail)
        os.execvpe("afl-fuzz", afl_cmd, os.environ)
        return

    cpu_count = os.cpu_count() or 1

    worker_count = None
    force_single = False
    serious_mode = True

    if args.single:
        force_single = True
        serious_mode = False
    if args.serious:
        serious_mode = True
        force_single = False

    if args.workers is not None:
        worker_count = args.workers

    if force_single and worker_count and worker_count > 1:
        die("--single cannot be combined with --workers values greater than 1.")

    if worker_count is None:
        if force_single:
            worker_count = 1
        elif serious_mode:
            worker_count = min(cpu_count, 32)
        else:
            worker_count = 1

    worker_count = max(1, worker_count)

    base_cmd = ["afl-fuzz", "-i", str(corpus_dir), "-o", str(findings_dir)]
    if args.timeout is not None:
        print(f"Setting AFL++ execution timeout to {args.timeout} ms.")
        base_cmd.extend(["-t", str(args.timeout)])
    if memory_limit is not None:
        if memory_limit == "none":
            print("Disabling AFL++ memory limit (-m none).")
            base_cmd.extend(["-m", "none"])
        else:
            print(f"Setting AFL++ memory limit to {memory_limit} MB.")
            base_cmd.extend(["-m", memory_limit])

    if worker_count == 1:
        print(f"Launching AFL++ with seed corpus at {corpus_dir}.")
        print(f"Findings will be written to {findings_dir}.")
        cmd = base_cmd + harness_tail
        os.execvpe("afl-fuzz", cmd, os.environ)
        return

    secondary_count = worker_count - 1
    host_tag = socket.gethostname().split(".")[0]
    host_tag = re.sub(r"[^A-Za-z0-9_-]", "", host_tag)
    if not host_tag:
        host_tag = "host"

    main_name = f"main-{host_tag}"
    logs_dir = findings_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"Launching AFL++ campaign with {worker_count} workers (1 master, {secondary_count} secondary)."
    )
    print(f"Seed corpus: {corpus_dir}")
    print(f"Findings directory: {findings_dir}")

    secondary_processes = []
    variant_count = len(SECONDARY_VARIANTS)
    for index in range(secondary_count):
        variant_name, variant_opts, variant_env = SECONDARY_VARIANTS[index % variant_count]
        fuzzer_name = f"{variant_name}-{index + 1}-{host_tag}"
        fuzzer_name = re.sub(r"[^A-Za-z0-9_-]", "-", fuzzer_name)
        cmd = base_cmd + ["-S", fuzzer_name]
        if variant_opts:
            cmd.extend(variant_opts)
        cmd.extend(harness_tail)

        log_file = logs_dir / f"{fuzzer_name}.log"
        schedule = " ".join(variant_opts) if variant_opts else "default schedule"
        env_suffix = ""
        if variant_env:
            env_pairs = ", ".join(f"{key}={value}" for key, value in sorted(variant_env.items()))
            env_suffix = f" (env: {env_pairs})"
        print(f"  Secondary {fuzzer_name}: {schedule}{env_suffix} -> {log_file}")

        proc_env = os.environ.copy()
        proc_env.update(variant_env)
        log_handle = log_file.open("w", encoding="utf-8", errors="replace")
        process = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=proc_env,
        )
        secondary_processes.append((process, log_handle))

    def cleanup() -> None:
        for proc, handle in secondary_processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            handle.close()

    print("Master {} running in the foreground. Press Ctrl+C to stop the campaign.".format(main_name))
    main_cmd = base_cmd + ["-M", main_name, "-p", "explore"] + harness_tail
    main_env = os.environ.copy()
    main_env["AFL_FINAL_SYNC"] = "1"
    try:
        result = subprocess.run(main_cmd, env=main_env, check=False)
        exit_code = result.returncode
    except KeyboardInterrupt:
        print("Master interrupted by user.", file=sys.stderr)
        exit_code = 130
    finally:
        cleanup()

    if exit_code:
        raise SystemExit(exit_code)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command = args.command
    if command == "instrument":
        instrument_harness()
        return 0
    if command == "afl":
        run_afl(args)
        return 0
    if command == "analyze":
        analyze_findings(args)
        return 0

    parser.error(f"Unexpected command: {command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
