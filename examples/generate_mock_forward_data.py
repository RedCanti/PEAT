#!/usr/bin/env python3
"""
Generate a mock PEAT run directory for exercising the ``peat forward`` SIEM
integrations (Security Onion and Malcolm) without touching real OT devices.

The output mirrors what :meth:`peat.Elastic._dump_docs_to_file` writes after a
real run::

    <out>/elastic_data/<RUN_ID>/<dated-index>.jsonl

Each line is a bulk-action dict ``{"_index", "_id", "_source"}`` -- exactly what
:func:`peat.integrations.forwarder.iter_run_docs` reads back. You can then
replay it into either SIEM, e.g.::

    peat forward examples/mock_forward_data/peat_results/mock_pull_2026-05-28_run \\
        --target security_onion --so-server https://so-manager:9200 ...

    peat forward examples/mock_forward_data/peat_results/mock_pull_2026-05-28_run \\
        --target malcolm --malcolm-server https://malcolm.example.com/

The data is shaped to light up the fields the shipped dashboards query:

  Security Onion (distribution/securityonion-files/peat-so-saved-objects.ndjson)
    - event.module:peat, event.dataset:peat.configs, event.dataset:peat.events
    - columns: event.dataset, observer.hostname, host.ip, message,
      firmware.version, event.action

  Malcolm (distribution/opensearch-files/peat-malcolm-dashboard.ndjson)
    - index patterns ot-device-hosts-*, ot-device-events-*
    - host.id, host.name, host.type, host.description.full,
      host.firmware.hash.md5 (cardinality), host.logic.hash.md5 (cardinality),
      event.message, event.dataset

Two devices intentionally change their firmware hash, and two change their
logic hash, across host snapshots -- so Malcolm's "multiple hashes means
firmware/logic changed" tables show a cardinality > 1.

This script uses only the Python standard library and is deterministic
(fixed RNG seed), so regenerating produces a stable dataset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# Constants mirroring real PEAT output
# --------------------------------------------------------------------------

ECS_VERSION = "8.10.0"
PEAT_VERSION = "2026.05"
# RUN_ID: PEAT uses int(f"{epoch:10}{randint(0,99):02}"); we hard-code one so
# the run directory / _id values are stable across regenerations.
RUN_ID = 176480851200
# All docs from a single run land in the index dated for the run day, even
# though @timestamp carries the original (historical) observation time.
RUN_DAY = "2026.05.28"

# The PEAT host that did the collecting (ECS "observer.*").
OBSERVER = {
    "geo": {"timezone": "America/Denver"},
    "hostname": "peat-collector-01",
    "ip": ["10.50.4.20"],
    "mac": ["02:42:0a:32:04:14"],
    "user": {"name": "ot-analyst"},
}

# Observation window: a week of activity ending on the run day.
WINDOW_START = datetime(2026, 5, 22, 0, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 5, 28, 18, 0, 0, tzinfo=timezone.utc)

RNG = random.Random(1337)

# --------------------------------------------------------------------------
# Devices (realistic OT fleet)
# --------------------------------------------------------------------------

# firmware_changed / logic_changed flip the respective hash on the *last*
# host snapshot so the Malcolm cardinality tables report a change.
DEVICES = [
    {
        "id": "192.0.2.11",
        "name": "sub1-line-relay-a",
        "type": "Relay",
        "ip": "192.0.2.11",
        "mac": "00:30:A7:11:22:01",
        "vendor_id": "SEL",
        "vendor_name": "Schweitzer Engineering Laboratories",
        "brand": "SEL",
        "model": "351S",
        "product": "SEL-351S",
        "fw_version": "R325-V0",
        "os": ("SEL-OS", "4.2"),
        "serial": "1151200034",
        "firmware_changed": False,
        "logic_changed": True,
        "protocol": "dnp3",
    },
    {
        "id": "192.0.2.21",
        "name": "plc-modicon-pumphouse",
        "type": "PLC",
        "ip": "192.0.2.21",
        "mac": "00:80:F4:21:33:02",
        "vendor_id": "Schneider",
        "vendor_name": "Schneider Electric",
        "brand": "Modicon",
        "model": "M340",
        "product": "Modicon M340",
        "fw_version": "2.70",
        "os": ("VxWorks", "6.9"),
        "serial": "SAS340M-77120",
        "firmware_changed": True,
        "logic_changed": False,
        "protocol": "modbus_tcp",
    },
    {
        "id": "192.0.2.31",
        "name": "sub2-busbar-protect",
        "type": "Relay",
        "ip": "192.0.2.31",
        "mac": "08:00:06:31:44:03",
        "vendor_id": "Siemens",
        "vendor_name": "Siemens AG",
        "brand": "SIPROTEC",
        "model": "7SJ85",
        "product": "SIPROTEC 5 7SJ85",
        "fw_version": "V08.80",
        "os": ("Siemens-EN100", "4.40"),
        "serial": "BF1942-7SJ85",
        "firmware_changed": False,
        "logic_changed": False,
        "protocol": "iec61850",
    },
    {
        "id": "192.0.2.41",
        "name": "plc-controllogix-mainfeed",
        "type": "PLC",
        "ip": "192.0.2.41",
        "mac": "00:00:BC:41:55:04",
        "vendor_id": "Rockwell",
        "vendor_name": "Rockwell Automation",
        "brand": "Allen-Bradley",
        "model": "1756-L71",
        "product": "ControlLogix 1756-L71",
        "fw_version": "32.011",
        "os": ("Logix", "32.11"),
        "serial": "C01756L71-99210",
        "firmware_changed": True,
        "logic_changed": True,
        "protocol": "ethernet_ip",
    },
    {
        "id": "192.0.2.51",
        "name": "sub1-feeder-relay-f650",
        "type": "Relay",
        "ip": "192.0.2.51",
        "mac": "00:A0:F4:51:66:05",
        "vendor_id": "GE",
        "vendor_name": "General Electric",
        "brand": "Multilin",
        "model": "F650",
        "product": "Multilin F650",
        "fw_version": "7.10",
        "os": ("GE-RTOS", "3.1"),
        "serial": "ML-F650-44021",
        "firmware_changed": False,
        "logic_changed": False,
        "protocol": "modbus_tcp",
    },
    {
        "id": "192.0.2.61",
        "name": "main-incomer-meter-ion9000",
        "type": "Power Meter",
        "ip": "192.0.2.61",
        "mac": "00:80:67:61:77:06",
        "vendor_id": "Schneider",
        "vendor_name": "Schneider Electric",
        "brand": "PowerLogic",
        "model": "ION9000",
        "product": "PowerLogic ION9000",
        "fw_version": "4.0.1",
        "os": ("ION-OS", "4.0"),
        "serial": "ION9000-30551",
        "firmware_changed": False,
        "logic_changed": False,
        "protocol": "modbus_tcp",
    },
    {
        "id": "192.0.2.71",
        "name": "rtu-wago-wellfield",
        "type": "RTU",
        "ip": "192.0.2.71",
        "mac": "00:30:DE:71:88:07",
        "vendor_id": "WAGO",
        "vendor_name": "WAGO Kontakttechnik",
        "brand": "PFC",
        "model": "750-8212",
        "product": "PFC200 750-8212",
        "fw_version": "03.10.08",
        "os": ("Linux", "4.9.146"),
        "serial": "WG750-8212-1188",
        "firmware_changed": False,
        "logic_changed": False,
        "protocol": "modbus_tcp",
    },
    {
        "id": "192.0.2.81",
        "name": "rtu-abb-560-intertie",
        "type": "RTU",
        "ip": "192.0.2.81",
        "mac": "00:1B:1B:81:99:08",
        "vendor_id": "ABB",
        "vendor_name": "ABB Ltd",
        "brand": "RTU560",
        "model": "560CMU05",
        "product": "RTU560 560CMU05",
        "fw_version": "12.2.1",
        "os": ("ABB-RTOS", "12.2"),
        "serial": "ABB560-CMU-2299",
        "firmware_changed": False,
        "logic_changed": False,
        "protocol": "iec104",
    },
]

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def ts(dt: datetime) -> str:
    """Format a datetime the way PEAT's Elastic.convert_tstamp does."""
    # e.g. 2026-05-24T13:45:30.123Z
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def rand_dt() -> datetime:
    span = (WINDOW_END - WINDOW_START).total_seconds()
    return WINDOW_START + timedelta(seconds=RNG.uniform(0, span))


def gen_id() -> str:
    """Mirror Elastic.gen_id(): peat~<run-id>~<microsecond>~<random>."""
    return f"peat~{RUN_ID}~{RNG.randint(0, 999999):06d}~{RNG.randint(0, 9999)}"


def base_source(timestamp: str, message: str, tags: list[str]) -> dict:
    """Standard PEAT fields present on every doc (see Elastic.gen_body)."""
    return {
        "ecs": {"version": ECS_VERSION},
        "agent": {"id": str(RUN_ID), "type": "PEAT", "version": PEAT_VERSION},
        "observer": OBSERVER,
        "@timestamp": timestamp,
        "message": message,
        "tags": tags,
    }


def base_host(dev: dict) -> dict:
    """host.{basic fields} as produced by gen_base_host_fields_content()."""
    return {
        "id": dev["id"],
        "name": dev["name"],
        "type": dev["type"],
        "ip": [dev["ip"]],
        "mac": [dev["mac"]],
        "serial_number": dev["serial"],
        "description": {
            "full": f"{dev['vendor_name']} {dev['product']}",
            "vendor": {"id": dev["vendor_id"], "name": dev["vendor_name"]},
            "brand": dev["brand"],
            "model": dev["model"],
            "product": dev["product"],
        },
    }


def action(index_base: str, source: dict) -> dict:
    return {"_index": f"{index_base}-{RUN_DAY}", "_id": gen_id(), "_source": source}


# --------------------------------------------------------------------------
# Per-index document builders
# --------------------------------------------------------------------------

EVENT_TEMPLATES = [
    ("login", "session", "Successful local HMI login by operator 'opr1'"),
    ("login-failed", "authentication", "Failed login attempt (bad password) from 10.50.9.7"),
    ("logout", "session", "Operator session closed"),
    ("config-change", "configuration", "Settings group 2 activated by engineering workstation"),
    ("setpoint-change", "configuration", "Overcurrent pickup changed 5.0A -> 4.6A"),
    ("firmware-update", "package", "Firmware image staged for next reboot"),
    ("breaker-trip", "intrusion_detection", "Phase A overcurrent element 51P picked up and tripped"),
    ("alarm", "host", "Watchdog timeout cleared; device recovered"),
    ("metering-read", "host", "Interval energy read recorded (kWh import register)"),
    ("comm-loss", "network", "DNP3 master heartbeat lost for 12s, then restored"),
]


def host_snapshots(dev: dict) -> list[dict]:
    """ot-device-hosts-timeseries: 3 snapshots; flip fw/logic hash on the last."""
    docs = []
    times = sorted(rand_dt() for _ in range(3))
    fw_seed = f"{dev['id']}-fw-{dev['fw_version']}"
    logic_seed = f"{dev['id']}-logic-base"
    for i, t in enumerate(times):
        last = i == len(times) - 1
        fw_basis = fw_seed + ("-v2" if (last and dev["firmware_changed"]) else "")
        logic_basis = logic_seed + ("-rev2" if (last and dev["logic_changed"]) else "")
        fw_ver = dev["fw_version"] + (".1" if (last and dev["firmware_changed"]) else "")

        host = base_host(dev)
        host["hostname"] = dev["name"]
        host["os"] = {"name": dev["os"][0], "version": dev["os"][1]}
        host["firmware"] = {
            "version": fw_ver,
            "id": f"FID={dev['model']}-{fw_ver}",
            "revision": fw_ver,
            "hash": {
                "md5": md5(fw_basis),
                "sha1": sha1(fw_basis),
                "sha256": sha256(fw_basis),
            },
        }
        host["logic"] = {
            "author": "controls-eng",
            "description": f"Protection/control logic for {dev['name']}",
            "hash": {"md5": md5(logic_basis), "sha256": sha256(logic_basis)},
        }
        src = base_source(
            ts(t),
            f"{dev['vendor_name']} {dev['type']}",
            [dev["vendor_name"], dev["product"], "devices"],
        )
        src["host"] = host
        docs.append(action("ot-device-hosts-timeseries", src))
    return docs


def event_docs(dev: dict) -> list[dict]:
    """ot-device-events: varied actions; event.dataset set to peat.events.

    NOTE: event.dataset is set to "peat.events" so the Security Onion saved
    search (query event.dataset:peat.events) matches. SO's enrich() only sets
    event.dataset when absent, and a device-log name would otherwise shadow it.
    """
    docs = []
    n = RNG.randint(6, 11)
    for _ in range(n):
        act, category, msg = RNG.choice(EVENT_TEMPLATES)
        t = rand_dt()
        src = base_source(ts(t), msg, ["events", dev["vendor_name"], dev["product"]])
        src["event"] = {
            "action": act,
            "category": [category],
            "kind": "event",
            "dataset": "peat.events",
            "message": msg,
            "created": ts(t),
            "ingested": ts(WINDOW_END),
        }
        src["host"] = base_host(dev)
        docs.append(action("ot-device-events", src))
    return docs


def config_docs(dev: dict) -> list[dict]:
    """peat-configs: device configuration snapshots.

    Carries a top-level ``firmware.version`` (the SO Device Configs search
    column) plus full host.* including firmware/logic hashes.
    """
    docs = []
    for i in range(2):
        t = rand_dt()
        host = base_host(dev)
        host["firmware"] = {
            "version": dev["fw_version"],
            "hash": {"md5": md5(f"{dev['id']}-fw-{dev['fw_version']}")},
        }
        host["logic"] = {"hash": {"md5": md5(f"{dev['id']}-logic-base")}}
        src = base_source(
            ts(t),
            f"Configuration snapshot {i + 1} for {dev['name']}",
            ["config", dev["vendor_name"], dev["product"]],
        )
        # top-level firmware.* (matches SO 'firmware.version' column)
        src["firmware"] = {
            "version": dev["fw_version"],
            "id": f"FID={dev['model']}-{dev['fw_version']}",
        }
        src["host"] = host
        src["config"] = {
            "comms_protocol": dev["protocol"],
            "settings_group_active": RNG.randint(1, 4),
            "ntp_server": "10.50.4.1",
            "syslog_server": "10.50.4.20",
        }
        docs.append(action("peat-configs", src))
    return docs


def file_docs(dev: dict) -> list[dict]:
    """ot-device-files: firmware image, config export, logic project."""
    specs = [
        (f"{dev['model']}-fw-{dev['fw_version']}.bin", "/firmware/", "file", "Firmware for the device", 1_540_096),
        (f"{dev['name']}.cfg", "/config/", "file", "Device configuration export", 48_213),
        (f"{dev['name']}-logic.proj", "/logic/", "file", "Control/protection logic project", 262_144),
    ]
    docs = []
    for name, directory, ftype, desc, size in specs:
        t = rand_dt()
        seed = f"{dev['id']}-{name}"
        src = base_source(ts(t), desc, ["file", dev["vendor_name"], dev["product"]])
        src["event"] = {"ingested": ts(WINDOW_END), "module": "mock_generator"}
        src["file"] = {
            "name": name,
            "directory": directory,
            "path": f"{directory}{name}",
            "type": ftype,
            "size": size,
            "hash": {"md5": md5(seed), "sha256": sha256(seed)},
            "mtime": ts(t),
        }
        src["host"] = base_host(dev)
        docs.append(action("ot-device-files", src))
    return docs


def register_docs(dev: dict) -> list[dict]:
    """ot-device-registers: protocol register map (PLC/RTU/meter only)."""
    if dev["type"] not in ("PLC", "RTU", "Power Meter"):
        return []
    regs = [
        ("40001", "float_32", "read", "phase_a_current", "Phase A current (A)", "analog"),
        ("40003", "float_32", "read", "phase_a_voltage", "Phase A voltage (V)", "analog"),
        ("40005", "float_32", "read", "active_power_kw", "Total active power (kW)", "analog"),
        ("00017", "bool", "read_write", "breaker_close_cmd", "Breaker close command", "binary"),
        ("00018", "bool", "read", "breaker_status", "Breaker closed status", "binary"),
        ("40021", "int_16", "read", "frequency_hz_x100", "System frequency x100 (Hz)", "analog"),
    ]
    docs = []
    for addr, dtype, rw, tag, desc, mtype in regs:
        t = rand_dt()
        src = base_source(ts(t), f"{desc} @ {addr}", ["register", dev["vendor_name"], dev["product"]])
        src["event"] = {"ingested": ts(WINDOW_END)}
        src["register"] = {
            "address": addr,
            "protocol": dev["protocol"],
            "data_type": dtype,
            "read_write": rw,
            "tag": tag,
            "description": desc,
            "measurement_type": mtype,
        }
        src["host"] = base_host(dev)
        docs.append(action("ot-device-registers", src))
    return docs


def tag_docs(dev: dict) -> list[dict]:
    """ot-device-tags: named program tags (PLC/RTU only)."""
    if dev["type"] not in ("PLC", "RTU"):
        return []
    tags = [
        ("Pump1_Run", "binary", "I0.0", "Wellfield pump 1 run feedback"),
        ("Pump1_Cmd", "binary", "Q0.0", "Wellfield pump 1 start command"),
        ("Tank_Level_Pct", "analog", "IW64", "Storage tank level (percent)"),
        ("Flow_Setpoint", "analog", "MW20", "Flow control setpoint"),
    ]
    docs = []
    for name, ttype, addr, desc in tags:
        t = rand_dt()
        src = base_source(ts(t), desc, ["tag", dev["vendor_name"], dev["product"]])
        src["event"] = {"ingested": ts(WINDOW_END)}
        src["tag"] = {"name": name, "address": addr, "type": ttype, "description": desc}
        src["host"] = base_host(dev)
        docs.append(action("ot-device-tags", src))
    return docs


def io_docs(dev: dict) -> list[dict]:
    """ot-device-io: physical I/O points (PLC/RTU only)."""
    if dev["type"] not in ("PLC", "RTU"):
        return []
    points = [
        ("DI_00", "input", "binary", "Pump 1 motor run contact"),
        ("DI_01", "input", "binary", "High-high tank level float"),
        ("DO_00", "output", "binary", "Pump 1 motor contactor"),
        ("AI_00", "input", "analog", "Tank level transmitter 4-20mA"),
        ("AO_00", "output", "analog", "VFD speed reference"),
    ]
    docs = []
    for pid, direction, iotype, desc in points:
        t = rand_dt()
        src = base_source(ts(t), desc, ["io", dev["vendor_name"], dev["product"]])
        src["event"] = {"ingested": ts(WINDOW_END)}
        src["io"] = {
            "id": pid,
            "name": f"var_{dev['name']}_{pid}",
            "direction": direction,
            "type": iotype,
            "description": desc,
            "slot": [str(RNG.randint(1, 3))],
        }
        src["host"] = base_host(dev)
        docs.append(action("ot-device-io", src))
    return docs


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def build_docs() -> list[dict]:
    docs: list[dict] = []
    for dev in DEVICES:
        docs += host_snapshots(dev)
        docs += event_docs(dev)
        docs += config_docs(dev)
        docs += file_docs(dev)
        docs += register_docs(dev)
        docs += tag_docs(dev)
        docs += io_docs(dev)
    return docs


def write_run(out_root: Path) -> Path:
    run_dir = out_root / "peat_results" / "mock_pull_2026-05-28_run"
    elastic_dir = run_dir / "elastic_data" / str(RUN_ID)
    elastic_dir.mkdir(parents=True, exist_ok=True)

    # Group bulk actions by their (dated) index -> one .jsonl per index,
    # exactly like Elastic._dump_docs_to_file.
    by_index: dict[str, list[str]] = {}
    for doc in build_docs():
        line = json.dumps(doc, separators=(",", ":"))
        by_index.setdefault(doc["_index"], []).append(line)

    total = 0
    for index, lines in sorted(by_index.items()):
        (elastic_dir / f"{index}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        total += len(lines)

    print(f"Wrote {total} docs across {len(by_index)} indices to:")
    print(f"  {elastic_dir.as_posix()}")
    for index, lines in sorted(by_index.items()):
        print(f"    {index}.jsonl  ({len(lines)} docs)")
    print()
    print("Forward it with, e.g.:")
    print(f"  peat forward {run_dir.as_posix()} --target security_onion --so-server https://so-manager:9200")
    print(f"  peat forward {run_dir.as_posix()} --target malcolm --malcolm-server https://malcolm.example.com/")
    return run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "mock_forward_data",
        help="Output root directory (default: examples/mock_forward_data)",
    )
    args = parser.parse_args()
    write_run(args.out)


if __name__ == "__main__":
    main()
