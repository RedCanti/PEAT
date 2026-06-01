"""Tests for the Schneider Modicon M241 module."""

import struct

import pytest

from peat import M241, config, datastore
from peat.modules.schneider.m241 import m241_modbus


def _build_device_id_response(
    objects: dict[int, str],
    function_code: int = 0x2B,
    mei_type: int = 0x0E,
    conformity: int = 0x82,
) -> bytes:
    """Build a synthetic Modbus/TCP Read Device Identification response frame."""
    object_stream = b""
    for object_id, value in objects.items():
        encoded = value.encode("utf-8")
        object_stream += bytes([object_id, len(encoded)]) + encoded

    # PDU: func, MEI type, read_device_id_code, conformity, more_follows,
    #      next_object_id, number_of_objects, <objects>
    pdu = (
        bytes([function_code, mei_type, 0x02, conformity, 0x00, 0x00, len(objects)])
        + object_stream
    )
    # MBAP length covers the unit id byte plus the PDU.
    header = struct.pack(">HHHB", 0x0001, 0x0000, len(pdu) + 1, 0x00)
    return header + pdu


# Object set a real Schneider M241 would return for the standard objects.
_M241_IDENTITY = {
    0x00: "Schneider Electric",
    0x01: "TM241CE24T",
    0x02: "V5.1.10.6",
    0x04: "M241",
}


# --- m241_modbus: request building -------------------------------------------


def test_build_read_device_id_request_default():
    request = m241_modbus.build_read_device_id_request()
    # transaction(0000) protocol(0000) length(0005) unit(00) 2b 0e <code> <obj>
    assert request == bytes.fromhex("000000000005002b0e0200")


def test_build_read_device_id_request_basic_code():
    request = m241_modbus.build_read_device_id_request(
        read_device_id_code=m241_modbus.READ_DEVICE_ID_BASIC
    )
    assert request == bytes.fromhex("000000000005002b0e0100")


# --- m241_modbus: response parsing -------------------------------------------


def test_parse_read_device_id_response_m241():
    response = _build_device_id_response(_M241_IDENTITY)
    parsed = m241_modbus.parse_read_device_id_response(response)

    assert parsed == {
        "vendor_name": "Schneider Electric",
        "product_code": "TM241CE24T",
        "revision": "V5.1.10.6",
        "product_name": "M241",
    }


def test_parse_read_device_id_response_unknown_object_id():
    response = _build_device_id_response({0x80: "custom-value"})
    parsed = m241_modbus.parse_read_device_id_response(response)
    assert parsed == {"object_0x80": "custom-value"}


def test_parse_read_device_id_exception_returns_empty():
    # Function code 0x2B with the exception flag (0x80) set => 0xAB.
    header = struct.pack(">HHHB", 0x0001, 0x0000, 0x03, 0x00)
    response = header + bytes([0xAB, 0x01])
    assert m241_modbus.parse_read_device_id_response(response) == {}


def test_parse_read_device_id_too_short_raises():
    with pytest.raises(ValueError, match="too short"):
        m241_modbus.parse_read_device_id_response(b"\x00\x01\x02")


def test_parse_read_device_id_wrong_function_code_raises():
    header = struct.pack(">HHHB", 0x0001, 0x0000, 0x09, 0x00)
    # Function code 0x03 (read holding registers), not device identification.
    response = header + bytes([0x03, 0x0E, 0x02, 0x82, 0x00, 0x00, 0x00])
    with pytest.raises(ValueError, match="unexpected function code"):
        m241_modbus.parse_read_device_id_response(response)


# --- M241 module attributes --------------------------------------------------


def test_m241_class_attributes():
    assert M241.model == "M241"
    assert M241.vendor_id == "Schneider"
    assert M241.brand == "Modicon"
    assert "m241" in M241.module_aliases


def test_m241_ip_methods_registered():
    names = [m.name for m in M241.ip_methods]
    assert names == ["M241 Modbus/TCP", "M241 SNMP sysDescr", "M241 FTP"]
    protocols = {m.protocol for m in M241.ip_methods}
    assert protocols == {"modbus_tcp", "snmp", "ftp"}


# --- M241 verification (network mocked) --------------------------------------


def test_verify_modbus_identifies_m241(mocker):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(
        m241_modbus, "read_device_identification", return_value=_M241_IDENTITY_NAMED
    )

    dev = datastore.get("192.0.2.42")
    assert M241._verify_modbus(dev) is True
    # Identity should be annotated onto the device even during verification.
    assert dev.firmware.version == "V5.1.10.6"
    assert dev.hardware.id == "TM241CE24T"
    assert dev.extra["modbus_device_identification"]["product_name"] == "M241"


def test_verify_modbus_rejects_non_m241(mocker):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(
        m241_modbus,
        "read_device_identification",
        return_value={
            "vendor_name": "Schneider Electric",
            "product_code": "BMX P34 2020",
            "product_name": "M340",
        },
    )

    dev = datastore.get("192.0.2.43")
    assert M241._verify_modbus(dev) is False


def test_verify_modbus_empty_identity(mocker):
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(m241_modbus, "read_device_identification", return_value={})

    dev = datastore.get("192.0.2.44")
    assert M241._verify_modbus(dev) is False


# --- M241 pull (network mocked) ----------------------------------------------


def test_pull_modbus_populates_device(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {"DEVICE_DIR": tmp_path / "devices", "TEMP_DIR": tmp_path / "temp_results"},
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(
        m241_modbus, "read_device_identification", return_value=_M241_IDENTITY_NAMED
    )

    dev = datastore.get("192.0.2.45")
    assert M241._pull_modbus(dev) is True

    assert dev.firmware.version == "V5.1.10.6"
    assert 502 in dev.related.ports
    assert "modbus_tcp" in dev.related.protocols
    assert any(svc.protocol == "modbus_tcp" for svc in dev.service)


# Named-key version of the identity (as returned by the real parser).
_M241_IDENTITY_NAMED = {
    "vendor_name": "Schneider Electric",
    "product_code": "TM241CE24T",
    "revision": "V5.1.10.6",
    "product_name": "M241",
}
