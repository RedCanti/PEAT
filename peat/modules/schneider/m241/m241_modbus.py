"""
Modbus/TCP "Read Device Identification" support for the Schneider M241.

The Modicon M241 exposes a Modbus/TCP server on port 502 that is enabled by
default and requires no configuration. That server implements the standard
Modbus *Read Device Identification* function (function code ``0x2B`` with
MEI type ``0x0E``), which returns vendor/product/revision objects that are
ideal for fingerprinting the device and pulling basic identity metadata.

This module implements just enough of that function to build a request and
parse the response, without depending on a full Modbus stack. It deliberately
does NOT use the Schneider-proprietary :term:`UMAS` packets that the M340
module relies on, since the M241 is a CODESYS-runtime controller and does not
speak UMAS.

Reference: *MODBUS Application Protocol Specification V1.1b3*, section 6.21
("43 / 14 (0x2B / 0x0E) Read Device Identification").

Authors

- Reece
"""

import socket
import struct

from peat import CommError, log

# Modbus function code for "Encapsulated Interface Transport"
_FUNCTION_READ_DEVICE_ID = 0x2B
# MEI (Modbus Encapsulated Interface) type for Read Device Identification
_MEI_TYPE_DEVICE_ID = 0x0E
# High bit set on a function code indicates an exception (error) response
_EXCEPTION_FLAG = 0x80

# "Read Device ID" access codes: which category of objects to request.
READ_DEVICE_ID_BASIC = 0x01
READ_DEVICE_ID_REGULAR = 0x02
READ_DEVICE_ID_EXTENDED = 0x03
READ_DEVICE_ID_SPECIFIC = 0x04

# Standard object IDs, per the MODBUS specification (section 6.21).
OBJECT_NAMES: dict[int, str] = {
    0x00: "vendor_name",
    0x01: "product_code",
    0x02: "revision",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "user_application_name",
}


def build_read_device_id_request(
    read_device_id_code: int = READ_DEVICE_ID_REGULAR,
    object_id: int = 0x00,
    unit_id: int = 0x00,
    transaction_id: int = 0x0000,
) -> bytes:
    """
    Build a Modbus/TCP "Read Device Identification" request frame.

    Args:
        read_device_id_code: Which category of objects to request, one of
            :data:`READ_DEVICE_ID_BASIC`, :data:`READ_DEVICE_ID_REGULAR`,
            :data:`READ_DEVICE_ID_EXTENDED`, or :data:`READ_DEVICE_ID_SPECIFIC`.
        object_id: First object ID to read (the starting point of the stream).
        unit_id: Modbus unit/slave identifier.
        transaction_id: Modbus transaction identifier, echoed in the response.

    Returns:
        The complete Modbus/TCP request frame as :class:`bytes`.
    """
    # Protocol Data Unit: function code, MEI type, access code, object id
    pdu = bytes([_FUNCTION_READ_DEVICE_ID, _MEI_TYPE_DEVICE_ID, read_device_id_code, object_id])

    # MBAP header: transaction id, protocol id (0), length, unit id.
    # The length field counts the unit id byte plus the PDU.
    length = len(pdu) + 1
    header = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)

    return header + pdu


def parse_read_device_id_response(data: bytes) -> dict[str, str]:
    """
    Parse a Modbus/TCP "Read Device Identification" response frame.

    Args:
        data: Raw bytes received from the device.

    Returns:
        Mapping of object name (see :data:`OBJECT_NAMES`, or ``object_0xNN``
        for unrecognized IDs) to its decoded string value. An empty
        :class:`dict` is returned if the device returned a Modbus exception.

    Raises:
        ValueError: If the frame is malformed (too short, wrong function code,
            or wrong MEI type).
    """
    # Minimum frame to read the function code: 7-byte MBAP header + 1 byte.
    if len(data) < 8:
        raise ValueError(f"response too short ({len(data)} bytes)")

    function_code = data[7]

    # Exception responses set the high bit of the function code. These are
    # shorter than a normal response, so handle them before the length check.
    if function_code & _EXCEPTION_FLAG:
        exception_code = data[8] if len(data) > 8 else 0
        log.bind(classname="m241_modbus").debug(
            f"Modbus exception response (code 0x{exception_code:02x})"
        )
        return {}

    if function_code != _FUNCTION_READ_DEVICE_ID:
        raise ValueError(f"unexpected function code 0x{function_code:02x}")

    # A valid device-identification response has at least the MEI header
    # (function code through number_of_objects), i.e. 7 PDU bytes after MBAP.
    if len(data) < 14:
        raise ValueError(f"device identification response too short ({len(data)} bytes)")

    mei_type = data[8]
    if mei_type != _MEI_TYPE_DEVICE_ID:
        raise ValueError(f"unexpected MEI type 0x{mei_type:02x}")

    # PDU layout after the MEI type byte:
    #   read_device_id_code(1) conformity_level(1) more_follows(1)
    #   next_object_id(1) number_of_objects(1) then the object stream
    number_of_objects = data[13]
    offset = 14
    objects: dict[str, str] = {}

    for _ in range(number_of_objects):
        # Each object is: object_id(1) length(1) value(length)
        if offset + 2 > len(data):
            break

        object_id = data[offset]
        object_len = data[offset + 1]
        value_start = offset + 2
        value_end = value_start + object_len

        if value_end > len(data):
            break

        value = data[value_start:value_end].decode("utf-8", errors="replace").strip()
        name = OBJECT_NAMES.get(object_id, f"object_{object_id:#04x}")
        objects[name] = value
        offset = value_end

    return objects


def read_device_identification(
    ip: str,
    port: int = 502,
    timeout: float = 1.0,
    read_device_id_code: int = READ_DEVICE_ID_REGULAR,
    unit_id: int = 0x00,
) -> dict[str, str]:
    """
    Query a device's identity via Modbus/TCP "Read Device Identification".

    Args:
        ip: IPv4 address of the device.
        port: Modbus/TCP port (default 502).
        timeout: Socket timeout, in seconds.
        read_device_id_code: Category of objects to request (see
            :func:`build_read_device_id_request`).
        unit_id: Modbus unit/slave identifier.

    Returns:
        Mapping of object name to decoded value (see
        :func:`parse_read_device_id_response`). An empty :class:`dict` is
        returned if no usable data was retrieved.

    Raises:
        CommError: If the device could not be reached.
    """
    request = build_read_device_id_request(
        read_device_id_code=read_device_id_code, unit_id=unit_id
    )
    target_log = log.bind(classname="m241_modbus", target=f"{ip}:{port}")
    target_log.trace(f"Sending Read Device Identification request to {ip}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            sock.sendall(request)
            response = sock.recv(4096)
        except OSError as err:
            raise CommError(f"({ip}:{port}) {err}") from err

    if not response:
        target_log.debug("No data returned from Read Device Identification request")
        return {}

    try:
        return parse_read_device_id_response(response)
    except ValueError as err:
        target_log.debug(f"Failed to parse Read Device Identification response: {err}")
        return {}


__all__ = [
    "OBJECT_NAMES",
    "READ_DEVICE_ID_BASIC",
    "READ_DEVICE_ID_EXTENDED",
    "READ_DEVICE_ID_REGULAR",
    "READ_DEVICE_ID_SPECIFIC",
    "build_read_device_id_request",
    "parse_read_device_id_response",
    "read_device_identification",
]
