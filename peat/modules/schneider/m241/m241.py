"""
The Schneider Electric Modicon M241 logic controller.

The M241 belongs to Schneider's Modicon M2xx machine-controller family
(M221 / M241 / M251 / M262). Unlike the older Modicon M340 -- which is
programmed with Unity Pro / Control Expert and uses the Schneider-proprietary
:term:`UMAS` protocol over Modbus/TCP to transfer an ``.apx`` project blob --
the M241 is programmed with EcoStruxure Machine Expert (formerly SoMachine)
and runs a CODESYS 3.5 runtime. Consequently the UMAS-based project pull used
by the M340 module does NOT apply here. This module fingerprints and
interrogates the M241 over the standard services it exposes.

Services

- FTP (TCP 21)
- HTTP (TCP 80) / HTTPS (TCP 443), embedded web server
- SNMP (UDP 161), standard MIB-2
- Modbus/TCP (TCP 502), server enabled by default, no configuration required
- EtherNet/IP adapter (TCP 44818 / UDP 2222)

Reliable services for scanning: Modbus/TCP, SNMP, FTP

.. note::
   Retrieval of the CODESYS application/project (the device "logic") is not yet
   implemented. Doing so would require speaking the CODESYS gateway protocol or
   pulling the application archive via FTP / the SD card, and is tracked as
   future work. This module currently performs identification and pulls device
   identity + system metadata over Modbus/TCP and SNMP.

References

- CISA advisory ICSA-26-020-02 (Schneider CODESYS-runtime controllers)

Authors

- Reece
"""

from peat import (
    DeviceData,
    DeviceModule,
    IPMethod,
    Service,
)
from peat.protocols import FTP, SNMP

from . import m241_modbus

# Standard MIB-2 system-group OIDs pulled over SNMP.
_SNMP_SYSTEM_OIDS: dict[str, str] = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_contact": "1.3.6.1.2.1.1.4.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}


class M241(DeviceModule):
    """
    Schneider Modicon M241 logic controller (EcoStruxure Machine Expert / CODESYS).
    """

    device_type = "PLC"
    vendor_id = "Schneider"
    vendor_name = "Schneider Electric"
    brand = "Modicon"
    model = "M241"
    supported_models = ["M241"]
    module_aliases = ["m241", "tm241"]
    # Offline project parsing is not supported yet (CODESYS project archive).
    filename_patterns: list[str] = []
    default_options = {
        "m241": {
            # Which protocols to use when pulling from the device.
            # Available methods: modbus, snmp
            "pull_methods": ["modbus", "snmp"],
        },
    }

    # Strings used to fingerprint the M241 across protocols.
    _vendor_strings = ["schneider", "telemecanique"]
    _model_strings = ["m241", "tm241"]

    @classmethod
    def _verify_modbus(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M241 via Modbus/TCP by sending a "Read Device
        Identification" request (function code ``0x2B`` / ``0x0E``) and matching
        the returned vendor and product strings.
        """
        port = dev.options["modbus_tcp"]["port"]
        timeout = dev.options["modbus_tcp"]["timeout"]
        log = cls.log.bind(target=f"{dev.ip}:{port}")
        log.trace(f"Verifying {dev.ip}:{port} via Modbus/TCP (timeout: {timeout})")

        try:
            identity = m241_modbus.read_device_identification(dev.ip, port, timeout)
        except Exception as err:
            log.debug(f"Modbus/TCP verification error for {dev.ip}: {err}")
            return False

        if not identity:
            return False

        # Annotate the device while we have the data, even if verification fails.
        cls._annotate_identity(dev, identity)

        haystack = " ".join(identity.values()).lower()
        is_m241 = any(v in haystack for v in cls._vendor_strings) and any(
            m in haystack for m in cls._model_strings
        )

        log.debug(
            f"Modbus/TCP verification of device {dev.ip} {'succeeded' if is_m241 else 'failed'}"
        )
        return is_m241

    @classmethod
    def _verify_snmp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M241 by querying SNMP for OID
        ``1.3.6.1.2.1.1.1.0`` (``sysDescr``) and comparing it against
        specific strings.
        """
        port = dev.options["snmp"]["port"]
        timeout = dev.options["snmp"]["timeout"]

        cls.log.trace(f"Verifying {dev.ip}:{port} via SNMP (timeout: {timeout})")

        to_find = cls._vendor_strings + cls._model_strings

        for community in dev.options["snmp"]["communities"]:
            snmp = SNMP(dev.ip, port, timeout, community=community)
            if snmp.verify("1.3.6.1.2.1.1.1.0", to_find=to_find):
                return True

        return False

    @classmethod
    def _verify_ftp(cls, dev: DeviceData) -> bool:
        """
        Check if a device is a M241 via FTP by logging in and looking for
        M2xx fingerprint strings in the welcome banner or directory listing.
        """
        port = dev.options["ftp"]["port"]
        timeout = dev.options["ftp"]["timeout"]

        # If the user configured a specific FTP user/pass, just use that.
        if dev.options["ftp"].get("user") and dev.options["ftp"].get("pass"):
            creds = [[dev.options["ftp"]["user"], dev.options["ftp"]["pass"]]]
        elif dev.options["ftp"].get("creds"):
            creds = dev.options["ftp"]["creds"]
        else:
            # Best-effort: M2xx FTP often requires credentials, but try
            # anonymous so an open server can still be fingerprinted.
            creds = [["anonymous", "anonymous@"]]

        cls.log.trace(f"Verifying {dev.ip}:{port} via FTP (timeout: {timeout})")

        search_strings = cls._model_strings + cls._vendor_strings

        try:
            for user, password in creds:
                with FTP(dev.ip, port, timeout) as ftp:
                    if not ftp.login(user, password):
                        continue

                    dev.related.user.add(user)
                    welcome = ftp.getwelcome() or ""
                    files = ftp.nlst_files()

                haystack = f"{welcome} {' '.join(files)}".lower()

                if any(s in haystack for s in search_strings):
                    cls.log.debug(f"Verified {dev.ip}:{port} via FTP")
                    return True

                cls.log.debug(
                    f"Failed to find fingerprint strings via FTP on {dev.ip}:{port} "
                    f"(search strings: {search_strings})"
                )
        except Exception as ex:
            # An exception shouldn't occur just because a credential failed,
            # so stop early rather than trying more credentials.
            cls.log.debug(f"Failed to verify {dev.ip} via FTP: {ex}")

        return False

    @classmethod
    def _annotate_identity(cls, dev: DeviceData, identity: dict[str, str]) -> None:
        """
        Populate a DeviceData object from Modbus "Read Device Identification"
        objects.

        Args:
            dev: DeviceData instance to update.
            identity: Mapping of object name to value, as returned by
                :func:`~peat.modules.schneider.m241.m241_modbus.read_device_identification`.
        """
        revision = identity.get("revision", "")
        product_code = identity.get("product_code", "")

        if revision and not dev.firmware.version:
            dev.firmware.version = revision

        # The product code is the specific part number (e.g. "TM241CE24T").
        if product_code and not dev.hardware.id:
            dev.hardware.id = product_code

        # Keep the full set of objects for forensic value.
        dev.extra["modbus_device_identification"] = dict(identity)

    @classmethod
    def _pull(cls, dev: DeviceData) -> bool:
        methods = dev.options["m241"]["pull_methods"]
        pulled_any = False

        if "modbus" in methods and cls._pull_modbus(dev):
            pulled_any = True

        if "snmp" in methods and cls._pull_snmp(dev):
            pulled_any = True

        if not pulled_any:
            cls.log.warning(f"No data could be pulled from {dev.ip}")

        # NOTE: CODESYS application/project (logic) retrieval is not yet
        # implemented for the M241. See the module docstring for details.
        return pulled_any

    @classmethod
    def _pull_modbus(cls, dev: DeviceData) -> bool:
        """
        Pull device identity over Modbus/TCP "Read Device Identification".

        Args:
            dev: DeviceData instance to update with the pulled identity.

        Returns:
            If any identity data was successfully pulled.
        """
        port = dev.options["modbus_tcp"]["port"]
        timeout = dev.options["modbus_tcp"]["timeout"]
        cls.log.info(f"Pulling Modbus device identification from {dev.ip}:{port}")

        try:
            identity = m241_modbus.read_device_identification(dev.ip, port, timeout)
        except Exception as err:
            cls.log.warning(f"Modbus pull failed for {dev.ip}: {err}")
            return False

        if not identity:
            cls.log.warning(f"No Modbus device identification data from {dev.ip}")
            return False

        cls._annotate_identity(dev, identity)
        dev.write_file(identity, "modbus-device-identification.json")

        svc = Service(
            protocol="modbus_tcp",
            port=port,
            transport="tcp",
            enabled=True,
            extra=dict(identity),
        )
        dev.related.ports.add(port)
        dev.related.protocols.add("modbus_tcp")
        dev.store("service", svc, lookup="protocol")

        cls.update_dev(dev)
        return True

    @classmethod
    def _pull_snmp(cls, dev: DeviceData) -> bool:
        """
        Pull standard MIB-2 system-group information over SNMP.

        Args:
            dev: DeviceData instance to update with the pulled system info.

        Returns:
            If any SNMP system data was successfully pulled.
        """
        port = dev.options["snmp"]["port"]
        timeout = dev.options["snmp"]["timeout"]
        cls.log.info(f"Pulling SNMP system information from {dev.ip}:{port}")

        results: dict[str, str] = {}
        for community in dev.options["snmp"]["communities"]:
            snmp = SNMP(dev.ip, port, timeout, community=community)
            for name, oid in _SNMP_SYSTEM_OIDS.items():
                values = snmp.get(oid)
                if values:
                    results[name] = str(values[0]["value_string"])
            # Stop once a community string returns data.
            if results:
                break

        if not results:
            cls.log.warning(f"No SNMP system data from {dev.ip}")
            return False

        if results.get("sys_name") and not dev.name:
            dev.name = results["sys_name"]
        if results.get("sys_descr") and not dev.description.description:
            dev.description.description = results["sys_descr"]
        if results.get("sys_contact") and not dev.description.contact_info:
            dev.description.contact_info = results["sys_contact"]

        dev.extra["snmp_system"] = results
        dev.write_file(results, "snmp-system.json")

        svc = Service(protocol="snmp", port=port, transport="udp", enabled=True)
        dev.related.ports.add(port)
        dev.related.protocols.add("snmp")
        dev.store("service", svc, lookup="protocol")

        cls.update_dev(dev)
        return True


# Identification methods are registered after the class is defined, mirroring
# the pattern used by the other Schneider modules.
M241.ip_methods = [
    IPMethod(
        name="M241 Modbus/TCP",
        description=str(M241._verify_modbus.__doc__).strip(),
        type="unicast_ip",
        identify_function=M241._verify_modbus,
        reliability=8,
        protocol="modbus_tcp",
        transport="tcp",
        default_port=502,
    ),
    IPMethod(
        name="M241 SNMP sysDescr",
        description=str(M241._verify_snmp.__doc__).strip(),
        type="unicast_ip",
        identify_function=M241._verify_snmp,
        reliability=7,
        protocol="snmp",
        transport="udp",
        default_port=161,
    ),
    IPMethod(
        name="M241 FTP",
        description=str(M241._verify_ftp.__doc__).strip(),
        type="unicast_ip",
        identify_function=M241._verify_ftp,
        reliability=5,
        protocol="ftp",
        transport="tcp",
        default_port=21,
    ),
]

M241.serial_methods = []


__all__ = ["M241"]
