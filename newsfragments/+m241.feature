Added a device module for the Schneider Electric Modicon M241 logic controller (M2xx family).

PEAT can now fingerprint and pull identity metadata from M241 controllers via the
Modbus/TCP "Read Device Identification" function (FC 0x2B / MEI 0x0E), MIB-2 system
information over SNMP, and FTP banner/listing data. Unlike the M340, the M241 runs a
CODESYS 3.5 runtime and is programmed with EcoStruxure Machine Expert, so it does not
use :term:`UMAS`; retrieval of the CODESYS application/project is not yet implemented.
