===========================================================================
MISP Intel - Zeek Threat Intelligence Integration
===========================================================================

Zeek package for ingesting MISP (Malware Information Sharing Platform)
threat intelligence feeds and logging matches in a structured JSON format
suitable for SOC/SIEM consumption.

Features
--------

1. Reads and digests MISP-exported intel files into Zeek's Intel framework
2. Logs intel hits as JSON in ``misp.log`` with:
   - Defanged IP addresses for safe display in tickets
   - Human-readable byte counts
   - RFC3339 nanosecond timestamps
   - Connection context (protocol, ports, bytes up/down)
3. Filters noise: byte threshold, source-based exclusion, local-only originator
4. Cluster-aware: proper Broker communication for manager/worker topology
5. Operational alerts: email notifications on feed read failures

Supported Indicator Types
-------------------------

- Domains (``Intel::DOMAIN``)
- Hostnames
- IP addresses - source and destination (``Intel::ADDR``)
- JA3 fingerprints (``Intel::JA3``)
- File hashes: MD5, SHA1, SHA256, SHA512 (``Intel::FILE_HASH``)
- URLs (``Intel::URL``)

Installation
------------

Via ``zkg`` (recommended)::

    zkg install zeek/initconf/INTEL_MISP

Or load directly in ``local.zeek``::

    @load INTEL_MISP/scripts

Configuration
-------------

All configuration is done via ``redef`` in your ``local.zeek``.

**Feed directory** (required - set to your local MISP export path)::

    redef Intel::MISP::feed_dir = "/path/to/your/misp/feeds";

**Analyst1 feed directory** (if using Analyst1 feeds)::

    redef Intel::Analyst1::feed_dir = "/path/to/your/analyst1/feeds";

**Byte threshold** - suppress matches where both directions are below
this value (default: 4096 bytes)::

    redef Intel::MISP::byte_threshold = 8192;

**Source filtering** - pattern of intel source names to exclude from
``misp.log`` (default: ``/QRishing/``)::

    redef Intel::MISP::ignore_sources = /QRishing|SomeOtherSource/;

**Debug logging** (default: disabled)::

    redef Intel::MISP::DEBUG = T;

Output Format
-------------

The package generates ``misp.log`` in JSON format::

    {
      "ioc": "1drv.ms",
      "timestamp_rfc3339ns": "2024-11-11T21:44:29.832664000Z",
      "detection": "*TCP Traffic*:: `10[.]2.184.252:64447` -> `198[.]51.100.1:443` [X509::IN_CERT]\n*Total bytes*: 2.42KB up/9.73KB down",
      "ioc_type": "Intel::DOMAIN",
      "uid": "C4J4Th3PJpwUYZZ6gc",
      "url": ""
    }

Two log files are generated:

1. ``intel.log`` - standard Zeek intel log
2. ``misp.log`` - JSON formatted with enriched connection context

Log files are compatible with ``jq`` for command-line processing.

Feed File Format
----------------

MISP intel files must be in Zeek's tab-separated intel format::

    #fields	indicator	indicator_type	meta.source	meta.desc	meta.url
    example.com	Intel::DOMAIN	MISP-Feed	Malicious domain	https://misp.example.org/events/123

Testing
-------

Run the BTest suite::

    cd tests && btest -d

Or via ``zkg``::

    zkg test misp_intel

Architecture
------------

::

    MISP Feed Files
        |
        v
    Zeek Intel Framework (Intel::read_files)
        |
        | Intel::match -> Intel::log_intel
        v
    misp table[uid] (in-memory, 6hr TTL)
        |
        | connection_state_remove
        v
    Intel::MISP::to_json (filter + format)
        |
        | Intel::MISP::log (source filter)
        v
    misp.log (JSON)

The key design pattern is **deferred enrichment**: intel matches are
cached by connection UID, then enriched with full connection metadata
(byte counts, endpoints) when the connection is torn down. This ensures
the JSON output contains complete connection context that isn't available
at match time.

File Structure
--------------

- ``scripts/__load__.zeek`` - Package entry point
- ``scripts/debug.zeek`` - Debug logging utilities
- ``scripts/log_misp_json.zeek`` - Core JSON logging engine
- ``scripts/misp.zeek`` - MISP feed configuration and error handling
- ``scripts/analyst1.zeek`` - Analyst1 feed configuration
- ``scripts/test.zeek`` - Local development test overrides (not loaded in production)

License
-------

BSD 3-Clause. Copyright (c) 2010-2020, Aashish Sharma and Lawrence
Berkeley National Laboratory. See COPYING for details.
