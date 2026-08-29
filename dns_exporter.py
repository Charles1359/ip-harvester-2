#!/usr/bin/env python3
"""Query DNS records with optional ECS and export unique IP CIDRs."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
from pathlib import Path
import ssl
import sys
import tempfile
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

import dns.asyncquery
import dns.edns
import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import httpx
import yaml


QUERY_TIMEOUT_SECONDS = 5.0
MAX_RETRIES = 2
MAX_CONCURRENT_QUERIES = 20
EDNS_UDP_PAYLOAD = 1232
RETRY_BACKOFF_SECONDS = 0.25

LOGGER = logging.getLogger("dns-exporter")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(ValueError):
    """Raised when the YAML configuration is invalid."""


class OutputValidationError(RuntimeError):
    """Raised when an exported file does not match the expected content."""


@dataclass(frozen=True)
class DNSServer:
    name: str
    protocol: str
    address: str | None = None
    port: int | None = None
    url: str | None = None
    server_name: str | None = None
    verify: bool = True


@dataclass(frozen=True)
class DomainQuery:
    name: str
    types: tuple[str, ...]


@dataclass(frozen=True)
class AppConfig:
    dns_servers: tuple[DNSServer, ...]
    edns_client_subnets: tuple[IPNetwork, ...]
    domains: tuple[DomainQuery, ...]


@dataclass(frozen=True)
class QuerySpec:
    server: DNSServer
    domain: str
    record_type: str
    subnet: IPNetwork | None

    @property
    def label(self) -> str:
        subnet = str(self.subnet) if self.subnet is not None else "none"
        return (
            f"server={self.server.name} domain={self.domain} "
            f"type={self.record_type} ecs={subnet}"
        )


def _require_mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{location} must be a YAML mapping")
    return value


def _require_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigError(f"{location} must be a YAML list")
    return value


def _reject_unknown_keys(
    mapping: dict[str, Any], allowed: set[str], location: str
) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ConfigError(f"{location} contains unknown key(s): {', '.join(unknown)}")


def _parse_port(value: Any, default: int, location: str) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ConfigError(f"{location} must be an integer between 1 and 65535")
    return value


def _parse_server(value: Any, index: int) -> DNSServer:
    location = f"dns_servers[{index}]"
    item = _require_mapping(value, location)
    _reject_unknown_keys(
        item,
        {"name", "protocol", "address", "port", "url", "server_name", "verify"},
        location,
    )

    protocol_value = item.get("protocol")
    if not isinstance(protocol_value, str):
        raise ConfigError(f"{location}.protocol must be one of: udp, tcp, dot, doh")
    protocol = protocol_value.strip().lower()
    if protocol not in {"udp", "tcp", "dot", "doh"}:
        raise ConfigError(f"{location}.protocol must be one of: udp, tcp, dot, doh")

    name_value = item.get("name", f"{protocol}-{index + 1}")
    if not isinstance(name_value, str) or not name_value.strip():
        raise ConfigError(f"{location}.name must be a non-empty string")
    name = name_value.strip()

    verify = item.get("verify", True)
    if not isinstance(verify, bool):
        raise ConfigError(f"{location}.verify must be true or false")

    if protocol == "doh":
        if "address" in item or "port" in item or "server_name" in item:
            raise ConfigError(
                f"{location} uses DoH; put the endpoint and optional port in url"
            )
        url_value = item.get("url")
        if not isinstance(url_value, str) or not url_value.strip():
            raise ConfigError(f"{location}.url must be a non-empty HTTPS URL")
        url = url_value.strip()
        parsed = urlsplit(url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ConfigError(
                f"{location}.url must be an HTTPS URL without credentials or a fragment"
            )
        return DNSServer(name=name, protocol=protocol, url=url, verify=verify)

    if "url" in item:
        raise ConfigError(f"{location}.url is only valid for DoH servers")
    address_value = item.get("address")
    if not isinstance(address_value, str) or not address_value.strip():
        raise ConfigError(f"{location}.address must be an IPv4 or IPv6 address")
    address = address_value.strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError as exc:
        raise ConfigError(f"{location}.address must be an IPv4 or IPv6 address") from exc

    default_port = 853 if protocol == "dot" else 53
    port = _parse_port(item.get("port"), default_port, f"{location}.port")

    if protocol != "dot":
        if "server_name" in item or "verify" in item:
            raise ConfigError(
                f"{location}.server_name and verify are only valid for encrypted DNS"
            )
        return DNSServer(name=name, protocol=protocol, address=address, port=port)

    server_name_value = item.get("server_name", address)
    if not isinstance(server_name_value, str) or not server_name_value.strip():
        raise ConfigError(f"{location}.server_name must be a non-empty string")
    return DNSServer(
        name=name,
        protocol=protocol,
        address=address,
        port=port,
        server_name=server_name_value.strip(),
        verify=verify,
    )


def _parse_subnet(value: Any, index: int) -> IPNetwork:
    location = f"edns_client_subnets[{index}]"
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location} must be an IPv4 or IPv6 CIDR string")
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ConfigError(f"{location} must be an IPv4 or IPv6 CIDR string") from exc


def _parse_domain(value: Any, index: int) -> DomainQuery:
    location = f"domains[{index}]"
    item = _require_mapping(value, location)
    _reject_unknown_keys(item, {"name", "types"}, location)

    name_value = item.get("name")
    if not isinstance(name_value, str) or not name_value.strip():
        raise ConfigError(f"{location}.name must be a non-empty domain name")
    name_text = name_value.strip()
    try:
        parsed_name = dns.name.from_text(name_text, origin=dns.name.root)
    except (dns.exception.DNSException, UnicodeError, ValueError) as exc:
        raise ConfigError(f"{location}.name is not a valid domain name") from exc
    if parsed_name == dns.name.root:
        raise ConfigError(f"{location}.name must not be the DNS root")
    name = parsed_name.to_text(omit_final_dot=True)

    types_value = _require_list(item.get("types"), f"{location}.types")
    if not types_value:
        raise ConfigError(f"{location}.types must contain A and/or AAAA")
    record_types: list[str] = []
    for type_index, record_type_value in enumerate(types_value):
        if not isinstance(record_type_value, str):
            raise ConfigError(f"{location}.types[{type_index}] must be A or AAAA")
        record_type = record_type_value.strip().upper()
        if record_type not in {"A", "AAAA"}:
            raise ConfigError(f"{location}.types[{type_index}] must be A or AAAA")
        if record_type not in record_types:
            record_types.append(record_type)
    return DomainQuery(name=name, types=tuple(record_types))


def load_config(path: Path) -> AppConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"unable to read config file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc

    root = _require_mapping(raw, "configuration")
    _reject_unknown_keys(root, {"dns_servers", "edns_client_subnets", "domains"}, "configuration")

    server_values = _require_list(root.get("dns_servers"), "dns_servers")
    if not server_values:
        raise ConfigError("dns_servers must contain at least one server")
    servers = tuple(_parse_server(value, index) for index, value in enumerate(server_values))
    server_names = [server.name for server in servers]
    if len(server_names) != len(set(server_names)):
        raise ConfigError("dns_servers names must be unique")

    subnet_values = _require_list(
        root.get("edns_client_subnets", []), "edns_client_subnets"
    )
    subnets = tuple(_parse_subnet(value, index) for index, value in enumerate(subnet_values))
    if len(subnets) != len(set(subnets)):
        raise ConfigError("edns_client_subnets must not contain duplicates")

    domain_values = _require_list(root.get("domains", []), "domains")
    domains = tuple(_parse_domain(value, index) for index, value in enumerate(domain_values))
    return AppConfig(servers, subnets, domains)


def _make_query(spec: QuerySpec) -> dns.message.QueryMessage:
    options: list[dns.edns.Option] = []
    if spec.subnet is not None:
        options.append(
            dns.edns.ECSOption(
                address=str(spec.subnet.network_address),
                srclen=spec.subnet.prefixlen,
                scopelen=0,
            )
        )
    return dns.message.make_query(
        spec.domain,
        spec.record_type,
        use_edns=0,
        payload=EDNS_UDP_PAYLOAD,
        options=options,
    )


def _extract_addresses(
    response: dns.message.Message, record_type: str
) -> set[IPAddress]:
    expected_rdtype = dns.rdatatype.from_text(record_type)
    addresses: set[IPAddress] = set()
    for rrset in response.answer:
        if rrset.rdtype != expected_rdtype:
            continue
        for record in rrset:
            address = ipaddress.ip_address(record.address)
            if address.version == (4 if record_type == "A" else 6):
                addresses.add(address)
    return addresses


def _github_escape(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_query_warning(message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        print(
            f"::warning title=DNS query failed::{_github_escape(message)}",
            file=sys.stderr,
            flush=True,
        )
    else:
        LOGGER.warning(message)


EXPECTED_QUERY_EXCEPTIONS = (
    dns.exception.DNSException,
    httpx.HTTPError,
    OSError,
    ssl.SSLError,
    TimeoutError,
)


class QueryEngine:
    """Run queries while reusing one HTTP/2 client per DoH server."""

    def __init__(self, servers: Iterable[DNSServer]) -> None:
        self._servers = tuple(servers)
        self._doh_clients: dict[DNSServer, httpx.AsyncClient] = {}

    async def __aenter__(self) -> QueryEngine:
        for server in self._servers:
            if server.protocol == "doh":
                self._doh_clients[server] = httpx.AsyncClient(
                    http1=True,
                    http2=True,
                    verify=server.verify,
                    timeout=None,
                    limits=httpx.Limits(
                        max_connections=MAX_CONCURRENT_QUERIES,
                        max_keepalive_connections=MAX_CONCURRENT_QUERIES,
                    ),
                )
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        await asyncio.gather(
            *(client.aclose() for client in self._doh_clients.values())
        )

    async def _send_once(self, spec: QuerySpec) -> dns.message.Message:
        query = _make_query(spec)
        server = spec.server
        async with asyncio.timeout(QUERY_TIMEOUT_SECONDS):
            if server.protocol == "udp":
                response, _used_tcp = await dns.asyncquery.udp_with_fallback(
                    query,
                    server.address,
                    timeout=QUERY_TIMEOUT_SECONDS,
                    port=server.port,
                )
                return response
            if server.protocol == "tcp":
                return await dns.asyncquery.tcp(
                    query,
                    server.address,
                    timeout=QUERY_TIMEOUT_SECONDS,
                    port=server.port,
                )
            if server.protocol == "dot":
                return await dns.asyncquery.tls(
                    query,
                    server.address,
                    timeout=QUERY_TIMEOUT_SECONDS,
                    port=server.port,
                    server_hostname=server.server_name,
                    verify=server.verify,
                )
            if server.protocol == "doh":
                return await dns.asyncquery.https(
                    query,
                    server.url,
                    timeout=QUERY_TIMEOUT_SECONDS,
                    client=self._doh_clients[server],
                )
        raise RuntimeError(f"unsupported DNS protocol: {server.protocol}")

    async def query(self, spec: QuerySpec) -> set[IPAddress]:
        total_attempts = MAX_RETRIES + 1
        for attempt in range(1, total_attempts + 1):
            try:
                response = await self._send_once(spec)
                return _extract_addresses(response, spec.record_type)
            except EXPECTED_QUERY_EXCEPTIONS as exc:
                _emit_query_warning(
                    f"{spec.label} attempt={attempt}/{total_attempts}: "
                    f"{type(exc).__name__}: {exc}"
                )
                if attempt < total_attempts:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        return set()


def _iter_query_specs(config: AppConfig) -> Iterable[QuerySpec]:
    subnets: tuple[IPNetwork | None, ...]
    if config.edns_client_subnets:
        subnets = config.edns_client_subnets
    else:
        subnets = (None,)
    for domain in config.domains:
        for record_type in domain.types:
            for server in config.dns_servers:
                for subnet in subnets:
                    yield QuerySpec(server, domain.name, record_type, subnet)


async def collect_addresses(config: AppConfig) -> tuple[set[IPAddress], set[IPAddress]]:
    specs = tuple(_iter_query_specs(config))
    if not specs:
        return set(), set()

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
    async with QueryEngine(config.dns_servers) as engine:
        async def run_one(spec: QuerySpec) -> set[IPAddress]:
            async with semaphore:
                return await engine.query(spec)

        result_sets = await asyncio.gather(*(run_one(spec) for spec in specs))

    ipv4: set[IPAddress] = set()
    ipv6: set[IPAddress] = set()
    for result in result_sets:
        for address in result:
            (ipv4 if address.version == 4 else ipv6).add(address)
    return ipv4, ipv6


def _render_cidrs(addresses: Iterable[IPAddress], version: int) -> str:
    filtered = {address for address in addresses if address.version == version}
    suffix = 32 if version == 4 else 128
    lines = [f"{address}/{suffix}" for address in sorted(filtered, key=int)]
    return "" if not lines else "\n".join(lines) + "\n"


def _write_temp_file(directory: Path, filename: str, content: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        prefix=f".{filename}.",
        dir=directory,
        delete=False,
    ) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        return Path(handle.name)


def export_addresses(
    output_dir: Path,
    ipv4_addresses: Iterable[IPAddress],
    ipv6_addresses: Iterable[IPAddress],
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    expected = {
        "IPv4.txt": _render_cidrs(ipv4_addresses, 4),
        "IPv6.txt": _render_cidrs(ipv6_addresses, 6),
    }
    temporary_files: dict[str, Path] = {}
    try:
        for filename, content in expected.items():
            temporary_files[filename] = _write_temp_file(output_dir, filename, content)
        for filename, temporary_path in temporary_files.items():
            os.replace(temporary_path, output_dir / filename)
        for filename, content in expected.items():
            actual = (output_dir / filename).read_text(encoding="utf-8")
            if actual != content:
                raise OutputValidationError(f"export validation failed for {filename}")
    finally:
        for temporary_path in temporary_files.values():
            temporary_path.unlink(missing_ok=True)
    return output_dir / "IPv4.txt", output_dir / "IPv6.txt"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query configured DNS servers and export unique IP CIDRs."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="YAML config path (default: config.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("."),
        help="directory for IPv4.txt and IPv6.txt (default: current directory)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = _build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        ipv4, ipv6 = asyncio.run(collect_addresses(config))
        ipv4_path, ipv6_path = export_addresses(args.output_dir, ipv4, ipv6)
        LOGGER.info(
            "exported %d IPv4 and %d IPv6 address(es) to %s and %s",
            len(ipv4),
            len(ipv6),
            ipv4_path,
            ipv6_path,
        )
        return 0
    except ConfigError as exc:
        LOGGER.error("configuration error: %s", exc)
        return 1
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130
    except Exception:
        LOGGER.exception("program failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
