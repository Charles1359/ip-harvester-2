from __future__ import annotations

import asyncio
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns.exception
import dns.message
import dns.rcode
import dns.rrset

import dns_exporter


def make_config(
    *,
    servers: tuple[dns_exporter.DNSServer, ...] | None = None,
    subnets: tuple[dns_exporter.IPNetwork, ...] = (),
    domains: tuple[dns_exporter.DomainQuery, ...] | None = None,
) -> dns_exporter.AppConfig:
    if servers is None:
        servers = (
            dns_exporter.DNSServer("one", "udp", address="192.0.2.1", port=53),
        )
    if domains is None:
        domains = (dns_exporter.DomainQuery("example.com", ("A", "AAAA")),)
    return dns_exporter.AppConfig(servers, subnets, domains)


class ConfigTests(unittest.TestCase):
    def write_config(self, content: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".yaml", delete=False
        )
        with temporary:
            temporary.write(content)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_loads_all_protocols_and_normalizes_subnet(self) -> None:
        path = self.write_config(
            """
dns_servers:
  - {name: udp, protocol: udp, address: 8.8.8.8}
  - {name: tcp, protocol: tcp, address: 2001:4860:4860::8888, port: 53}
  - name: dot
    protocol: dot
    address: 1.1.1.1
    server_name: cloudflare-dns.com
  - name: doh
    protocol: doh
    url: https://cloudflare-dns.com/dns-query
edns_client_subnets: [8.213.221.9/24]
domains:
  - {name: example.com, types: [A, AAAA, A]}
"""
        )
        config = dns_exporter.load_config(path)
        self.assertEqual([server.protocol for server in config.dns_servers], ["udp", "tcp", "dot", "doh"])
        self.assertEqual(str(config.edns_client_subnets[0]), "8.213.221.0/24")
        self.assertEqual(config.domains[0].types, ("A", "AAAA"))

    def test_missing_domains_is_valid(self) -> None:
        path = self.write_config(
            "dns_servers:\n  - {protocol: udp, address: 8.8.8.8}\n"
        )
        self.assertEqual(dns_exporter.load_config(path).domains, ())

    def test_unknown_key_is_an_error(self) -> None:
        path = self.write_config(
            "dns_servers:\n  - {protocol: udp, address: 8.8.8.8}\ndomians: []\n"
        )
        with self.assertRaises(dns_exporter.ConfigError):
            dns_exporter.load_config(path)


class QueryTests(unittest.IsolatedAsyncioTestCase):
    async def test_query_message_contains_requested_ecs(self) -> None:
        spec = dns_exporter.QuerySpec(
            dns_exporter.DNSServer(
                "one", "udp", address="192.0.2.1", port=53
            ),
            "example.com",
            "A",
            ipaddress.ip_network("8.213.221.9/24", strict=False),
        )
        query = dns_exporter._make_query(spec)

        self.assertEqual(query.payload, dns_exporter.EDNS_UDP_PAYLOAD)
        self.assertEqual(len(query.options), 1)
        self.assertEqual(query.options[0].to_text(), "ECS 8.213.221.0/24 scope/0")

    async def test_doh_queries_reuse_the_same_client(self) -> None:
        server = dns_exporter.DNSServer(
            "doh",
            "doh",
            url="https://dns.example/dns-query",
        )
        config = make_config(
            servers=(server,),
            domains=(
                dns_exporter.DomainQuery("example.com", ("A",)),
                dns_exporter.DomainQuery("example.net", ("A",)),
            ),
        )
        clients: list[object] = []

        async def fake_https(
            query: dns.message.Message,
            _url: str,
            *,
            timeout: float,
            client: object,
        ) -> dns.message.Message:
            self.assertEqual(timeout, dns_exporter.QUERY_TIMEOUT_SECONDS)
            clients.append(client)
            return dns.message.make_response(query)

        with patch.object(dns_exporter.dns.asyncquery, "https", new=fake_https):
            await dns_exporter.collect_addresses(config)

        self.assertEqual(len(clients), 2)
        self.assertIs(clients[0], clients[1])

    async def test_runs_full_server_subnet_type_matrix_and_deduplicates(self) -> None:
        servers = (
            dns_exporter.DNSServer("one", "udp", address="192.0.2.1", port=53),
            dns_exporter.DNSServer("two", "udp", address="192.0.2.2", port=53),
        )
        subnets = (
            ipaddress.ip_network("8.213.221.0/24"),
            ipaddress.ip_network("47.253.107.0/24"),
        )
        config = make_config(servers=servers, subnets=subnets)
        seen: list[dns_exporter.QuerySpec] = []

        async def fake_send(
            _engine: dns_exporter.QueryEngine, spec: dns_exporter.QuerySpec
        ) -> dns.message.Message:
            seen.append(spec)
            query = dns.message.make_query(spec.domain, spec.record_type)
            response = dns.message.make_response(query)
            address = "203.0.113.7" if spec.record_type == "A" else "2001:db8::7"
            response.answer.append(
                dns.rrset.from_text(spec.domain, 60, "IN", spec.record_type, address)
            )
            return response

        with patch.object(dns_exporter.QueryEngine, "_send_once", new=fake_send):
            ipv4, ipv6 = await dns_exporter.collect_addresses(config)

        self.assertEqual(len(seen), 8)
        self.assertEqual(ipv4, {ipaddress.ip_address("203.0.113.7")})
        self.assertEqual(ipv6, {ipaddress.ip_address("2001:db8::7")})

    async def test_failed_query_retries_twice_then_returns_empty(self) -> None:
        attempts = 0

        async def always_timeout(
            _engine: dns_exporter.QueryEngine, _spec: dns_exporter.QuerySpec
        ) -> dns.message.Message:
            nonlocal attempts
            attempts += 1
            raise dns.exception.Timeout

        with (
            patch.object(dns_exporter.QueryEngine, "_send_once", new=always_timeout),
            patch.object(dns_exporter, "RETRY_BACKOFF_SECONDS", 0),
            self.assertLogs("dns-exporter", level="WARNING") as logs,
        ):
            ipv4, ipv6 = await dns_exporter.collect_addresses(
                make_config(domains=(dns_exporter.DomainQuery("example.com", ("A",)),))
            )

        self.assertEqual(attempts, 3)
        self.assertEqual((ipv4, ipv6), (set(), set()))
        self.assertEqual(len(logs.output), 3)

    async def test_dns_response_without_ip_is_successful_and_not_retried(self) -> None:
        attempts = 0

        async def nxdomain(
            _engine: dns_exporter.QueryEngine, spec: dns_exporter.QuerySpec
        ) -> dns.message.Message:
            nonlocal attempts
            attempts += 1
            response = dns.message.make_response(
                dns.message.make_query(spec.domain, spec.record_type)
            )
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response

        with patch.object(dns_exporter.QueryEngine, "_send_once", new=nxdomain):
            ipv4, ipv6 = await dns_exporter.collect_addresses(
                make_config(domains=(dns_exporter.DomainQuery("example.com", ("A",)),))
            )

        self.assertEqual(attempts, 1)
        self.assertEqual((ipv4, ipv6), (set(), set()))


class ExportTests(unittest.TestCase):
    def test_exports_sorted_pure_cidrs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            dns_exporter.export_addresses(
                output,
                {
                    ipaddress.ip_address("203.0.113.10"),
                    ipaddress.ip_address("192.0.2.1"),
                },
                {
                    ipaddress.ip_address("2001:db8::10"),
                    ipaddress.ip_address("2001:db8::1"),
                },
            )
            self.assertEqual(
                (output / "IPv4.txt").read_text(encoding="utf-8"),
                "192.0.2.1/32\n203.0.113.10/32\n",
            )
            self.assertEqual(
                (output / "IPv6.txt").read_text(encoding="utf-8"),
                "2001:db8::1/128\n2001:db8::10/128\n",
            )

    def test_empty_results_create_two_empty_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            dns_exporter.export_addresses(output, set(), set())
            self.assertEqual((output / "IPv4.txt").read_bytes(), b"")
            self.assertEqual((output / "IPv6.txt").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
