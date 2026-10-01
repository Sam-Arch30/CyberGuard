import asyncio
from typing import List, Optional, Tuple
import dns.resolver
import dns.exception
import idna

from backend.schemas.domain_intelligence import DNSRecords


class DNSService:
    """Service to resolve DNS records (A, AAAA, MX, NS, TXT) safely using dnspython."""

    def __init__(self, timeout_seconds: float = 2.5, nameservers: Optional[List[str]] = None):
        self.timeout = timeout_seconds
        self.nameservers = nameservers or ["8.8.8.8", "1.1.1.1"]

    def _get_resolver(self) -> dns.resolver.Resolver:
        """Constructs a configured dns.resolver.Resolver instance with strict timeouts."""
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(self.nameservers)
        except Exception:
            resolver = dns.resolver.Resolver()

        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    @staticmethod
    def normalize_and_punycode(domain: str) -> Tuple[str, Optional[str]]:
        """
        Normalizes a domain and converts IDN (internationalized domain names) to Punycode ASCII.
        Returns (lookup_domain, punycode_representation_if_different).
        """
        clean = domain.strip().lower().rstrip(".")
        try:
            ascii_domain = idna.encode(clean).decode("ascii")
            punycode = ascii_domain if ascii_domain != clean else None
            return ascii_domain, punycode
        except Exception:
            return clean, None

    def _query_record_sync(self, resolver: dns.resolver.Resolver, lookup_domain: str, rtype: str) -> Tuple[str, List[str], Optional[str]]:
        """Synchronously query a single record type. Returns (rtype, records_list, error_type)."""
        try:
            answers = resolver.resolve(lookup_domain, rtype)
            records: List[str] = []

            if rtype == "MX":
                # Sort MX records by preference priority ascending
                mx_items = []
                for r in answers:
                    pref = getattr(r, "preference", 10)
                    exchange = r.exchange.to_text().rstrip(".")
                    mx_items.append((pref, exchange))
                mx_items.sort(key=lambda x: x[0])
                records = [f"{pref} {exchange}" for pref, exchange in mx_items]

            elif rtype == "TXT":
                for r in answers:
                    # Join byte strings in multi-chunk TXT records
                    if hasattr(r, "strings") and r.strings:
                        txt_val = b"".join(r.strings).decode("utf-8", errors="replace")
                    else:
                        txt_val = r.to_text().strip('"')
                    records.append(txt_val)

            else:
                for r in answers:
                    records.append(r.to_text().rstrip("."))

            return rtype, records, None

        except dns.resolver.NXDOMAIN:
            return rtype, [], "NXDOMAIN"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return rtype, [], "NO_ANSWER"
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return rtype, [], "TIMEOUT"
        except Exception:
            return rtype, [], "ERROR"

    async def resolve_records(self, domain: str) -> Tuple[DNSRecords, bool, str, Optional[str]]:
        """
        Asynchronously queries A, AAAA, MX, NS, and TXT records for a domain.
        Returns: (DNSRecords, is_resolvable, status_message, punycode).
        """
        lookup_domain, punycode = self.normalize_and_punycode(domain)
        resolver = self._get_resolver()

        rtypes = ["A", "AAAA", "MX", "NS", "TXT"]
        tasks = [
            asyncio.to_thread(self._query_record_sync, resolver, lookup_domain, rtype)
            for rtype in rtypes
        ]

        results = await asyncio.gather(*tasks)

        rec_dict: dict = {
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "txt": []
        }
        nxdomain_count = 0
        timeout_count = 0

        for rtype, records, err in results:
            field_name = rtype.lower()
            rec_dict[field_name] = records
            if err == "NXDOMAIN":
                nxdomain_count += 1
            elif err == "TIMEOUT":
                timeout_count += 1

        is_resolvable = any(len(records) > 0 for records in rec_dict.values())

        if is_resolvable:
            status_message = "Active / Resolvable"
        elif nxdomain_count > 0:
            status_message = "NXDOMAIN (Domain does not exist in DNS)"
        elif timeout_count == len(rtypes):
            status_message = "DNS Resolution Timeout"
        else:
            status_message = "No DNS records found"

        dns_records = DNSRecords(
            a=rec_dict["a"],
            aaaa=rec_dict["aaaa"],
            mx=rec_dict["mx"],
            ns=rec_dict["ns"],
            txt=rec_dict["txt"]
        )

        return dns_records, is_resolvable, status_message, punycode

    async def resolve_all(self, domain: str) -> DNSRecords:
        """Convenience method resolving all record types and returning DNSRecords directly."""
        dns_records, _, _, _ = await self.resolve_records(domain)
        return dns_records
