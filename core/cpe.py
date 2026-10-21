from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import re

@dataclass
class CPE:
    """
    Structured representation of Common Platform Enumeration (CPE).
    Supports both CPE 2.2 (URI) and CPE 2.3 (Formatted String) standards.
    """
    raw: str
    part: str = ""           # 'a' (application), 'o' (OS), 'h' (hardware)
    vendor: str = ""
    product: str = ""
    version: str = ""
    update: str = ""
    edition: str = ""
    language: str = ""
    sw_edition: str = ""
    target_sw: str = ""
    target_hw: str = ""
    other: str = ""

    @property
    def part_type(self) -> str:
        """Returns human-friendly part category."""
        mapping = {
            "a": "Application",
            "o": "Operating System",
            "h": "Hardware"
        }
        return mapping.get(self.part.lower(), "Unknown")

    @property
    def human_name(self) -> str:
        """Returns a clean display name (e.g. 'OpenBSD OpenSSH 4.7p1')."""
        components = []
        if self.vendor and self.vendor not in ("*", "-"):
            components.append(self.vendor.replace("_", " ").title())
        if self.product and self.product not in ("*", "-"):
            # Avoid repeating vendor if product starts with vendor
            prod_name = self.product.replace("_", " ")
            if not (self.vendor and prod_name.lower().startswith(self.vendor.lower())):
                components.append(prod_name.title())
            else:
                components.append(prod_name.title())
        if self.version and self.version not in ("*", "-"):
            components.append(self.version)
        if self.update and self.update not in ("*", "-"):
            components.append(self.update)
            
        return " ".join(components) if components else self.raw

    def to_cpe22(self) -> str:
        """Formats into CPE 2.2 URI syntax."""
        part = self.part or "a"
        vendor = self.vendor or "*"
        product = self.product or "*"
        version = self.version or ""
        update = self.update or ""
        edition = self.edition or ""
        language = self.language or ""

        uri = f"cpe:/{part}:{vendor}:{product}"
        if version:
            uri += f":{version}"
            if update:
                uri += f":{update}"
                if edition:
                    uri += f":{edition}"
                    if language:
                        uri += f":{language}"
        return uri

    def to_cpe23(self) -> str:
        """Formats into CPE 2.3 Formatted String syntax."""
        def clean(val: str) -> str:
            return val if val else "*"

        return (
            f"cpe:2.3:{clean(self.part)}:{clean(self.vendor)}:{clean(self.product)}:"
            f"{clean(self.version)}:{clean(self.update)}:{clean(self.edition)}:"
            f"{clean(self.language)}:{clean(self.sw_edition)}:{clean(self.target_sw)}:"
            f"{clean(self.target_hw)}:{clean(self.other)}"
        )

    def matches(self, query: str) -> bool:
        """
        Check if this CPE matches a given query, pattern, or vendor/product keyword.
        Accepts:
          - CPE URI / 2.3 string (prefix match or wildcard comparison)
          - vendor string (e.g., 'apache', 'openbsd')
          - vendor:product string (e.g., 'apache:http_server')
        """
        query = query.strip().lower()
        if not query:
            return False

        # Direct string containment or equality against raw
        if query == self.raw.lower() or query in self.raw.lower():
            return True

        # Check vendor or product match
        if query == self.vendor.lower() or query == self.product.lower():
            return True

        if ":" in query and not query.startswith("cpe:"):
            parts = query.split(":", 1)
            if parts[0] == self.vendor.lower() and (parts[1] == "*" or parts[1] == self.product.lower()):
                return True

        # If query is a CPE itself, do component-level comparison
        parsed_query = parse_cpe(query)
        if parsed_query:
            if parsed_query.part and parsed_query.part != "*" and parsed_query.part.lower() != self.part.lower():
                return False
            if parsed_query.vendor and parsed_query.vendor != "*" and parsed_query.vendor.lower() != self.vendor.lower():
                return False
            if parsed_query.product and parsed_query.product != "*" and parsed_query.product.lower() != self.product.lower():
                return False
            if parsed_query.version and parsed_query.version != "*" and parsed_query.version.lower() != self.version.lower():
                return False
            return True

        return False


def _unescape_cpe_component(component: str) -> str:
    """Unescapes special characters in CPE components."""
    return component.replace(r"\:", ":").replace(r"\\", "\\")


def _split_unescaped(s: str, delimiter: str = ":") -> List[str]:
    """Splits a string by delimiter, ignoring escaped delimiters (e.g. \\:)."""
    # Regex split on delimiter not preceded by a backslash
    tokens = re.split(r"(?<!\\)" + re.escape(delimiter), s)
    return [_unescape_cpe_component(t) for t in tokens]


def parse_cpe(cpe_str: Optional[str]) -> Optional[CPE]:
    """
    Parses a CPE string (CPE 2.2 URI or CPE 2.3 Formatted String) into a CPE object.
    Returns None if the input is not a recognized CPE format.
    """
    if not cpe_str or not isinstance(cpe_str, str):
        return None

    cpe_str = cpe_str.strip()
    if not cpe_str:
        return None

    # Handle CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    if cpe_str.startswith("cpe:2.3:"):
        remainder = cpe_str[len("cpe:2.3:"):]
        parts = _split_unescaped(remainder, ":")
        
        # Pad with empty strings if fewer than 11 components
        while len(parts) < 11:
            parts.append("*")

        return CPE(
            raw=cpe_str,
            part=parts[0],
            vendor=parts[1],
            product=parts[2],
            version=parts[3] if parts[3] != "*" else "",
            update=parts[4] if parts[4] != "*" else "",
            edition=parts[5] if parts[5] != "*" else "",
            language=parts[6] if parts[6] != "*" else "",
            sw_edition=parts[7] if parts[7] != "*" else "",
            target_sw=parts[8] if parts[8] != "*" else "",
            target_hw=parts[9] if parts[9] != "*" else "",
            other=parts[10] if parts[10] != "*" else ""
        )

    # Handle CPE 2.2: cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
    if cpe_str.startswith("cpe:/"):
        remainder = cpe_str[len("cpe:/"):]
        parts = _split_unescaped(remainder, ":")

        part = parts[0] if len(parts) > 0 else ""
        vendor = parts[1] if len(parts) > 1 else ""
        product = parts[2] if len(parts) > 2 else ""
        version = parts[3] if len(parts) > 3 else ""
        update = parts[4] if len(parts) > 4 else ""
        edition = parts[5] if len(parts) > 5 else ""
        language = parts[6] if len(parts) > 6 else ""

        return CPE(
            raw=cpe_str,
            part=part,
            vendor=vendor,
            product=product,
            version=version,
            update=update,
            edition=edition,
            language=language
        )

    return None

