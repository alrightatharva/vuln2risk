import os
import json
import requests
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
from core.cpe import parse_cpe

class EOLEngine:
    """
    End-of-Life (EOL) engine that checks software lifecycle against
    endoflife.date API with local caching and offline heuristic fallback.
    """
    CACHE_DIR = os.path.join("cache", "eol")
    API_BASE = "https://endoflife.date/api"
    
    # Mapping of CPE product/vendor identifiers to endoflife.date slugs
    PRODUCT_MAPPING = {
        "http_server": "apache",
        "apache": "apache",
        "apache_http_server": "apache",
        "openssh": "openssh",
        "linux_kernel": "linux",
        "linux": "linux",
        "php": "php",
        "mysql": "mysql",
        "mariadb": "mariadb",
        "postgresql": "postgresql",
        "nginx": "nginx",
        "tomcat": "tomcat",
        "node.js": "nodejs",
        "nodejs": "nodejs",
        "python": "python",
        "redis": "redis",
        "samba": "samba",
    }

    # Static offline lifecycle database for common legacy services
    OFFLINE_LIFECYCLE_DB = {
        "apache": {
            "2.2": {"eol": "2018-01-01"},
            "2.0": {"eol": "2013-07-10"},
            "1.3": {"eol": "2010-02-03"},
        },
        "openssh": {
            "4.7": {"eol": "2010-09-01"},
            "5.": {"eol": "2015-01-01"},
            "6.": {"eol": "2017-01-01"},
            "7.": {"eol": "2020-01-01"},
        },
        "php": {
            "5.2": {"eol": "2011-01-06"},
            "5.3": {"eol": "2014-08-14"},
            "5.4": {"eol": "2015-09-03"},
            "5.6": {"eol": "2018-12-31"},
            "7.0": {"eol": "2019-01-10"},
            "7.4": {"eol": "2022-11-28"},
        },
        "mysql": {
            "5.0": {"eol": "2011-12-31"},
            "5.1": {"eol": "2013-12-31"},
            "5.5": {"eol": "2018-12-03"},
            "5.6": {"eol": "2021-02-05"},
            "5.7": {"eol": "2023-10-25"},
        },
        "linux": {
            "2.6": {"eol": "2016-02-10"},
            "3.2": {"eol": "2018-05-31"},
            "4.4": {"eol": "2022-02-06"},
        },
        "vsftpd": {
            "2.3": {"eol": "2012-01-01"},
            "2.": {"eol": "2015-01-01"},
        }
    }

    _MEMORY_CACHE = {}

    @classmethod
    def _fetch_product_cycles(cls, product_slug: str) -> Optional[list]:
        if product_slug in cls._MEMORY_CACHE:
            return cls._MEMORY_CACHE[product_slug]

        os.makedirs(cls.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(cls.CACHE_DIR, f"{product_slug}.json")

        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cls._MEMORY_CACHE[product_slug] = data
                    return data
            except Exception:
                pass

        try:
            url = f"{cls.API_BASE}/{product_slug}.json"
            res = requests.get(url, timeout=3)
            if res.status_code == 200:
                data = res.json()
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                cls._MEMORY_CACHE[product_slug] = data
                return data
            else:
                # Cache non-existent slugs as empty list
                cls._MEMORY_CACHE[product_slug] = []
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump([], f)
        except requests.RequestException:
            cls._MEMORY_CACHE[product_slug] = []

        return cls._MEMORY_CACHE.get(product_slug)

    @classmethod
    def check_eol(
        cls,
        cpe_str: Optional[str] = None,
        service_name: Optional[str] = None,
        service_version: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Determines whether a component is End-of-Life (EOL).
        Returns: (is_eol, cycle_identifier, eol_date_string)
        """
        product = None
        version = None

        if cpe_str:
            parsed = parse_cpe(cpe_str)
            if parsed:
                product = parsed.product.lower()
                version = parsed.version

        if not product and service_name:
            product = service_name.lower()
        if not version and service_version:
            version = service_version

        if not product or not version:
            return (False, None, None)

        slug = cls.PRODUCT_MAPPING.get(product, product)

        # 1. Check live / cached endoflife.date API
        cycles = cls._fetch_product_cycles(slug)
        if cycles and isinstance(cycles, list):
            today = datetime.now().strftime("%Y-%m-%d")
            for cycle_data in cycles:
                cycle_str = str(cycle_data.get("cycle", ""))
                if version.startswith(cycle_str):
                    eol_val = cycle_data.get("eol")
                    if eol_val is True:
                        return (True, cycle_str, "Discontinued")
                    elif isinstance(eol_val, str) and eol_val <= today:
                        return (True, cycle_str, eol_val)
                    elif eol_val is False:
                        return (False, cycle_str, "Supported")

        # 2. Check offline static database fallback
        if slug in cls.OFFLINE_LIFECYCLE_DB:
            for cycle_str, meta in cls.OFFLINE_LIFECYCLE_DB[slug].items():
                if version.startswith(cycle_str):
                    return (True, cycle_str, meta.get("eol", "Discontinued"))

        return (False, None, None)
