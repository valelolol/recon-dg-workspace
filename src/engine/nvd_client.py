"""
NVD API Client with rate-limiting, exponential backoff, and caching.
"""

import httpx
from typing import Dict, Optional, List, Tuple
import time
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter for API requests."""
    
    def __init__(self, rate_limit: int = 5, burst_limit: int = 10, initial_delay: float = 0.0):
        """
        Initialize rate limiter.
        
        Args:
            rate_limit: Requests per minute
            burst_limit: Maximum burst allowance
            initial_delay: Initial delay before first request
        """
        self.rate_limit = rate_limit
        self.burst_limit = burst_limit
        self.tokens = burst_limit
        self.last_update = time.time()
        self.initial_delay = initial_delay
    
    def acquire(self) -> float:
        """
        Acquire a token, waiting if necessary.
        
        Returns:
            Seconds to wait before making the request
        """
        now = time.time()
        elapsed = now - self.last_update
        
        # Add tokens based on elapsed time
        tokens_per_second = self.rate_limit / 60.0
        self.tokens = min(self.burst_limit, self.tokens + elapsed * tokens_per_second)
        
        if self.tokens >= 1:
            self.tokens -= 1
            self.last_update = now
            return 0.0
        
        # Calculate wait time
        tokens_needed = 1 - self.tokens
        wait_time = tokens_needed / tokens_per_second
        self.last_update = now
        return wait_time
    
    def reset(self):
        """Reset the rate limiter."""
        self.tokens = self.burst_limit
        self.last_update = time.time()


class CachedResponse:
    """Cache entry with TTL and expiry check."""
    
    def __init__(self, data: Dict, timestamp: float, ttl: int):
        self.data = data
        self.timestamp = timestamp
        self.ttl = ttl
    
    @property
    def is_expired(self) -> bool:
        return (time.time() - self.timestamp) > self.ttl


class NVDClient:
    """NVD API client with rate-limiting, exponential backoff, and caching."""
    
    def __init__(
        self,
        base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0",
        rate_limit: int = 5,
        burst_limit: int = 10,
        cache_ttl: int = 3600,
        cache_max_size: int = 1000,
        max_retries: int = 3,
        initial_delay: float = 0.0,
        max_delay: float = 60.0,
    ):
        self.base_url = base_url
        self.rate_limiter = RateLimiter(
            rate_limit=rate_limit, 
            burst_limit=burst_limit, 
            initial_delay=initial_delay
        )
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._cache_size_limit = cache_max_size
        self.max_retries = max_retries
        self.max_delay = max_delay
        
        # Statistics
        self._stats = {
            "total_requests": 0,
            "requests_made": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "rate_limited": 0,
            "errors": 0,
            "osv_fallbacks": 0,
            "total_latency_ms": 0.0,
        }
    
    def _get_cache_key(self, ecosystem: str, package: str, version: str) -> str:
        """Generate cache key from ecosystem, package, and version."""
        return f"{ecosystem}:{package}:{version}"
    
    def _generate_cache_key(self, ecosystem: str, package: str, version: str) -> str:
        """Generate cache key from ecosystem, package, and version (alias for _get_cache_key)."""
        return self._get_cache_key(ecosystem, package, version)
    
    def _cache_get(self, key: str) -> Optional[Dict]:
        """Get cached response if not expired."""
        if key in self._cache:
            entry = self._cache[key]
            if not entry.is_expired:
                self._stats["cache_hits"] += 1
                return entry.data
        
        self._stats["cache_misses"] += 1
        return None
    
    def _cache_set(self, key: str, data: Dict):
        """Store response in cache."""
        if len(self._cache) >= self._cache_size_limit:
            # Evict oldest entry
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k].timestamp)
            del self._cache[oldest_key]
        
        self._cache[key] = CachedResponse(data, time.time(), self.cache_ttl)
    
    def _exponential_backoff(self, attempt: int) -> float:
        """Calculate backoff delay using exponential backoff."""
        base_delay = 1.0
        max_delay = self.max_delay
        return min(base_delay * (2 ** attempt), max_delay)
    
    def _handle_rate_limit(self, response: httpx.Response) -> bool:
        """Handle 429 Too Many Requests response."""
        if response.status_code == 429:
            self._stats["rate_limited"] += 1
            retry_after = int(response.headers.get("Retry-After", 60))
            logger.warning(f"Rate limited by NVD API. Waiting {retry_after}s...")
            time.sleep(retry_after)
            return True
        return False
    
    def _fetch_with_retry(self, url: str) -> Optional[Dict]:
        """
        Fetch URL with retry logic and exponential backoff.
        
        Args:
            url: URL to fetch
        
        Returns:
            Parsed JSON response or None on failure
        """
        last_error = None
        
        for attempt in range(self.max_retries):
            # Rate limiting
            wait_time = self.rate_limiter.acquire()
            if wait_time > 0:
                self._stats["rate_limited"] += 1
                logger.debug(f"Rate limited, waiting {wait_time:.2f}s...")
                time.sleep(wait_time)
            
            try:
                response = httpx.get(url, timeout=30.0)
                response.raise_for_status()
                
                if self._handle_rate_limit(response):
                    continue
                
                self._stats["requests_made"] += 1
                return response.json()
                
            except httpx.HTTPStatusError as e:
                last_error = e
                if self._handle_rate_limit(e.response):
                    continue
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                
            except Exception as e:
                last_error = e
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
        
        logger.error(f"All retries failed: {last_error}")
        return None
    
    def query_nvd_api(self, ecosystem: str, package: str, version: str) -> Optional[Dict]:
        """
        Query NVD API for vulnerabilities in a package.
        
        Args:
            ecosystem: Package ecosystem (pypi, npm, maven, etc.)
            package: Package name
            version: Package version
        
        Returns:
            Dictionary mapping CVE IDs to severity scores (0.0-1.0) or None
        """
        cache_key = self._get_cache_key(ecosystem, package, version)
        
        # Check cache first
        cached_result = self._cache_get(cache_key)
        if cached_result is not None:
            return cached_result
        
        # Build NVD API query URL
        query_params = {
            "criteria": {
                "cpeSearch": {
                    "criteria": f"cpe:2.3:a:{package}:{package}:{version}:*:A:*:*:*:*:*",
                    "matchCriteriaId": ""
                }
            },
            "resultsPerPage": 1000
        }
        
        url = f"{self.base_url}/cves?cpeSearch={query_params['criteria']}&resultsPerPage={query_params['resultsPerPage']}"
        
        result = self._fetch_with_retry(url)
        
        if not result:
            return None
        
        # Parse NVD response
        cve_data = {}
        
        for vulnerability in result.get("vulnerabilities", []):
            cve_id = vulnerability.get("cve", {}).get("id", "")
            metrics = vulnerability.get("metrics", {})
            
            # Extract CVSS score from v3.1 or v3.0 metrics
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            
            score = 0.0
            
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
            elif cvss_v30:
                cvss_data = cvss_v30[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
            
            # Normalize to 0.0-1.0 range (NVD scores are already 0.0-10.0)
            normalized_score = score / 10.0
            cve_data[cve_id] = normalized_score
        
        # Cache the result
        self._cache_set(cache_key, cve_data)
        return cve_data
    
    def query_osv_api(self, ecosystem: str, package: str, version: str) -> Optional[Dict]:
        """
        Query OSV API for vulnerabilities.
        
        Args:
            ecosystem: Package ecosystem (pypi, npm, maven, etc.)
            package: Package name
            version: Package version
        
        Returns:
            Dictionary mapping CVE IDs to severity scores (0.0-1.0) or None
        """
        cache_key = self._get_cache_key(ecosystem, package, version)
        
        # Check cache first
        cached_result = self._cache_get(cache_key)
        if cached_result is not None:
            return cached_result
        
        # Build OSV API query URL
        url = f"https://osv.dev/search?ecosystem={ecosystem}&package={package}&version={version}"
        
        result = self._fetch_with_retry(url)
        
        if not result:
            return None
        
        # OSV returns a list of affected packages
        # Parse and extract vulnerability information
        cve_data = {}
        
        affected = result.get("affected", [])
        
        for affected_pkg in affected:
            # Check ecosystem match
            if affected_pkg.get("ecosystem", {}).get("name") != ecosystem:
                continue
            
            versions = affected_pkg.get("versions", [])
            ids = affected_pkg.get("database_specific", {}).get("ids", [])
            
            for ver in versions:
                for vuln_id in ids:
                    # Calculate severity from OSV
                    severity = self._calculate_osv_severity(affected_pkg)
                    self._stats["osv_fallbacks"] += 1
                    
                    # Store CVE ID if available
                    if vuln_id.get("type") == "CVE":
                        cve_data[vuln_id["value"]] = severity
            
            # Extract GHSA and other IDs (avoid duplicates)
            seen_ids = set()
            for vuln_id in ids:
                id_key = f"OSV-{vuln_id['value']}"
                if id_key not in seen_ids:
                    seen_ids.add(id_key)
                    cve_data[id_key] = self._calculate_osv_severity(affected_pkg)
        
        # Cache the result
        self._cache_set(cache_key, cve_data)
        return cve_data
    
    def _calculate_osv_severity(self, affected_pkg: Dict) -> float:
        """
        Calculate severity score from OSV response.
        
        Args:
            affected_pkg: OSV affected package data
        
        Returns:
            Severity score (0.0-1.0)
        """
        vuln = affected_pkg.get("vulnerability", {})
        
        # Check for severity field
        severity = vuln.get("severity")
        if severity:
            severity_map = {
                "CRITICAL": 1.0,
                "HIGH": 0.75,
                "MODERATE": 0.5,
                "LOW": 0.25,
                "UNKNOWN": 0.0,
            }
            return severity_map.get(str(severity).upper(), 0.0)
        
        # Fall back to CVSS score
        cvss = vuln.get("cwe_ids") or vuln.get("aliases", [])
        for alias in cvss:
            if alias.startswith("CVE-"):
                # Try to extract score from NVD reference
                pass
        
        return 0.0
    
    def clear_cache(self):
        """Clear the client cache."""
        self._cache.clear()
    
    def clear_stats(self):
        """Clear client statistics."""
        self._stats = {
            "total_requests": 0,
            "requests_made": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "rate_limited": 0,
            "errors": 0,
            "osv_fallbacks": 0,
            "total_latency_ms": 0.0,
        }
    
    def get_stats(self) -> Dict:
        """Get client statistics."""
        return self._stats.copy()


def create_nvd_client(**kwargs) -> NVDClient:
    """
    Factory function to create an NVDClient instance.
    
    Args:
        **kwargs: Configuration options for NVDClient
    
    Returns:
        Configured NVDClient instance
    """
    return NVDClient(**kwargs)


def get_client() -> Optional[NVDClient]:
    """Get the default NVD client instance."""
    return _default_client


def set_client(client: NVDClient):
    """Set the default NVD client instance."""
    global _default_client
    _default_client = client


def clear_default_client():
    """Clear the default NVD client instance."""
    global _default_client
    _default_client = None


# Global default client
_default_client: Optional[NVDClient] = None
