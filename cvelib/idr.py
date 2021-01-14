from urllib.parse import urljoin

import requests


class IdrException(Exception):
    """Raise when encountering errors returned by the IDR API."""

    pass


class Idr:
    ENVS = {
        "prod": "https://cveawg.mitre.org/api/",
        "dev": "https://cveawg-dev.mitre.org/api/",
    }

    def __init__(self, username, org, api_key, env="prod", url=None, raise_exc=True):
        self.username = username
        self.org = org
        self.api_key = api_key
        self.url = url or self.ENVS.get(env)
        if not self.url:
            raise ValueError("Missing URL for IDR")
        self.raise_exc = raise_exc

    def http_request(self, method, path, **kwargs):
        url = urljoin(self.url, path)
        headers = {
            "CVE-API-KEY": self.api_key,
            "CVE-API-ORG": self.org,
            "CVE-API-USER": self.username,
        }
        response = requests.request(method=method, url=url, timeout=60, headers=headers, **kwargs)
        if self.raise_exc:
            try:
                response.raise_for_status()
            except requests.exceptions.RequestException as exc:
                if exc.response is not None:
                    try:
                        error = exc.response.json()
                    except ValueError:
                        error = exc.response.content
                    raise IdrException(f"{exc}; returned error: {error}") from None
                else:
                    raise IdrException(str(exc)) from None
        return response

    def get(self, path, **kwargs):
        return self.http_request("get", path, **kwargs)

    def post(self, path, **kwargs):
        return self.http_request("post", path, **kwargs)

    def reserve(self, count, random, year, owning_cna):
        params = {
            "cve_year": year,
            "amount": count,
            "short_name": owning_cna,
        }
        if count > 1:
            params["batch_type"] = "nonsequential" if random else "sequential"
        return self.post("cve-id", params=params)

    def show_cve(self, cve_id):
        return self.get(f"cve-id/{cve_id}")

    def list_cves(self, year=None, state=None, reserved_lt=None, reserved_gt=None):
        params = {}
        if year:
            params["cve_id_year"] = year
        if state:
            params["state"] = state.upper()
        if reserved_lt:
            params["time_reserved.lt"] = reserved_lt.isoformat()
        if reserved_gt:
            params["time_reserved.gt"] = reserved_gt.isoformat()
        return self.get(f"cve-id", params=params)

    def quota(self):
        return self.get(f"org/{self.org}/id_quota")

    def ping(self):
        return self.get("health-check")
