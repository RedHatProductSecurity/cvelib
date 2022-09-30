from datetime import datetime
from enum import Enum
from typing import Iterator, Optional
from urllib.parse import urljoin

import requests


class Constants(str, Enum):
    @classmethod
    def values(cls):
        return tuple(m.value for m in cls)


class CveApi:
    ENVS = {
        "prod": "https://cveawg.mitre.org/api/",
        "dev": "https://cveawg-dev.mitre.org/api/",
        "test": "https://cveawg-test.mitre.org/api/",
    }

    USER_ROLES = ("ADMIN",)

    class States(Constants):
        RESERVED = "reserved"
        PUBLISHED = "published"
        REJECTED = "rejected"

    class Errors(Constants):
        RECORD_EXISTS = "CVE_RECORD_EXISTS"
        RECORD_DOES_NOT_EXIST = "CVE_RECORD_DNE"

    def __init__(
        self, username: str, org: str, api_key: str, env: str = "prod", url: Optional[str] = None
    ) -> None:
        self.username = username
        self.org = org
        self.api_key = api_key
        if not url:
            url = self.ENVS.get(env)
            if not url:
                raise ValueError("Missing URL for CVE API")
        self.url = url

    def _http_request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = urljoin(self.url, path)
        headers = {
            "CVE-API-KEY": self.api_key,
            "CVE-API-ORG": self.org,
            "CVE-API-USER": self.username,
        }
        response = requests.request(method=method, url=url, timeout=60, headers=headers, **kwargs)
        response.raise_for_status()
        return response

    def _get(self, path: str, **kwargs) -> requests.Response:
        return self._http_request("get", path, **kwargs)

    def _get_paged(self, path: str, page_data_attr: str, params: dict, **kwargs) -> Iterator[dict]:
        """Get data from a paged endpoint.

        CVE Services 1.1.0 added pagination on responses longer than the default page size. For
        responses smaller than the page size, the pagination attributes like `nextPage` and
        `pageCount` are not present in the response.

        Responses include the returned data in an attribute named after the resource being
        queried, identified here as `page_data_attr`.

        This method yields returned data as it is received from each response.
        """
        while True:
            response = self._get(path, params=params, **kwargs)
            page = response.json()

            yield from page[page_data_attr]

            # On the last page, `nextPage` is set to `null`.
            next_page = page.get("nextPage")
            if next_page is not None:
                params["page"] = next_page
            else:
                break

    def _post(self, path: str, **kwargs) -> requests.Response:
        return self._http_request("post", path, **kwargs)

    def _put(self, path: str, **kwargs) -> requests.Response:
        return self._http_request("put", path, **kwargs)

    def publish(self, cve_id: str, cve_json: dict) -> dict:
        """Publish a CVE from a JSON object representing the CNA container data."""
        cve_json = {"cnaContainer": cve_json}
        response = self._post(f"cve/{cve_id}/cna", json=cve_json)
        response.raise_for_status()
        return response.json()

    def update_published(self, cve_id: str, cve_json: dict) -> dict:
        """Update a published CVE record from a JSON object representing the CNA container data."""
        cve_json = {"cnaContainer": cve_json}
        response = self._put(f"cve/{cve_id}/cna", json=cve_json)
        response.raise_for_status()
        return response.json()

    def reject(self, cve_id: str, cve_json: dict) -> dict:
        """Reject a CVE from a JSON object representing the CNA container data."""
        cve_json = {"cnaContainer": cve_json}
        response = self._post(f"cve/{cve_id}/reject", json=cve_json)
        response.raise_for_status()
        return response.json()

    def update_rejected(self, cve_id: str, cve_json: dict) -> dict:
        """Update a rejected CVE record from a JSON object representing the CNA container data."""
        cve_json = {"cnaContainer": cve_json}
        response = self._put(f"cve/{cve_id}/reject", json=cve_json)
        response.raise_for_status()
        return response.json()

    def move_to_rejected(self, cve_id):
        """Move a CVE ID to the REJECTED state without a CVE record.

        This is only possible if a CVE ID is in the RESERVED state.

        Moving a CVE ID to the REJECTED state without a CVE record is not possible if it has
        already been PUBLISHED.
        """
        params = {"state": self.States.REJECTED}
        return self._put(f"cve-id/{cve_id}", params=params).json()

    def move_to_reserved(self, cve_id):
        """Move a CVE ID to the RESERVED state without a CVE record.

        This is only possible if the CVE ID is in the REJECTED state without a CVE record.

        Moving a CVE ID to the RESERVED state is not possible if it has already been PUBLISHED.
        """
        params = {"state": self.States.RESERVED}
        return self._put(f"cve-id/{cve_id}", params=params).json()

    def reserve(self, count: int, random: bool, year: str) -> dict:
        """Reserve a set of CVE IDs.

        The return object contains the reserved CVE IDs and the remaining CVE ID quota.
        """
        params = {
            "cve_year": year,
            "amount": count,
            "short_name": self.org,
        }
        if count > 1:
            params["batch_type"] = "nonsequential" if random else "sequential"
        return self._post("cve-id", params=params).json()

    def show_cve_id(self, cve_id: str) -> dict:
        return self._get(f"cve-id/{cve_id}").json()

    def show_cve_record(self, cve_id: str) -> dict:
        return self._get(f"cve/{cve_id}").json()

    def list_cves(
        self,
        year: str = None,
        state: str = None,
        reserved_lt: datetime = None,
        reserved_gt: datetime = None,
    ) -> Iterator[dict]:
        params = {}
        if year:
            params["cve_id_year"] = year
        if state:
            params["state"] = state.upper()
        if reserved_lt:
            params["time_reserved.lt"] = reserved_lt.isoformat()
        if reserved_gt:
            params["time_reserved.gt"] = reserved_gt.isoformat()
        return self._get_paged("cve-id", page_data_attr="cve_ids", params=params)

    def quota(self) -> dict:
        return self._get(f"org/{self.org}/id_quota").json()

    def show_user(self, username: str) -> dict:
        return self._get(f"org/{self.org}/user/{username}").json()

    def reset_api_key(self, username: str) -> dict:
        return self._put(f"org/{self.org}/user/{username}/reset_secret").json()

    def create_user(self, **user_data: dict) -> dict:
        return self._post(f"org/{self.org}/user", json=user_data).json()

    def update_user(self, username, **user_data: dict) -> dict:
        return self._put(f"org/{self.org}/user/{username}", params=user_data).json()

    def list_users(self) -> Iterator[dict]:
        return self._get_paged(f"org/{self.org}/users", page_data_attr="users", params={})

    def show_org(self) -> dict:
        return self._get(f"org/{self.org}").json()

    def ping(self) -> Optional[requests.exceptions.RequestException]:
        """Check the CVE API status.

        Returns any RequestException that was raised if it did not succeed, else None.
        """
        try:
            self._get("health-check")
        except requests.exceptions.RequestException as exc:
            return exc
        return None
