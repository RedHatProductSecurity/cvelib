from urllib.parse import urljoin

import requests


class CveApiError(Exception):
    """Raise when encountering errors returned by the CVE API."""

    pass


class CveApi:
    ENVS = {
        "prod": "https://cveawg.mitre.org/api/",
        "dev": "https://cveawg-dev.mitre.org/api/",
    }
    USER_ROLES = ("ADMIN",)

    def __init__(self, username, org, api_key, env="prod", url=None):
        self.username = username
        self.org = org
        self.api_key = api_key
        self.url = url or self.ENVS.get(env)
        if not self.url:
            raise ValueError("Missing URL for CVE API")

    def http_request(self, method, path, **kwargs):
        url = urljoin(self.url, path)
        headers = {
            "CVE-API-KEY": self.api_key,
            "CVE-API-ORG": self.org,
            "CVE-API-USER": self.username,
        }
        try:
            response = requests.request(
                method=method, url=url, timeout=60, headers=headers, **kwargs
            )
        except requests.exceptions.ConnectionError as exc:
            raise CveApiError(str(exc)) from None

        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            if exc.response is not None:
                try:
                    error = exc.response.json()
                except ValueError:
                    error = exc.response.content
                raise CveApiError(f"{exc}; returned error: {error}") from None
            else:
                raise CveApiError(str(exc)) from None

        return response

    def get(self, path, **kwargs):
        return self.http_request("get", path, **kwargs)

    def get_paged(self, path, page_data_attr, params, **kwargs):
        """Get data from a paged endpoint.

        CVE Services 1.1.0 added pagination on responses longer than the default page size. For
        responses smaller than the page size, the pagination attributes like `nextPage` and
        `pageCount` are not present in the response.

        Responses include the returned data in an attribute named after the resource being
        queried, identified here as `page_data_attr`.

        This method yields returned data as it is received from each response.
        """
        while True:
            response = self.get(path, params=params, **kwargs)
            page = response.json()

            yield from page[page_data_attr]

            # On the last page, `nextPage` is set to `null`.
            next_page = page.get("nextPage")
            if next_page is not None:
                params["page"] = next_page
            else:
                break

    def post(self, path, **kwargs):
        return self.http_request("post", path, **kwargs)

    def put(self, path, **kwargs):
        return self.http_request("put", path, **kwargs)

    def reserve(self, count, random, year):
        """Reserve a set of CVE IDs.

        This method returns a tuple containing the reserved CVE IDs, and the remaining ID quota
        left over. The quota is only returned in an HTTP response header and is not part of the
        returned data. If the following issue moves that information to the body of the response,
        this method will be adjusted to return just the body of the response:

        https://github.com/CVEProject/cve-services/issues/427
        """
        params = {
            "cve_year": year,
            "amount": count,
            "short_name": self.org,
        }
        if count > 1:
            params["batch_type"] = "nonsequential" if random else "sequential"
        response = self.post("cve-id", params=params)
        return response.json(), response.headers["CVE-API-REMAINING-QUOTA"]

    def show_cve(self, cve_id):
        return self.get(f"cve-id/{cve_id}").json()

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
        return self.get_paged(f"cve-id", page_data_attr="cve_ids", params=params)

    def quota(self):
        return self.get(f"org/{self.org}/id_quota").json()

    def show_user(self, username):
        return self.get(f"org/{self.org}/user/{username}").json()

    def reset_api_token(self, username):
        return self.put(f"org/{self.org}/user/{username}/reset_secret").json()

    def create_user(self, **user_data):
        return self.post(f"org/{self.org}/user", json=user_data).json()

    def update_user(self, username, **user_data):
        return self.put(f"org/{self.org}/user/{username}", params=user_data).json()

    def list_users(self):
        return self.get_paged(f"org/{self.org}/users", page_data_attr="users", params={})

    def show_org(self):
        return self.get(f"org/{self.org}").json()

    def ping(self):
        """Check the CVE API status.

        Returns a tuple containing a boolean value of whether the request succeeded and any
        error message that was emitted if it did not succeed.
        """
        try:
            self.get("health-check")
        except CveApiError as exc:
            return False, str(exc)
        return True, None
