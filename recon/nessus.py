"""Minimal Nessus REST API client (API-key auth)."""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NessusClient:
    def __init__(self, url, access_key, secret_key, session=None):
        self.url = url.rstrip("/")
        self.session = session or requests.Session()
        self.headers = {
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
            "Content-Type": "application/json",
        }

    def _get(self, path):
        resp = self.session.get(f"{self.url}{path}", headers=self.headers, verify=False)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path, payload=None):
        resp = self.session.post(
            f"{self.url}{path}", headers=self.headers, json=payload or {}, verify=False
        )
        resp.raise_for_status()
        return resp.json()

    def find_template(self, name):
        data = self._get("/editor/scan/templates")
        wanted = name.strip().lower()
        for tpl in data.get("templates", []):
            if wanted in (tpl.get("name", "").lower(), tpl.get("title", "").lower()):
                return tpl["uuid"]
        raise ValueError(f"Nessus template not found: {name}")

    def create_scan(self, name, targets, template_uuid, folder_id=None):
        settings = {"name": name, "text_targets": targets, "enabled": True}
        if folder_id is not None:
            settings["folder_id"] = folder_id
        data = self._post("/scans", {"uuid": template_uuid, "settings": settings})
        return data["scan"]["id"]

    def launch(self, scan_id):
        data = self._post(f"/scans/{scan_id}/launch")
        return data.get("scan_uuid", "")

    def status(self, scan_id):
        data = self._get(f"/scans/{scan_id}")
        return data.get("info", {}).get("status", "unknown")
