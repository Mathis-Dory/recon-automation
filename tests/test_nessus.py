import pytest
from recon import nessus


class FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = str(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self):
        self.requests = []
        self.responses = {}

    def get(self, url, **kwargs):
        self.requests.append(("GET", url, kwargs))
        return self.responses[("GET", url)]

    def post(self, url, **kwargs):
        self.requests.append(("POST", url, kwargs))
        return self.responses[("POST", url)]


def make_client():
    sess = FakeSession()
    client = nessus.NessusClient("https://nessus:8834", "AK", "SK", session=sess)
    return client, sess


def test_find_template_matches_name():
    client, sess = make_client()
    sess.responses[("GET", "https://nessus:8834/editor/scan/templates")] = FakeResp(
        {"templates": [
            {"name": "basic", "title": "Basic Network Scan", "uuid": "u-basic"},
            {"name": "advanced", "title": "Advanced Scan", "uuid": "u-adv"},
        ]}
    )
    assert client.find_template("Basic Network Scan") == "u-basic"


def test_find_template_missing_raises():
    client, sess = make_client()
    sess.responses[("GET", "https://nessus:8834/editor/scan/templates")] = FakeResp(
        {"templates": []}
    )
    with pytest.raises(ValueError):
        client.find_template("Nope")


def test_create_scan_returns_id():
    client, sess = make_client()
    sess.responses[("POST", "https://nessus:8834/scans")] = FakeResp(
        {"scan": {"id": 42}}
    )
    sid = client.create_scan("job", "10.0.0.0/24", "u-basic")
    assert sid == 42
    _, _, kwargs = sess.requests[-1]
    assert kwargs["json"]["settings"]["text_targets"] == "10.0.0.0/24"
    assert "X-ApiKeys" in kwargs["headers"]


def test_launch_returns_uuid():
    client, sess = make_client()
    sess.responses[("POST", "https://nessus:8834/scans/42/launch")] = FakeResp(
        {"scan_uuid": "run-uuid"}
    )
    assert client.launch(42) == "run-uuid"
