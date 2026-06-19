from recon import probes


def test_extract_title():
    assert probes.extract_title("<html><head><title> Hello </title></head>") == "Hello"
    assert probes.extract_title("<html>no title</html>") == ""


def test_probe_web_title_uses_getter():
    class Resp:
        text = "<title>Admin Panel</title>"
        status_code = 200

    calls = {}

    def fake_get(url, **kwargs):
        calls["url"] = url
        return Resp()

    title = probes.probe_web_title("10.0.0.1", 8080, getter=fake_get)
    assert title == "Admin Panel"
    assert calls["url"].startswith("http://10.0.0.1:8080")


def test_probe_web_title_https_for_443():
    class Resp:
        text = "<title>x</title>"
        status_code = 200

    seen = {}

    def fake_get(url, **kwargs):
        seen["url"] = url
        return Resp()

    probes.probe_web_title("10.0.0.1", 443, getter=fake_get)
    assert seen["url"].startswith("https://")


def test_probe_banner_reads_socket():
    class FakeSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def recv(self, n): return b"SSH-2.0-OpenSSH_8.9\r\n"
        def settimeout(self, t): pass

    def factory(addr, timeout=None):
        return FakeSock()

    out = probes.probe_banner("10.0.0.1", 22, sock_factory=factory)
    assert "OpenSSH_8.9" in out


def test_probe_ftp_anon_success():
    class FakeFTP:
        def __init__(self, *a, **k): pass
        def connect(self, host, port, timeout): pass
        def login(self): pass
        def nlst(self): return ["pub", "incoming"]
        def quit(self): pass

    out = probes.probe_ftp_anon("10.0.0.1", ftp_factory=FakeFTP)
    assert out == "FTP ANON OK (listing: yes)"


def test_probe_ftp_anon_failure():
    class FakeFTP:
        def __init__(self, *a, **k): pass
        def connect(self, host, port, timeout): pass
        def login(self): raise OSError("530 denied")

    assert probes.probe_ftp_anon("10.0.0.1", ftp_factory=FakeFTP) is None


def test_probe_smb_null_shares():
    class Result:
        returncode = 0
        stdout = "SMB 10.0.0.1 445 HOST [+] domain\\: (guest)\nShareName ... READ\nIPC$ ...\n"
        stderr = ""

    def runner(cmd, **kwargs):
        return Result()

    out = probes.probe_smb("10.0.0.1", runner=runner)
    assert out is not None
    assert "SMB" in out
