from recon import cli_nessus


class FakeClient:
    def __init__(self):
        self.launched = None

    def find_template(self, name):
        return "u-basic"

    def create_scan(self, name, targets, uuid, folder_id=None):
        self.created = (name, targets, uuid)
        return 99

    def launch(self, scan_id):
        self.launched = scan_id
        return "run-uuid"


def test_run_creates_and_launches():
    args = cli_nessus.build_arg_parser().parse_args(
        ["-n", "job", "-t", "10.0.0.1,10.0.0.2"]
    )
    cfg = {"url": "https://nessus:8834", "template": "Basic Network Scan"}
    client = FakeClient()
    rc = cli_nessus.run(args, cfg, client)
    assert rc == 0
    assert client.created[0] == "job"
    assert client.created[1] == "10.0.0.1,10.0.0.2"
    assert client.launched == 99


def test_run_no_launch():
    args = cli_nessus.build_arg_parser().parse_args(
        ["-n", "job", "-t", "10.0.0.1", "--no-launch"]
    )
    cfg = {"url": "https://nessus:8834", "template": "Basic Network Scan"}
    client = FakeClient()
    rc = cli_nessus.run(args, cfg, client)
    assert rc == 0
    assert client.launched is None
