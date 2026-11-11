import pytest

from app.core.errors import BackendError
from app.firewall.backends import select_backend
from app.firewall.capabilities import detect_capabilities, parse_os_release
from app.utils.process import CommandResult

UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
ROCKY = 'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n'


def runner(argv, **_):
    if "nft" in argv[0]:
        return CommandResult(0, "nftables v1.0.9 (Old Doc Yak #3)\n", "")
    return CommandResult(0, "iptables v1.8.10 (nf_tables)\n", "")


def caps(tmp_path, osr, kernel, present=("nft", "iptables", "ip6tables", "iptables-restore"), root=True):
    f = tmp_path / "os-release"
    f.write_text(osr)
    return detect_capabilities(os_release=f, runner=runner, kernel_release=kernel,
                               which=lambda n: f"/usr/sbin/{n}" if n in present else None,
                               is_root=root, conntrack_path=tmp_path / "none")


def test_parse():
    assert parse_os_release('# c\nID=x\nA="b c"\n')["A"] == "b c"


def test_ubuntu(tmp_path):
    c = caps(tmp_path, UBUNTU, "6.8.0-149-generic")
    assert (c.distro_id, c.distro_like, c.kernel_tuple) == ("ubuntu", ["debian"], (6, 8))
    assert c.nft_version == "1.0.9" and c.iptables_flavor == "nf_tables"
    assert c.preferred_backend == "nftables" and not c.warnings


def test_rhel_family_and_legacy_kernel(tmp_path):
    c = caps(tmp_path, ROCKY, "3.10.0-1160.el7.x86_64")
    assert c.distro_id == "rocky" and "rhel" in c.distro_like
    assert c.preferred_backend == "iptables"  # kernel < 3.13: nftables unusable


def test_nothing_available(tmp_path):
    c = caps(tmp_path, UBUNTU, "6.8.0", present=(), root=False)
    assert c.preferred_backend is None and len(c.warnings) == 2
    with pytest.raises(BackendError):
        select_backend(c)


def test_missing_osrelease(tmp_path):
    c = detect_capabilities(os_release=tmp_path / "nope", runner=runner, kernel_release="6.1.0",
                            which=lambda n: None, is_root=True)
    assert c.distro_id == "unknown" and "cannot read os-release" in c.warnings


def test_select_explicit_and_unsupported(tmp_path):
    c = caps(tmp_path, UBUNTU, "6.8.0")
    assert select_backend(c, "iptables").name == "iptables"
    assert select_backend(c).name == "nftables"
    c2 = caps(tmp_path, UBUNTU, "6.8.0", present=("iptables", "ip6tables", "iptables-restore"))
    with pytest.raises(BackendError):
        select_backend(c2, "nftables")
