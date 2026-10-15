from pathlib import Path

from recontriage.recon.ports import parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "scanme.xml"


def test_parse_real_fixture():
    ports = parse_nmap_xml(FIXTURE.read_text())
    assert ports, "fixture should contain at least one open port"
    assert all(p["type"] == "port" and p["source"] == "nmap" for p in ports)
    assert all(isinstance(p["port"], int) for p in ports)
    # scanme.nmap.org always has ssh on 22
    ssh = [p for p in ports if p["port"] == 22]
    assert ssh and ssh[0]["service"] == "ssh"
    assert ssh[0]["host"]  # host address was picked up


def test_filtered_ports_are_dropped_and_missing_service_is_ok():
    xml = """
    <nmaprun>
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/></port>
          <port protocol="tcp" portid="81"><state state="filtered"/><service name="x"/></port>
          <port protocol="udp" portid="53"><state state="open"/><service name="domain" product="dnsmasq"/></port>
        </ports>
      </host>
    </nmaprun>"""
    ports = parse_nmap_xml(xml)
    assert [p["port"] for p in ports] == [80, 53]
    assert ports[0]["service"] == ""          # no <service> element, no crash
    assert ports[1] == {
        "type": "port", "host": "10.0.0.1", "port": 53, "proto": "udp",
        "service": "domain", "product": "dnsmasq", "version": "", "extra": "",
        "tunnel": "", "source": "nmap",
    }
