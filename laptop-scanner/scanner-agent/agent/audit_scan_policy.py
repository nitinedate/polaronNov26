"""Offline policy audit: validate configured service port hints, not NVT execution.

Run inside scanner-agent: python -m agent.audit_scan_policy
This validates only the *requested* TCP/UDP port policy. The native task
report and the target's accessible services still decide actual coverage.
"""
from __future__ import annotations

import argparse
import json
import os

from agent.gmp_local import _effective_scan_policy
from agent.service_policy import port_numbers, service_catalog


def _range_ports(spec: str, transport: str) -> set[int]:
    return {n for token in spec.split(',') if token.startswith(f'{transport}:')
            for n in port_numbers(token[2:])}


def audit(profile: str | None = None, udp: str | None = None) -> dict:
    policy = _effective_scan_policy(None, profile or os.getenv('PORT_PROFILE', 'full'),
                                    udp or os.getenv('UDP_PROFILE', 'priority'))
    tcp, udp_ports = _range_ports(policy['port_range'], 'T'), _range_ports(policy['port_range'], 'U')
    missing = []
    for svc in service_catalog()['services']:
        absent_tcp = sorted(set(svc['tcp_hints']) - tcp)
        absent_udp = sorted(set(svc['udp_hints']) - udp_ports)
        if absent_tcp or absent_udp:
            missing.append({'service_id': svc['key'], 'service': svc['name'],
                            'missing_tcp': absent_tcp, 'missing_udp': absent_udp})
    return {
        'port_profile': policy['port_profile'], 'udp_profile': policy['udp_profile'],
        'requested_tcp_ports': len(tcp), 'requested_udp_ports': len(udp_ports),
        'service_families': len(service_catalog()['services']),
        'families_with_port_hints_in_scope': len(service_catalog()['services']) - len(missing),
        'missing_hint_families': missing,
        'port_policy_eligible': not missing,
        'actual_greenbone_execution_verified': False,
        'note': 'Requested port scope only. No per-service NVT execution, credentials, or vulnerability pass is proven.',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Check requested 52-family TCP/UDP port scope')
    parser.add_argument('--profile', default=None, help='Override PORT_PROFILE')
    parser.add_argument('--udp', default=None, help='Override UDP_PROFILE')
    args = parser.parse_args()
    result = audit(profile=args.profile, udp=args.udp)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['port_policy_eligible'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
