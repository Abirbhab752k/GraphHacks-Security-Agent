"""
seed.py — Populate FalkorDB with a mock enterprise network for cybersec triage.

Run once:
    python seed.py

The script is idempotent: it wipes old nodes/edges from security_graph first
so re-runs are always safe.

Attack path seeded
------------------
    192.168.1.200 (Suspicious IP)
        --[ACCESSED]--> Server-PROD-01 (Device)
        --[OWNS (via attacker user)]--
        jsmith (User, compromised)
            --[ACCESSED]--> DB-CRITICAL (Service)
            --[TRIGGERED]--> ALERT-001 (Security_Alert)

A second lateral-movement hop is also included:
    Server-PROD-01 --[COMMUNICATES_WITH]--> Server-PROD-02
    Server-PROD-02 --[ACCESSED by]-- jsmith (via OWNS chain)
"""

from __future__ import annotations

import logging
import sys

from database import get_graph

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cypher helpers
# ---------------------------------------------------------------------------

def _run(cypher: str, params: dict | None = None) -> None:
    graph = get_graph()
    graph.query(cypher, params or {})


# ---------------------------------------------------------------------------
# Wipe existing data
# ---------------------------------------------------------------------------

def _clear_graph() -> None:
    logger.info("Clearing existing graph data …")
    _run("MATCH (n) DETACH DELETE n")
    logger.info("Graph cleared.")


# ---------------------------------------------------------------------------
# Create nodes
# ---------------------------------------------------------------------------

NODE_QUERIES: list[str] = [
    # ── IP Addresses ────────────────────────────────────────────────────────
    """
    CREATE (:IP_Address {
        id: 'ip-suspicious-001',
        address: '192.168.1.200',
        label: '192.168.1.200',
        reputation: 'malicious',
        country: 'Unknown',
        asn: 'AS666',
        first_seen: '2024-11-01T02:14:00Z',
        threat_score: 98,
        status: 'Active'
    })
    """,
    """
    CREATE (:IP_Address {
        id: 'ip-internal-010',
        address: '10.0.0.10',
        label: '10.0.0.10',
        reputation: 'internal',
        country: 'US',
        asn: 'CORP-NET',
        first_seen: '2023-01-01T00:00:00Z',
        threat_score: 5,
        status: 'Active'
    })
    """,
    """
    CREATE (:IP_Address {
        id: 'ip-internal-020',
        address: '10.0.0.20',
        label: '10.0.0.20',
        reputation: 'internal',
        country: 'US',
        asn: 'CORP-NET',
        first_seen: '2023-01-01T00:00:00Z',
        threat_score: 5,
        status: 'Active'
    })
    """,

    # ── Devices ─────────────────────────────────────────────────────────────
    """
    CREATE (:Device {
        id: 'dev-prod-01',
        hostname: 'Server-PROD-01',
        label: 'Server-PROD-01',
        os: 'Ubuntu 22.04',
        role: 'Application Server',
        ip: '10.0.0.10',
        criticality: 'HIGH',
        status: 'Active',
        last_patched: '2024-09-15',
        open_ports: '22,80,443,8080'
    })
    """,
    """
    CREATE (:Device {
        id: 'dev-prod-02',
        hostname: 'Server-PROD-02',
        label: 'Server-PROD-02',
        os: 'Ubuntu 22.04',
        role: 'Database Proxy',
        ip: '10.0.0.20',
        criticality: 'CRITICAL',
        status: 'Active',
        last_patched: '2024-08-01',
        open_ports: '22,5432'
    })
    """,
    """
    CREATE (:Device {
        id: 'dev-workstation-jsmith',
        hostname: 'WS-JSMITH',
        label: 'WS-JSMITH',
        os: 'Windows 11',
        role: 'User Workstation',
        ip: '10.0.1.55',
        criticality: 'MEDIUM',
        status: 'Active',
        last_patched: '2024-10-01',
        open_ports: '135,445'
    })
    """,

    # ── Users ────────────────────────────────────────────────────────────────
    """
    CREATE (:User {
        id: 'user-jsmith',
        username: 'jsmith',
        label: 'jsmith',
        full_name: 'John Smith',
        department: 'Engineering',
        role: 'Senior Developer',
        email: 'jsmith@corp.local',
        mfa_enabled: false,
        auth_status: 'active',
        last_login: '2024-11-10T02:16:00Z',
        privilege_level: 'admin',
        status: 'Active'
    })
    """,
    """
    CREATE (:User {
        id: 'user-aadmin',
        username: 'aadmin',
        label: 'aadmin',
        full_name: 'Alice Admin',
        department: 'IT',
        role: 'System Administrator',
        email: 'aadmin@corp.local',
        mfa_enabled: true,
        auth_status: 'active',
        last_login: '2024-11-09T17:00:00Z',
        privilege_level: 'superadmin',
        status: 'Active'
    })
    """,

    # ── Services ─────────────────────────────────────────────────────────────
    """
    CREATE (:Service {
        id: 'svc-db-critical',
        name: 'DB-CRITICAL',
        label: 'DB-CRITICAL',
        type: 'PostgreSQL',
        port: 5432,
        host: '10.0.0.20',
        classification: 'SECRET',
        data_sensitivity: 'HIGH',
        contains_pii: true,
        status: 'Active'
    })
    """,
    """
    CREATE (:Service {
        id: 'svc-auth-api',
        name: 'Auth-API',
        label: 'Auth-API',
        type: 'REST API',
        port: 8080,
        host: '10.0.0.10',
        classification: 'INTERNAL',
        data_sensitivity: 'MEDIUM',
        contains_pii: false,
        status: 'Active'
    })
    """,
    """
    CREATE (:Service {
        id: 'svc-hr-portal',
        name: 'HR-Portal',
        label: 'HR-Portal',
        type: 'Web Application',
        port: 443,
        host: '10.0.0.10',
        classification: 'CONFIDENTIAL',
        data_sensitivity: 'HIGH',
        contains_pii: true,
        status: 'Active'
    })
    """,

    # ── Security Alerts ──────────────────────────────────────────────────────
    """
    CREATE (:Security_Alert {
        id: 'alert-001',
        alert_id: 'ALERT-001',
        label: 'ALERT-001',
        severity: 'CRITICAL',
        type: 'Brute Force + Lateral Movement',
        description: 'Suspicious IP executed SSH brute-force on Server-PROD-01, then accessed DB-CRITICAL',
        source_system: 'SIEM-Splunk',
        timestamp: '2024-11-10T02:14:55Z',
        status: 'Open',
        mitre_tactic: 'TA0001,TA0008',
        mitre_technique: 'T1110,T1021'
    })
    """,
    """
    CREATE (:Security_Alert {
        id: 'alert-002',
        alert_id: 'ALERT-002',
        label: 'ALERT-002',
        severity: 'HIGH',
        type: 'Privilege Escalation',
        description: 'User jsmith attempted privilege escalation on DB-CRITICAL',
        source_system: 'EDR-CrowdStrike',
        timestamp: '2024-11-10T02:17:30Z',
        status: 'Open',
        mitre_tactic: 'TA0004',
        mitre_technique: 'T1068'
    })
    """,
]


# ---------------------------------------------------------------------------
# Create relationships
# ---------------------------------------------------------------------------

EDGE_QUERIES: list[str] = [
    # Suspicious IP → accessed production server (entry point)
    """
    MATCH (ip:IP_Address {id: 'ip-suspicious-001'}),
          (dev:Device      {id: 'dev-prod-01'})
    CREATE (ip)-[:ACCESSED {
        timestamp: '2024-11-10T02:14:00Z',
        method: 'SSH brute-force',
        port: 22,
        success: true,
        session_duration_s: 843
    }]->(dev)
    """,

    # Suspicious IP also touched Server-PROD-02 (lateral movement)
    """
    MATCH (ip:IP_Address {id: 'ip-suspicious-001'}),
          (dev:Device      {id: 'dev-prod-02'})
    CREATE (ip)-[:ACCESSED {
        timestamp: '2024-11-10T02:28:00Z',
        method: 'SSH',
        port: 22,
        success: true,
        session_duration_s: 310
    }]->(dev)
    """,

    # Server-PROD-01 communicates with Server-PROD-02 (pivot vector)
    """
    MATCH (d1:Device {id: 'dev-prod-01'}),
          (d2:Device {id: 'dev-prod-02'})
    CREATE (d1)-[:COMMUNICATES_WITH {
        protocol: 'PostgreSQL wire',
        port: 5432,
        frequency: 'high',
        anomaly_detected: true
    }]->(d2)
    """,

    # jsmith owns both server and workstation
    """
    MATCH (u:User   {id: 'user-jsmith'}),
          (d:Device {id: 'dev-prod-01'})
    CREATE (u)-[:OWNS {
        role: 'primary operator',
        since: '2023-03-01',
        sudo_access: true
    }]->(d)
    """,
    """
    MATCH (u:User   {id: 'user-jsmith'}),
          (d:Device {id: 'dev-workstation-jsmith'})
    CREATE (u)-[:OWNS {
        role: 'workstation owner',
        since: '2023-01-10',
        sudo_access: false
    }]->(d)
    """,

    # aadmin owns Server-PROD-02
    """
    MATCH (u:User   {id: 'user-aadmin'}),
          (d:Device {id: 'dev-prod-02'})
    CREATE (u)-[:OWNS {
        role: 'DBA',
        since: '2022-06-01',
        sudo_access: true
    }]->(d)
    """,

    # jsmith accessed critical DB (the key lateral movement / blast-radius hop)
    """
    MATCH (u:User    {id: 'user-jsmith'}),
          (s:Service {id: 'svc-db-critical'})
    CREATE (u)-[:ACCESSED {
        timestamp: '2024-11-10T02:16:45Z',
        method: 'psql CLI via compromised session',
        queries_executed: 47,
        data_exfiltrated_mb: 2.3,
        anomalous: true
    }]->(s)
    """,

    # jsmith also accessed auth-api and hr-portal (blast radius)
    """
    MATCH (u:User    {id: 'user-jsmith'}),
          (s:Service {id: 'svc-auth-api'})
    CREATE (u)-[:ACCESSED {
        timestamp: '2024-11-10T02:15:10Z',
        method: 'REST API token',
        queries_executed: 12,
        anomalous: true
    }]->(s)
    """,
    """
    MATCH (u:User    {id: 'user-jsmith'}),
          (s:Service {id: 'svc-hr-portal'})
    CREATE (u)-[:ACCESSED {
        timestamp: '2024-11-10T02:15:55Z',
        method: 'HTTP session cookie',
        queries_executed: 5,
        anomalous: false
    }]->(s)
    """,

    # Alerts triggered
    """
    MATCH (ip:IP_Address      {id: 'ip-suspicious-001'}),
          (a:Security_Alert   {id: 'alert-001'})
    CREATE (ip)-[:TRIGGERED {
        rule: 'SSH-BRUTE-001',
        confidence: 0.97
    }]->(a)
    """,
    """
    MATCH (u:User            {id: 'user-jsmith'}),
          (a:Security_Alert  {id: 'alert-002'})
    CREATE (u)-[:TRIGGERED {
        rule: 'PRIVESC-DB-001',
        confidence: 0.88
    }]->(a)
    """,
]


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

def seed() -> None:
    _clear_graph()

    logger.info("Creating nodes …")
    for q in NODE_QUERIES:
        _run(q)
    logger.info("  %d node queries executed.", len(NODE_QUERIES))

    logger.info("Creating edges …")
    for q in EDGE_QUERIES:
        _run(q)
    logger.info("  %d edge queries executed.", len(EDGE_QUERIES))

    # Quick verification
    graph = get_graph()
    node_count = graph.query("MATCH (n) RETURN count(n) AS c").result_set[0][0]
    edge_count = graph.query("MATCH ()-[r]->() RETURN count(r) AS c").result_set[0][0]
    logger.info("Seed complete — %d nodes, %d edges in '%s'.", node_count, edge_count, "security_graph")


if __name__ == "__main__":
    try:
        seed()
    except Exception as exc:
        logger.error("Seeding failed: %s", exc)
        sys.exit(1)
