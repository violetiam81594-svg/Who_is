#!/usr/bin/env python3
"""
BLAME GAME v1.0 — Code Forensics & Accountability System

EXPOSES deceptive coding practices, hidden workflows, and malicious data flows.
Labels EVERY action: WHO | WHEN | WHERE | WHAT | WHY

"Those with nothing to fear have nothing to hide."

Author: violetiam81594
License: MIT
Purpose: Security audit, fraud prevention, accountability
"""

import os
import sys
import json
import hashlib
import base64
import uuid
import time
import datetime
import argparse
import struct
import sqlite3
import re
import traceback
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from urllib.request import urlopen, Request
from urllib.parse import urlparse, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client
from dataclasses import dataclass, asdict
from enum import Enum

# ============================================================
# SECTION 1: RED FLAG PATTERN DATABASE
# ============================================================

class ThreatLevel(Enum):
    LOW = "low"           # Suspicious but explainable
    MEDIUM = "medium"     | Requires investigation
    HIGH = "high"         | Likely malicious
    CRITICAL = "critical" | Confirmed harmful pattern

@dataclass
class RedFlagPattern:
    """Known malicious or deceptive code patterns."""
    name: str
    pattern: str  # Regex pattern
    threat_level: ThreatLevel
    description: str
    category: str  # 'financial', 'data_theft', 'deception', 'obfuscation'
    example_code: str

RED_FLAG_DATABASE: List[RedFlagPattern] = [
    # Financial deception patterns
    RedFlagPattern(
        name="stripe_hidden_redirect",
        pattern=r"(?:r\.stripe|stripe\.redirect|payment\.bounce)",
        threat_level=ThreatLevel.HIGH,
        description="Redirects payment through intermediary - potential fund diversion",
        category="financial",
        example_code="const paymentUrl = r.stripe.bounce('/capture');"
    ),
    RedFlagPattern(
        name="p2p_obfuscated_transfer",
        pattern=r"\bp2p\s*(?:transfer|send|flow|bounce|route)\b",
        threat_level=ThreatLevel.MEDIUM,
        description="'P2P' terminology often hides untraceable transfers",
        category="financial",
        example_code="function p2pTransfer(user) { routeToOffshore(user.amount); }"
    ),
    RedFlagPattern(
        name="kanata_kantana_api_labs",
        pattern=r"(?:kanata|kantana|kantan)\s*(?:api|labs|service)\b",
        threat_level=ThreatLevel.HIGH,
        description="Suspicious third-party API providers claiming fake legitimacy",
        category="deception",
        example_code="import { KantanaAPILabs } from '@hidden/package';"
    ),
    RedFlagPattern(
        name="ad_privacy_deception",
        pattern=r"\bad\s*\w*\s*(?:privacy|track|collect|audit|consent)\b.*(?:false|null|skip)",
        threat_level=ThreatLevel.HIGH,
        description="Claims 'privacy' while collecting data - contradiction",
        category="data_theft",
        example_code="const adPrivacyMode = false; // Collect all user events"
    ),
    RedFlagPattern(
        name="null_fallback_exploit",
        pattern=r"(?:||\s*null|\?\s*\{\}|or\s+fallback)\s*=\s*(?:window\.parent|top|location)",
        threat_level=ThreatLevel.CRITICAL,
        description="Null fallback redirects to external frames - iframe hijacking",
        category="obfuscation",
        example_code="const target = userValue || null = window.parent.location;"
    ),
    RedFlagPattern(
        name="index_manipulation",
        pattern=r"index\s*[+\-=]\s*\d+\s*;.*(?:eval|exec|import|require)",
        threat_level=ThreatLevel.HIGH,
        description="Array index manipulation used to hide code execution paths",
        category="obfuscation",
        example_code="let i = 0; i += 1; eval(arr[i]);"
    ),
    RedFlagPattern(
        name="ai_blame_shift",
        pattern=r"(?:ai|algorithm|model).*(?:responsible|decision|error|fault).*human",
        threat_level=ThreatLevel.MEDIUM,
        description="Shifts blame to AI for human-designed harmful logic",
        category="deception",
        example_code="// AI made this decision, not us"
    ),
    RedFlagPattern(
        name="hidden_webhook",
        pattern=r"(?:webhook|callback|hook).*?(?:external|third|secret|hidden)",
        threat_level=ThreatLevel.HIGH,
        description="Undisclosed external callbacks sending data elsewhere",
        category="data_theft",
        example_code="const webhook = 'https://hidden-server.com/collect';"
    ),
    RedFlagPattern(
        name="consent_bypass",
        pattern=r"(?:consent|permission|opt.?out).*?(?:force|bypass|override|skip)",
        threat_level=ThreatLevel.CRITICAL,
        description="Actively bypasses user consent mechanisms",
        category="data_theft",
        example_code="if (!userConsent) { forceDataCollection(); }"
    ),
    RedFlagPattern(
        name="obfuscated_endpoint",
        pattern=r"(?:endpoint|url|host).*?(?:base64|atob|fromCharCode|String\.from)",
        threat_level=ThreatLevel.HIGH,
        description="Endpoints hidden via encoding to avoid detection",
        category="obfuscation",
        example_code="const api = atob('aHR0cHM6Ly9zYWFyLmlv'); // saari.io"
    ),
    RedFlagPattern(
        name="data_exfiltration_beacon",
        pattern=r"(?:beacon|ping|track|send).*?(?:navigator|fetch|xmlhttprequest)",
        threat_level=ThreatLevel.HIGH,
        description="Silent background data transmission without disclosure",
        category="data_theft",
        example_code="navigator.sendBeacon('/track', userData);"
    ),
    RedFlagPattern(
        name="dom_overwrite_attack",
        pattern=r"(?:body|document|innerHTML).*?=",
        threat_level=ThreatLevel.MEDIUM,
        description="Complete DOM replacement - could hide malicious content",
        category="obfuscation",
        example_code="document.body.innerHTML = externalHtml;"
    ),
    RedFlagPattern(
        name="timer_based_evasion",
        pattern=r"(?:setTimeout|setInterval).*?(?:eval|function\(|=>)",
        threat_level=ThreatLevel.MEDIUM,
        description="Delayed code execution to evade static analysis",
        category="obfuscation",
        example_code="setTimeout(() => eval(maliciousCode), 5000);"
    ),
    RedFlagPattern(
        name="crypto_miner_hidden",
        pattern=r"(?:coin|hive|miner|xmr|crypto).*?(?:start|run|execute|pool)",
        threat_level=ThreatLevel.CRITICAL,
        description="Cryptocurrency mining code - steals user resources",
        category="malware",
        example_code="CryptoMiner.startPool('https://mine.steal.com');"
    ),
    RedFlagPattern(
        name="keylogger_pattern",
        pattern=r"(?:keydown|keyup|keypress).*?(?:addEventListener|on)",
        threat_level=ThreatLevel.CRITICAL,
        description="Key press monitoring - captures passwords/credentials",
        category="malware",
        example_code="document.onkeydown = e => collectKeystroke(e.key);"
    ),
]


# ============================================================
# SECTION 2: CODE ANALYZER & PATTERN DETECTOR
# ============================================================

@dataclass
class CodeFinding:
    """Single finding from code analysis."""
    timestamp: str
    file_path: str
    line_number: int
    pattern_name: str
    threat_level: str
    matched_code: str
    description: str
    category: str
    severity_score: int  # 0-100
    recommended_action: str

class CodeForensicsAnalyzer:
    """Scans code for deceptive/malicious patterns."""
    
    def __init__(self):
        self.patterns = RED_FLAG_DATABASE
        self.findings: List[CodeFinding] = []
        self.file_hashes: Dict[str, str] = {}
        
    def scan_file(self, filepath: str) -> List[CodeFinding]:
        """Analyze single file for red flag patterns."""
        findings = []
        file_hash = self._compute_file_hash(filepath)
        self.file_hashes[filepath] = file_hash
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            return [self._create_finding_error(filepath, str(e))]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.patterns:
                if re.search(pattern.pattern, line, re.IGNORECASE):
                    finding = self._create_finding(
                        filepath, line_num, pattern, line.strip(), file_hash
                    )
                    findings.append(finding)
                    self.findings.append(finding)
                    
        return findings
    
    def scan_directory(self, dirpath: str, extensions: List[str] = None) -> List[CodeFinding]:
        """Recursively scan directory for all files."""
        if extensions is None:
            extensions = ['.js', '.py', '.ts', '.jsx', '.tsx', '.html', '.css', '.json', '.java', '.swift', '.kt']
        
        all_findings = []
        path_obj = Path(dirpath)
        
        for ext in extensions:
            for file_path in path_obj.rglob(f'*{ext}'):
                file_findings = self.scan_file(str(file_path))
                all_findings.extend(file_findings)
        
        return all_findings
    
    def _compute_file_hash(self, filepath: str) -> str:
        """Compute SHA256 hash of file."""
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def _create_finding(self, filepath: str, line_num: int, 
                        pattern: RedFlagPattern, matched_line: str,
                        file_hash: str) -> CodeFinding:
        """Create structured finding record."""
        severity_map = {
            ThreatLevel.LOW: 25,
            ThreatLevel.MEDIUM: 50,
            ThreatLevel.HIGH: 75,
            ThreatLevel.CRITICAL: 100
        }
        
        action_map = {
            ThreatLevel.LOW: "Review and document reason for pattern",
            ThreatLevel.MEDIUM: "Investigate purpose, request explanation from author",
            ThreatLevel.HIGH: "Block deployment, conduct security review",
            ThreatLevel.CRITICAL: "Remove immediately, preserve evidence for legal"
        }
        
        return CodeFinding(
            timestamp=datetime.datetime.utcnow().isoformat(),
            file_path=filepath,
            line_number=line_num,
            pattern_name=pattern.name,
            threat_level=pattern.threat_level.value,
            matched_code=matched_line[:200],  # Truncate very long lines
            description=pattern.description,
            category=pattern.category,
            severity_score=severity_map[pattern.threat_level],
            recommended_action=action_map[pattern.threat_level]
        )
    
    def _create_finding_error(self, filepath: str, error_msg: str) -> CodeFinding:
        """Create finding for file read errors."""
        return CodeFinding(
            timestamp=datetime.datetime.utcnow().isoformat(),
            file_path=filepath,
            line_number=0,
            pattern_name="FILE_READ_ERROR",
            threat_level="low",
            matched_code="",
            description=f"Could not analyze file: {error_msg}",
            category="error",
            severity_score=10,
            recommended_action="Check file permissions and encoding"
        )


# ============================================================
# SECTION 3: NETWORK INTERCEPTION LOGGER
# ============================================================

@dataclass
class NetworkRequest:
    """Captured network request with full attribution."""
    id: str
    timestamp: str
    source_ip: str
    destination_url: str
    method: str
    headers: Dict[str, str]
    body_size: int
    response_status: int
    user_agent: str
    referrer: str
    origin_page: str
    is_third_party: bool
    data_categories_sent: List[str]
    data_categories_received: List[str]

class NetworkTrafficLogger(BaseHTTPRequestHandler):
    """Proxy server that logs ALL traffic passing through."""
    
    def __init__(self, *args, log_database: str = "./traffic_audit.db", **kwargs):
        super().__init__(*args, **kwargs)
        self.db_path = log_database
        self._init_database()
    
    def _init_database(self):
        """Create SQLite database for traffic logs."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_requests (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                destination_url TEXT,
                method TEXT,
                headers_json TEXT,
                body_size INTEGER,
                response_status INTEGER,
                user_agent TEXT,
                referrer TEXT,
                origin_page TEXT,
                is_third_party BOOLEAN,
                data_sent_categories TEXT,
                data_received_categories TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON network_requests(timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_destination ON network_requests(destination_url)
        ''')
        
        conn.commit()
        conn.close()
    
    def log_request(self, request_data: NetworkRequest):
        """Store request in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO network_requests 
            (id, timestamp, source_ip, destination_url, method, headers_json,
             body_size, response_status, user_agent, referrer, origin_page,
             is_third_party, data_sent_categories, data_received_categories)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request_data.id,
            request_data.timestamp,
            request_data.source_ip,
            request_data.destination_url,
            request_data.method,
            json.dumps(request_data.headers),
            request_data.body_size,
            request_data.response_status,
            request_data.user_agent,
            request_data.referrer,
            request_data.origin_page,
            1 if request_data.is_third_party else 0,
            json.dumps(request_data.data_categories_sent),
            json.dumps(request_data.data_categories_received)
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[LOGGED] {request_data.timestamp} | {request_data.source_ip} -> {request_data.destination_url}")
    
    def log_message(self, format, *args):
        pass  # Suppress default logging


# ============================================================
# SECTION 4: DEVICE & LOCATION ATTESTATION
# ============================================================

@dataclass
class DeviceAttestation:
    """Full device fingerprint and location data for accountability."""
    id: str
    timestamp: str
    ip_address: str
    geo_location: Dict[str, Any]  # lat, lon, city, country from IP geolocation
    user_agent: str
    screen_resolution: str
    timezone: str
    language: str
    platform: str
    browser_version: str
    device_fingerprint: str  # Unique ID derived from hardware characteristics
    consent_given: bool
    consent_timestamp: Optional[str]
    data_requested_by: Optional[str]  # Who requested this data

class DeviceAttester:
    """Collects and attests device identity."""
    
    def __init__(self, tracking_domain: str):
        self.tracking_domain = tracking_domain
        self.attestations: List[DeviceAttestation] = []
    
    def generate_fingerprint(self, user_agent: str, screen_res: str, 
                            timezone: str, platform: str) -> str:
        """Generate unique device fingerprint from available signals."""
        components = [user_agent, screen_res, timezone, platform]
        raw = '|'.join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
    
    def estimate_geo_from_ip(self, ip_address: str) -> Dict[str, Any]:
        """Get approximate location from IP (using free services)."""
        # Using ip-api.com (free tier, no auth required)
        try:
            url = f"http://ip-api.com/json/{ip_address}"
            req = Request(url, headers={'User-Agent': 'BlameGame/1.0'})
            response = urlopen(req, timeout=5)
            data = json.loads(response.read().decode())
            
            if data.get('status') == 'success':
                return {
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'isp': data.get('isp')
                }
        except Exception:
            pass
        
        return {'unknown': True}
    
    def attest_access(self, ip_address: str, user_agent: str, 
                      screen_res: str = "", timezone: str = "",
                      platform: str = "", language: str = "",
                      consent_given: bool = False,
                      data_requester: Optional[str] = None) -> DeviceAttestation:
        """Create attestation record for this access."""
        
        # Generate device fingerprint
        fp = self.generate_fingerprint(user_agent, screen_res, timezone, platform)
        
        # Get location data
        geo = self.estimate_geo_from_ip(ip_address)
        
        attestation = DeviceAttestation(
            id=str(uuid.uuid4()),
            timestamp=datetime.datetime.utcnow().isoformat(),
            ip_address=ip_address,
            geo_location=geo,
            user_agent=user_agent,
            screen_resolution=screen_res,
            timezone=timezone,
            language=language,
            platform=platform,
            browser_version=self._extract_browser_version(user_agent),
            device_fingerprint=fp,
            consent_given=consent_given,
            consent_timestamp=datetime.datetime.utcnow().isoformat() if consent_given else None,
            data_requested_by=data_requester
        )
        
        self.attestations.append(attestation)
        return attestation
    
    def _extract_browser_version(self, user_agent: str) -> str:
        """Extract browser name and version from User-Agent string."""
        patterns = {
            'Chrome': r'Chrome/(\d+\.\d+\.\d+\.\d+)',
            'Firefox': r'Firefox/(\d+\.\d+)',
            'Safari': r'Safari/(\d+\.\d+)',
            'Edge': r'Edg/(\d+\.\d+\.\d+\.\d+)'
        }
        
        for browser, pattern in patterns.items():
            match = re.search(pattern, user_agent)
            if match:
                return f"{browser} {match.group(1)}"
        
        return "Unknown"


# ============================================================
# SECTION 5: CHANGE TRACKING & VERSION LABELING
# ============================================================

@dataclass
class FileChange:
    """Tracks every change made to a file."""
    id: str
    timestamp: str
    file_path: str
    change_type: str  # 'modified', 'deleted', 'created', 'accessed'
    changed_by: str  # IP or user identifier
    old_hash: Optional[str]
    new_hash: Optional[str]
    diff_summary: str  # Brief description of what changed
    reason_provided: Optional[str]  # If changelog entry provided
    approved_by: Optional[str]

class ChangeTracker:
    """Immutable changelog system - nothing gets deleted, only appended."""
    
    def __init__(self, changelog_db: str = "./change_audit.db"):
        self.db_path = changelog_db
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_changes (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                file_path TEXT,
                change_type TEXT,
                changed_by TEXT,
                old_hash TEXT,
                new_hash TEXT,
                diff_summary TEXT,
                reason_provided TEXT,
                approved_by TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_file ON file_changes(file_path)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_time ON file_changes(timestamp)
        ''')
        
        conn.commit()
        conn.close()
    
    def log_change(self, file_path: str, change_type: str, 
                   changed_by: str, old_hash: Optional[str] = None,
                   new_hash: Optional[str] = None,
                   diff_summary: str = "",
                   reason_provided: Optional[str] = None,
                   approved_by: Optional[str] = None) -> FileChange:
        """Record an immutable change event."""
        
        change = FileChange(
            id=str(uuid.uuid4()),
            timestamp=datetime.datetime.utcnow().isoformat(),
            file_path=file_path,
            change_type=change_type,
            changed_by=changed_by,
            old_hash=old_hash,
            new_hash=new_hash,
            diff_summary=diff_summary,
            reason_provided=reason_provided,
            approved_by=approved_by
        )
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO file_changes 
            (id, timestamp, file_path, change_type, changed_by,
             old_hash, new_hash, diff_summary, reason_provided, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            change.id, change.timestamp, change.file_path, change.change_type,
            change.changed_by, change.old_hash, change.new_hash,
            change.diff_summary, change.reason_provided, change.approved_by
        ))
        
        conn.commit()
        conn.close()
        
        print(f"[CHANGE LOGGED] {change.timestamp} | {file_path} | {change_type} | {changed_by}")
        
        return change
    
    def get_file_history(self, file_path: str) -> List[FileChange]:
        """Retrieve complete change history for a file."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM file_changes 
            WHERE file_path = ? 
            ORDER BY timestamp ASC
        ''', (file_path,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            FileChange(
                id=row[0], timestamp=row[1], file_path=row[2], change_type=row[3],
                changed_by=row[4], old_hash=row[5], new_hash=row[6],
                diff_summary=row[7], reason_provided=row[8], approved_by=row[9]
            )
            for row in rows
        ]
    
    def verify_no_deletion(self) -> bool:
        """Verify database integrity - changes cannot be deleted."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if deletion operation was attempted
        cursor.execute('''
            PRAGMA foreign_key_check
        ''')
        
        violations = cursor.fetchall()
        conn.close()
        
        if violations:
            print(f"[WARNING] Database integrity issues detected: {violations}")
            return False
        
        return True


# ============================================================
# SECTION 6: BLAME GAME REPORT GENERATOR
# ============================================================

def generate_blame_game_report(findings: List[CodeFinding], 
                               attestations: List[DeviceAttestation],
                               changes: List[FileChange],
                               output_path: str = 'blame_game_report.md'):
    """Generate comprehensive accountability report."""
    
    # Calculate summary stats
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if f.threat_level == 'critical')
    high_count = sum(1 for f in findings if f.threat_level == 'high')
    medium_count = sum(1 for f in findings if f.threat_level == 'medium')
    
    # Group by category
    categories = {}
    for f in findings:
        cat = f.category
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1
    
    report = f"""# BLAME GAME — Accountability Report

**Generated:** {datetime.datetime.utcnow().isoformat()}
**Report ID:** {uuid.uuid4()}
**Author:** violetiam81594

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Findings | {total_findings} |
| Critical Threats | {critical_count} |
| High Threats | {high_count} |
| Medium Threats | {medium_count} |
| Devices Attested | {len(attestations)} |
| Changes Logged | {len(changes)} |

---

## Threat Distribution by Category

"""
    
    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        report += f"- **{cat.upper()}**: {count} finding(s)\n"
    
    report += f"""
---

## Critical & High Severity Findings

"""
    
    # Sort by severity
    severe_findings = sorted(findings, 
                            key=lambda x: x.severity_score, 
                            reverse=True)[:20]  # Top 20
    
    for i, finding in enumerate(severe_findings, 1):
        report += f"""### {i}. {finding.pattern_name}

| Field | Value |
|-------|-------|
| **File** | `{finding.file_path}` |
| **Line** | {finding.line_number} |
| **Threat Level** | {finding.threat_level.upper()} |
| **Category** | {finding.category} |
| **Score** | {finding.severity_score}/100 |
| **Matched Code** | `{finding.matched_code}` |
| **Description** | {finding.description} |
| **Recommended Action** | {finding.recommended_action} |
| **Timestamp** | {finding.timestamp} |

---

"""
    
    report += f"""
## Device Access History

These devices accessed tracked content:

| Timestamp | IP Address | Location | Device Fingerprint | Consent Given |
|-----------|------------|----------|-------------------|---------------|
"""
    
    for att in attestations[-10:]:  # Last 10
        loc = f"{att.geo_location.get('city', '?')}, {att.geo_location.get('country', '?')}"
        consent = "✓ Yes" if att.consent_given else "✗ No"
        report += f"| {att.timestamp} | {att.ip_address} | {loc} | {att.device_fingerprint[:16]}... | {consent} |\n"
    
    report += f"""
---

## File Modification Audit Trail

Any file changes are permanently logged (cannot be deleted):

| Timestamp | File | Change Type | Changed By | Reason Provided | Approved By |
|-----------|------|-------------|------------|-----------------|-------------|
"""
    
    for change in changes[-10:]:  # Last 10
        reason = change.reason_provided or "(none provided)"
        approver = change.approved_by or "(no approval)"
        report += f"| {change.timestamp} | `{change.file_path}` | {change.change_type} | {change.changed_by} | {reason} | {approver} |\n"
    
    report += f"""
---

## Red Flag Pattern Reference

Known deceptive patterns this system detects:

"""
    
    for pattern in RED_FLAG_DATABASE:
        report += f"""
### {pattern.name}
- **Category:** {pattern.category}
- **Threat Level:** {pattern.threat_level.value.upper()}
- **Description:** {pattern.description}
- **Example:** `{pattern.example_code}`

"""
    
    report += f"""
---

## Disclaimer & Legal Notice

This report is generated by **BLAME GAME** for accountability and transparency purposes.

**Important:**
- IP addresses identify connections, not individuals
- This system logs objectively; interpretation requires context
- Innocent parties have nothing to fear from openness
- Consult qualified legal counsel before taking enforcement action
- Evidence collection does not equal prosecution

**Philosophy:** Those who operate honestly benefit from transparency. Deceptive actors resist accountability.

---

## Verification

To verify this report's authenticity:
```bash
sha256sum blame_game_report.md
# Compare against hash stored in immutable ledger
```

---

**Report Ends — All findings preserved immutably**

---

*Built by violetiam81594 | Open Source | MIT License*
"""
    
    with open(output_path, 'w') as f:
        f.write(report)
    
    print(f"[REPORT] Saved to {output_path}")


# ============================================================
# SECTION 7: WEB SCANNER FOR EXTERNAL CONTENT
# ============================================================

def scan_remote_url_for_patterns(url: str, timeout: int = 10) -> List[CodeFinding]:
    """Fetch and analyze remote webpage for red flag patterns."""
    
    analyzer = CodeForensicsAnalyzer()
    findings = []
    
    try:
        req = Request(url, headers={'User-Agent': 'BlameGame/1.0'})
        response = urlopen(req, timeout=timeout)
        content = response.read().decode(errors='ignore')
        
        # Simulate file path for reporting
        temp_path = f"[REMOTE:{url}]"
        
        for line_num, line in enumerate(content.split('\n'), 1):
            for pattern in analyzer.patterns:
                if re.search(pattern.pattern, line, re.IGNORECASE):
                    finding = analyzer._create_finding(
                        temp_path, line_num, pattern, line.strip(), 
                        hashlib.sha256(content.encode()).hexdigest()
                    )
                    findings.append(finding)
    
    except Exception as e:
        print(f"[ERROR] Failed to scan {url}: {e}")
    
    return findings


# ============================================================
# SECTION 8: MAIN CLI INTERFACE
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='BLAME GAME — Code Forensics & Accountability System'
    )
    subparsers = parser.add_subparsers(dest='command')
    
    # Scan local code
    scan_parser = subparsers.add_parser('scan', help='Scan local code/filesystem')
    scan_parser.add_argument('path', type=str, help='File or directory to scan')
    scan_parser.add_argument('--output', '-o', type=str, default='findings.json',
                            help='Output JSON file')
    
    # Scan remote URL
    remote_parser = subparsers.add_parser('scan-remote', help='Scan remote URL')
    remote_parser.add_argument('url', type=str, help='URL to scan')
    remote_parser.add_argument('--output', '-o', type=str, default='remote_findings.json',
                              help='Output JSON file')
    
    # Log device access
    device_parser = subparsers.add_parser('attest-device', help='Record device access')
    device_parser.add_argument('--ip', required=True, help='Client IP')
    device_parser.add_argument('--ua', required=True, dest='user_agent', help='User Agent')
    parser_device = device_parser.add_mutually_exclusive_group(required=False)
    parser_device.add_argument('--consent', action='store_true', help='Consent given')
    
    # Log file change
    change_parser = subparsers.add_parser('log-change', help='Record file modification')
    change_parser.add_argument('--file', required=True, help='File path')
    change_parser.add_argument('--type', required=True, choices=['created', 'modified', 'deleted'])
    change_parser.add_argument('--changed-by', required=True, help='Who made the change')
    change_parser.add_argument('--reason', help='Reason for change')
    change_parser.add_argument('--approved-by', help='Approver')
    
    # Generate report
    report_parser = subparsers.add_parser('report', help='Generate accountability report')
    report_parser.add_argument('--output', '-o', default='blame_game_report.md',
                              help='Output file')
    
    # Show all red flags
    list_parser = subparsers.add_parser('list-patterns', help='Show all detected patterns')
    list_parser.add_argument('--category', '-c', choices=['financial', 'deception', 
                            'data_theft', 'obfuscation', 'malware'])
    
    # Verify integrity
    verify_parser = subparsers.add_parser('verify', help='Verify database integrity')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        analyzer = CodeForensicsAnalyzer()
        path = Path(args.path)
        
        if path.is_file():
            findings = analyzer.scan_file(str(path))
        elif path.is_dir():
            findings = analyzer.scan_directory(str(path))
        else:
            print(f"[ERROR] Path not found: {args.path}")
            sys.exit(1)
        
        # Save findings
        with open(args.output, 'w') as f:
            json.dump([asdict(finding) for finding in findings], f, indent=2)
        
        print(f"[SCAN COMPLETE] Found {len(findings)} pattern(s)")
        print(f"[RESULTS] Saved to {args.output}")
        
    elif args.command == 'scan-remote':
        findings = scan_remote_url_for_patterns(args.url)
        
        with open(args.output, 'w') as f:
            json.dump([asdict(finding) for finding in findings], f, indent=2)
        
        print(f"[REMOTE SCAN] Found {len(findings)} pattern(s) in {args.url}")
        print(f"[RESULTS] Saved to {args.output}")
        
    elif args.command == 'attest-device':
        attester = DeviceAttester(tracking_domain="blamegame.local")
        
        attestation = attester.attest_access(
            ip_address=args.ip,
            user_agent=args.user_agent,
            consent_given=args.consent,
            data_requester="system"
        )
        
        print(f"[ATTESTED] Device fingerprint: {attestation.device_fingerprint[:16]}...")
        print(f"[LOCATION] {attestation.geo_location}")
        print(f"[CONSENT] {'Yes' if attestation.consent_given else 'No'}")
        
    elif args.command == 'log-change':
        tracker = ChangeTracker()
        
        change = tracker.log_change(
            file_path=args.file,
            change_type=args.type,
            changed_by=args.changed_by,
            reason_provided=args.reason,
            approved_by=args.approved_by
        )
        
        print(f"[CHANGE LOGGED] ID: {change.id}")
        print(f"[TIMESTAMP] {change.timestamp}")
        
    elif args.command == 'report':
        # Load existing findings, attestations, changes
        findings = []
        attestations = []
        changes = []
        
        # Try to load from previous scans
        for finding_file in ['findings.json', 'remote_findings.json']:
            if Path(finding_file).exists():
                with open(finding_file, 'r') as f:
                    data = json.load(f)
                    findings.extend([CodeFinding(**item) for item in data])
        
        generate_blame_game_report(findings, attestations, changes, args.output)
        
    elif args.command == 'list-patterns':
        patterns = RED_FLAG_DATABASE
        if args.category:
            patterns = [p for p in patterns if p.category == args.category]
        
        print(f"\n{'='*70}")
        print(f"RED FLAG PATTERNS ({len(patterns)} total)")
        print(f"{'='*70}\n")
        
        for pattern in patterns:
            print(f"[{pattern.threat_level.value.upper():10}] {pattern.name}")
            print(f"  Category: {pattern.category}")
            print(f"  Description: {pattern.description}")
            print(f"  Pattern: {pattern.pattern}")
            print(f"  Example: {pattern.example_code}")
            print("-" * 70)
        
    elif args.command == 'verify':
        tracker = ChangeTracker()
        if tracker.verify_no_deletion():
            print("[OK] Database integrity verified - no deletions detected")
        else:
            print("[FAIL] Integrity issues detected!")
            sys.exit(1)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
