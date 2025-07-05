#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 增强安全审计

实现全面的安全事件记录、分析和审计功能
"""

import asyncio
import json
import logging
import hashlib
import hmac
import time
import geoip2.database
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import sqlite3
import aiosqlite
import ipaddress
import re
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecurityEventType(Enum):
    """安全事件类型"""
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    COMMAND_INJECTION = "command_injection"
    FILE_INCLUSION = "file_inclusion"
    CSRF_ATTEMPT = "csrf_attempt"
    DOS_ATTACK = "dos_attack"
    DDOS_ATTACK = "ddos_attack"
    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_COMPROMISE = "system_compromise"
    POLICY_VIOLATION = "policy_violation"


class SecurityLevel(Enum):
    """安全级别"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStandard(Enum):
    """合规标准"""
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOX = "sox"
    ISO27001 = "iso27001"
    NIST = "nist"


@dataclass
class SecurityEvent:
    """安全事件"""
    id: str
    event_type: SecurityEventType
    security_level: SecurityLevel
    timestamp: datetime
    source_ip: str
    target_ip: Optional[str]
    user_agent: Optional[str]
    request_method: Optional[str]
    request_path: Optional[str]
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: Optional[int]
    response_size: Optional[int]
    session_id: Optional[str]
    user_id: Optional[str]
    username: Optional[str]
    description: str
    details: Dict[str, Any]
    geo_location: Optional[Dict[str, str]]
    threat_indicators: List[str]
    mitigation_actions: List[str]
    compliance_tags: List[ComplianceStandard]
    node_id: str
    checksum: Optional[str] = None
    
    def __post_init__(self):
        """计算事件校验和"""
        if not self.checksum:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """计算事件校验和"""
        # 创建事件的唯一标识字符串
        event_data = {
            'id': self.id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'description': self.description
        }
        
        event_str = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """验证事件完整性"""
        expected_checksum = self._calculate_checksum()
        return self.checksum == expected_checksum


class ThreatIntelligence:
    """威胁情报"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_hashes: Set[str] = set()
        self.threat_feeds: List[str] = config.get('threat_feeds', [])
        self.update_interval = config.get('update_interval', 3600)  # 1小时
        self.last_update = datetime.min
        
        # 威胁模式
        self.attack_patterns = {
            'sql_injection': [
                r"('|(\-\-)|(;)|(\||\|)|(\*|\*))",
                r"(union|select|insert|delete|update|drop|create|alter|exec|execute)",
                r"(script|javascript|vbscript|onload|onerror|onclick)"
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>"
            ],
            'directory_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c"
            ],
            'command_injection': [
                r"(;|\||&|`|\$\(|\${)",
                r"(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)",
                r"(rm|mv|cp|chmod|chown|kill|killall)"
            ]
        }
        
        # 编译正则表达式
        self.compiled_patterns = {}
        for attack_type, patterns in self.attack_patterns.items():
            self.compiled_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
    
    async def update_threat_feeds(self) -> None:
        """更新威胁情报源"""
        if (datetime.now() - self.last_update).total_seconds() < self.update_interval:
            return
        
        try:
            # 这里可以实现从各种威胁情报源获取数据
            # 如 VirusTotal, AlienVault OTX, 等
            
            # 示例：从本地文件加载威胁情报
            await self._load_local_threat_data()
            
            self.last_update = datetime.now()
            logging.info("威胁情报更新完成")
            
        except Exception as e:
            logging.error(f"更新威胁情报时发生错误: {e}")
    
    async def _load_local_threat_data(self) -> None:
        """从本地文件加载威胁数据"""
        threat_data_path = self.config.get('threat_data_path', 'data/threat_intelligence')
        
        # 加载恶意IP列表
        malicious_ips_file = Path(threat_data_path) / 'malicious_ips.txt'
        if malicious_ips_file.exists():
            with open(malicious_ips_file, 'r') as f:
                self.malicious_ips.update(line.strip() for line in f if line.strip())
        
        # 加载恶意域名列表
        malicious_domains_file = Path(threat_data_path) / 'malicious_domains.txt'
        if malicious_domains_file.exists():
            with open(malicious_domains_file, 'r') as f:
                self.malicious_domains.update(line.strip() for line in f if line.strip())
    
    def is_malicious_ip(self, ip: str) -> bool:
        """检查IP是否为恶意IP"""
        return ip in self.malicious_ips
    
    def is_malicious_domain(self, domain: str) -> bool:
        """检查域名是否为恶意域名"""
        return domain in self.malicious_domains
    
    def detect_attack_patterns(self, text: str) -> List[str]:
        """检测攻击模式
        
        Args:
            text: 要检测的文本
            
        Returns:
            检测到的攻击类型列表
        """
        detected_attacks = []
        
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text):
                    detected_attacks.append(attack_type)
                    break
        
        return detected_attacks
    
    def calculate_threat_score(self, event: SecurityEvent) -> float:
        """计算威胁分数
        
        Args:
            event: 安全事件
            
        Returns:
            威胁分数 (0-100)
        """
        score = 0.0
        
        # 基于事件类型的基础分数
        base_scores = {
            SecurityEventType.SQL_INJECTION: 80,
            SecurityEventType.COMMAND_INJECTION: 90,
            SecurityEventType.XSS_ATTEMPT: 60,
            SecurityEventType.DIRECTORY_TRAVERSAL: 70,
            SecurityEventType.BRUTE_FORCE_ATTACK: 50,
            SecurityEventType.DOS_ATTACK: 60,
            SecurityEventType.DDOS_ATTACK: 80,
            SecurityEventType.MALWARE_DETECTED: 95,
            SecurityEventType.SYSTEM_COMPROMISE: 100,
            SecurityEventType.DATA_EXFILTRATION: 95,
            SecurityEventType.PRIVILEGE_ESCALATION: 85
        }
        
        score += base_scores.get(event.event_type, 30)
        
        # 恶意IP加分
        if self.is_malicious_ip(event.source_ip):
            score += 20
        
        # 威胁指标加分
        score += len(event.threat_indicators) * 5
        
        # 安全级别加分
        level_scores = {
            SecurityLevel.INFO: 0,
            SecurityLevel.LOW: 10,
            SecurityLevel.MEDIUM: 20,
            SecurityLevel.HIGH: 30,
            SecurityLevel.CRITICAL: 40
        }
        score += level_scores.get(event.security_level, 0)
        
        return min(score, 100.0)


class SecurityAuditLogger:
    """安全审计日志记录器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = config.get('audit_db_path', 'data/security_audit.db')
        self.encryption_key = self._get_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.logger = logging.getLogger(__name__)
        
        # 确保数据库目录存在
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # 初始化数据库
        asyncio.create_task(self._init_database())
    
    def _get_encryption_key(self) -> bytes:
        """获取加密密钥"""
        password = self.config.get('encryption_password', 'default_password').encode()
        salt = self.config.get('encryption_salt', 'default_salt').encode()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    async def _init_database(self) -> None:
        """初始化数据库"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        security_level TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        target_ip TEXT,
                        user_agent TEXT,
                        request_method TEXT,
                        request_path TEXT,
                        request_headers TEXT,
                        request_body TEXT,
                        response_status INTEGER,
                        response_size INTEGER,
                        session_id TEXT,
                        user_id TEXT,
                        username TEXT,
                        description TEXT NOT NULL,
                        details TEXT,
                        geo_location TEXT,
                        threat_indicators TEXT,
                        mitigation_actions TEXT,
                        compliance_tags TEXT,
                        node_id TEXT NOT NULL,
                        checksum TEXT NOT NULL,
                        encrypted_data TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp 
                    ON security_events(timestamp)
                """)
                
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_source_ip 
                    ON security_events(source_ip)
                """)
                
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_event_type 
                    ON security_events(event_type)
                """)
                
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_security_level 
                    ON security_events(security_level)
                """)
                
                await db.commit()
                
            self.logger.info("安全审计数据库初始化完成")
            
        except Exception as e:
            self.logger.error(f"初始化安全审计数据库时发生错误: {e}")
    
    def _encrypt_sensitive_data(self, data: str) -> str:
        """加密敏感数据"""
        if not data:
            return ""
        
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            self.logger.error(f"加密数据时发生错误: {e}")
            return ""
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """解密敏感数据"""
        if not encrypted_data:
            return ""
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"解密数据时发生错误: {e}")
            return ""
    
    async def log_security_event(self, event: SecurityEvent) -> bool:
        """记录安全事件
        
        Args:
            event: 安全事件
            
        Returns:
            是否成功记录
        """
        try:
            # 加密敏感数据
            encrypted_request_body = self._encrypt_sensitive_data(event.request_body or "")
            encrypted_details = self._encrypt_sensitive_data(json.dumps(event.details))
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO security_events (
                        id, event_type, security_level, timestamp, source_ip, target_ip,
                        user_agent, request_method, request_path, request_headers,
                        request_body, response_status, response_size, session_id,
                        user_id, username, description, details, geo_location,
                        threat_indicators, mitigation_actions, compliance_tags,
                        node_id, checksum, encrypted_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.id,
                    event.event_type.value,
                    event.security_level.value,
                    event.timestamp.isoformat(),
                    event.source_ip,
                    event.target_ip,
                    event.user_agent,
                    event.request_method,
                    event.request_path,
                    json.dumps(event.request_headers),
                    event.request_body,
                    event.response_status,
                    event.response_size,
                    event.session_id,
                    event.user_id,
                    event.username,
                    event.description,
                    json.dumps(event.details),
                    json.dumps(event.geo_location) if event.geo_location else None,
                    json.dumps(event.threat_indicators),
                    json.dumps(event.mitigation_actions),
                    json.dumps([tag.value for tag in event.compliance_tags]),
                    event.node_id,
                    event.checksum,
                    encrypted_details
                ))
                
                await db.commit()
            
            self.logger.debug(f"安全事件已记录: {event.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"记录安全事件时发生错误: {e}")
            return False
    
    async def query_security_events(self, 
                                   start_time: Optional[datetime] = None,
                                   end_time: Optional[datetime] = None,
                                   event_types: Optional[List[SecurityEventType]] = None,
                                   security_levels: Optional[List[SecurityLevel]] = None,
                                   source_ips: Optional[List[str]] = None,
                                   limit: int = 1000) -> List[SecurityEvent]:
        """查询安全事件
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            event_types: 事件类型过滤
            security_levels: 安全级别过滤
            source_ips: 源IP过滤
            limit: 结果限制
            
        Returns:
            安全事件列表
        """
        try:
            query = "SELECT * FROM security_events WHERE 1=1"
            params = []
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time.isoformat())
            
            if event_types:
                placeholders = ','.join('?' * len(event_types))
                query += f" AND event_type IN ({placeholders})"
                params.extend([et.value for et in event_types])
            
            if security_levels:
                placeholders = ','.join('?' * len(security_levels))
                query += f" AND security_level IN ({placeholders})"
                params.extend([sl.value for sl in security_levels])
            
            if source_ips:
                placeholders = ','.join('?' * len(source_ips))
                query += f" AND source_ip IN ({placeholders})"
                params.extend(source_ips)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
            
            events = []
            for row in rows:
                # 重构安全事件对象
                event = SecurityEvent(
                    id=row[0],
                    event_type=SecurityEventType(row[1]),
                    security_level=SecurityLevel(row[2]),
                    timestamp=datetime.fromisoformat(row[3]),
                    source_ip=row[4],
                    target_ip=row[5],
                    user_agent=row[6],
                    request_method=row[7],
                    request_path=row[8],
                    request_headers=json.loads(row[9]) if row[9] else {},
                    request_body=row[10],
                    response_status=row[11],
                    response_size=row[12],
                    session_id=row[13],
                    user_id=row[14],
                    username=row[15],
                    description=row[16],
                    details=json.loads(row[17]) if row[17] else {},
                    geo_location=json.loads(row[18]) if row[18] else None,
                    threat_indicators=json.loads(row[19]) if row[19] else [],
                    mitigation_actions=json.loads(row[20]) if row[20] else [],
                    compliance_tags=[ComplianceStandard(tag) for tag in json.loads(row[21])] if row[21] else [],
                    node_id=row[22],
                    checksum=row[23]
                )
                events.append(event)
            
            return events
            
        except Exception as e:
            self.logger.error(f"查询安全事件时发生错误: {e}")
            return []
    
    async def get_security_statistics(self, 
                                     time_window: int = 3600) -> Dict[str, Any]:
        """获取安全统计信息
        
        Args:
            time_window: 时间窗口（秒）
            
        Returns:
            统计信息
        """
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=time_window)
            
            async with aiosqlite.connect(self.db_path) as db:
                # 总事件数
                async with db.execute(
                    "SELECT COUNT(*) FROM security_events WHERE timestamp >= ?",
                    (start_time.isoformat(),)
                ) as cursor:
                    total_events = (await cursor.fetchone())[0]
                
                # 按事件类型统计
                async with db.execute("""
                    SELECT event_type, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp >= ? 
                    GROUP BY event_type
                """, (start_time.isoformat(),)) as cursor:
                    events_by_type = dict(await cursor.fetchall())
                
                # 按安全级别统计
                async with db.execute("""
                    SELECT security_level, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp >= ? 
                    GROUP BY security_level
                """, (start_time.isoformat(),)) as cursor:
                    events_by_level = dict(await cursor.fetchall())
                
                # 按源IP统计（Top 10）
                async with db.execute("""
                    SELECT source_ip, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp >= ? 
                    GROUP BY source_ip 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                """, (start_time.isoformat(),)) as cursor:
                    top_source_ips = dict(await cursor.fetchall())
                
                # 按节点统计
                async with db.execute("""
                    SELECT node_id, COUNT(*) 
                    FROM security_events 
                    WHERE timestamp >= ? 
                    GROUP BY node_id
                """, (start_time.isoformat(),)) as cursor:
                    events_by_node = dict(await cursor.fetchall())
            
            return {
                'total_events': total_events,
                'events_by_type': events_by_type,
                'events_by_level': events_by_level,
                'top_source_ips': top_source_ips,
                'events_by_node': events_by_node,
                'time_window': time_window,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"获取安全统计信息时发生错误: {e}")
            return {}


class ComplianceReporter:
    """合规报告生成器"""
    
    def __init__(self, audit_logger: SecurityAuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
    
    async def generate_compliance_report(self, 
                                        standard: ComplianceStandard,
                                        start_time: datetime,
                                        end_time: datetime) -> Dict[str, Any]:
        """生成合规报告
        
        Args:
            standard: 合规标准
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            合规报告
        """
        try:
            # 查询相关安全事件
            events = await self.audit_logger.query_security_events(
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            # 过滤符合合规标准的事件
            compliance_events = [
                event for event in events 
                if standard in event.compliance_tags
            ]
            
            # 生成报告
            if standard == ComplianceStandard.PCI_DSS:
                return await self._generate_pci_dss_report(compliance_events, start_time, end_time)
            elif standard == ComplianceStandard.GDPR:
                return await self._generate_gdpr_report(compliance_events, start_time, end_time)
            elif standard == ComplianceStandard.HIPAA:
                return await self._generate_hipaa_report(compliance_events, start_time, end_time)
            else:
                return await self._generate_generic_report(compliance_events, start_time, end_time, standard)
                
        except Exception as e:
            self.logger.error(f"生成合规报告时发生错误: {e}")
            return {}
    
    async def _generate_pci_dss_report(self, events: List[SecurityEvent], 
                                      start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """生成PCI DSS合规报告"""
        # PCI DSS要求的关键指标
        failed_logins = [e for e in events if e.event_type == SecurityEventType.LOGIN_FAILURE]
        successful_logins = [e for e in events if e.event_type == SecurityEventType.LOGIN_SUCCESS]
        unauthorized_access = [e for e in events if e.event_type == SecurityEventType.UNAUTHORIZED_ACCESS]
        
        return {
            'standard': 'PCI DSS',
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'summary': {
                'total_events': len(events),
                'failed_login_attempts': len(failed_logins),
                'successful_logins': len(successful_logins),
                'unauthorized_access_attempts': len(unauthorized_access)
            },
            'requirements': {
                'req_8_1': {  # 用户身份验证
                    'description': '用户身份验证控制',
                    'events': len(failed_logins) + len(successful_logins),
                    'compliance_status': 'compliant' if len(failed_logins) < 100 else 'non_compliant'
                },
                'req_10_2': {  # 审计日志
                    'description': '审计日志记录',
                    'events': len(events),
                    'compliance_status': 'compliant'
                }
            },
            'events': [asdict(event) for event in events[:100]]  # 限制返回的事件数量
        }
    
    async def _generate_gdpr_report(self, events: List[SecurityEvent], 
                                   start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """生成GDPR合规报告"""
        data_breaches = [e for e in events if e.event_type == SecurityEventType.DATA_EXFILTRATION]
        unauthorized_access = [e for e in events if e.event_type == SecurityEventType.UNAUTHORIZED_ACCESS]
        
        return {
            'standard': 'GDPR',
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'summary': {
                'total_events': len(events),
                'data_breach_incidents': len(data_breaches),
                'unauthorized_access_attempts': len(unauthorized_access)
            },
            'breach_notification': {
                'required_within_72h': len(data_breaches) > 0,
                'incidents': [asdict(event) for event in data_breaches]
            },
            'events': [asdict(event) for event in events[:100]]
        }
    
    async def _generate_hipaa_report(self, events: List[SecurityEvent], 
                                    start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """生成HIPAA合规报告"""
        return {
            'standard': 'HIPAA',
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'summary': {
                'total_events': len(events),
                'phi_access_events': len([e for e in events if 'phi' in e.description.lower()])
            },
            'events': [asdict(event) for event in events[:100]]
        }
    
    async def _generate_generic_report(self, events: List[SecurityEvent], 
                                      start_time: datetime, end_time: datetime,
                                      standard: ComplianceStandard) -> Dict[str, Any]:
        """生成通用合规报告"""
        return {
            'standard': standard.value,
            'period': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat()
            },
            'summary': {
                'total_events': len(events)
            },
            'events': [asdict(event) for event in events[:100]]
        }


class SecurityAuditingSystem:
    """安全审计系统主类"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threat_intelligence = ThreatIntelligence(config.get('threat_intelligence', {}))
        self.audit_logger = SecurityAuditLogger(config.get('audit_logging', {}))
        self.compliance_reporter = ComplianceReporter(self.audit_logger)
        self.logger = logging.getLogger(__name__)
        
        # 地理位置数据库
        geoip_db_path = config.get('geoip_db_path', 'data/GeoLite2-City.mmdb')
        self.geoip_reader = None
        if Path(geoip_db_path).exists():
            try:
                self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                self.logger.warning(f"无法加载GeoIP数据库: {e}")
        
        # 事件缓存
        self.event_cache = deque(maxlen=1000)
        
        # 统计信息
        self.stats = {
            'total_events_processed': 0,
            'events_by_type': defaultdict(int),
            'events_by_level': defaultdict(int),
            'threat_scores': deque(maxlen=1000)
        }
    
    async def process_security_event(self, event_data: Dict[str, Any]) -> Optional[SecurityEvent]:
        """处理安全事件
        
        Args:
            event_data: 事件数据
            
        Returns:
            处理后的安全事件
        """
        try:
            # 更新威胁情报
            await self.threat_intelligence.update_threat_feeds()
            
            # 创建安全事件
            event = await self._create_security_event(event_data)
            
            # 增强事件信息
            await self._enrich_event(event)
            
            # 记录事件
            await self.audit_logger.log_security_event(event)
            
            # 更新统计
            self._update_statistics(event)
            
            # 缓存事件
            self.event_cache.append(event)
            
            self.logger.info(f"安全事件已处理: {event.id} ({event.event_type.value})")
            
            return event
            
        except Exception as e:
            self.logger.error(f"处理安全事件时发生错误: {e}")
            return None
    
    async def _create_security_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        """创建安全事件"""
        event_id = event_data.get('id', str(int(time.time() * 1000000)))
        
        # 检测攻击模式
        request_text = f"{event_data.get('request_path', '')} {event_data.get('request_body', '')}"
        detected_attacks = self.threat_intelligence.detect_attack_patterns(request_text)
        
        # 确定事件类型
        event_type = self._determine_event_type(event_data, detected_attacks)
        
        # 确定安全级别
        security_level = self._determine_security_level(event_data, detected_attacks)
        
        # 确定合规标签
        compliance_tags = self._determine_compliance_tags(event_type)
        
        event = SecurityEvent(
            id=event_id,
            event_type=event_type,
            security_level=security_level,
            timestamp=datetime.now(),
            source_ip=event_data.get('source_ip', ''),
            target_ip=event_data.get('target_ip'),
            user_agent=event_data.get('user_agent'),
            request_method=event_data.get('request_method'),
            request_path=event_data.get('request_path'),
            request_headers=event_data.get('request_headers', {}),
            request_body=event_data.get('request_body'),
            response_status=event_data.get('response_status'),
            response_size=event_data.get('response_size'),
            session_id=event_data.get('session_id'),
            user_id=event_data.get('user_id'),
            username=event_data.get('username'),
            description=event_data.get('description', f'{event_type.value} detected'),
            details=event_data.get('details', {}),
            geo_location=None,  # 将在enrich阶段填充
            threat_indicators=detected_attacks,
            mitigation_actions=event_data.get('mitigation_actions', []),
            compliance_tags=compliance_tags,
            node_id=event_data.get('node_id', 'unknown')
        )
        
        return event
    
    async def _enrich_event(self, event: SecurityEvent) -> None:
        """增强事件信息"""
        # 添加地理位置信息
        if self.geoip_reader and event.source_ip:
            try:
                response = self.geoip_reader.city(event.source_ip)
                event.geo_location = {
                    'country': response.country.name,
                    'country_code': response.country.iso_code,
                    'city': response.city.name,
                    'latitude': float(response.location.latitude) if response.location.latitude else None,
                    'longitude': float(response.location.longitude) if response.location.longitude else None
                }
            except Exception:
                pass  # 忽略地理位置查询错误
        
        # 计算威胁分数
        threat_score = self.threat_intelligence.calculate_threat_score(event)
        event.details['threat_score'] = threat_score
        
        # 检查是否为已知恶意IP
        if self.threat_intelligence.is_malicious_ip(event.source_ip):
            event.threat_indicators.append('known_malicious_ip')
            event.security_level = SecurityLevel.HIGH
    
    def _determine_event_type(self, event_data: Dict[str, Any], 
                             detected_attacks: List[str]) -> SecurityEventType:
        """确定事件类型"""
        # 基于检测到的攻击模式
        if 'sql_injection' in detected_attacks:
            return SecurityEventType.SQL_INJECTION
        elif 'xss' in detected_attacks:
            return SecurityEventType.XSS_ATTEMPT
        elif 'directory_traversal' in detected_attacks:
            return SecurityEventType.DIRECTORY_TRAVERSAL
        elif 'command_injection' in detected_attacks:
            return SecurityEventType.COMMAND_INJECTION
        
        # 基于事件数据
        if event_data.get('event_type'):
            try:
                return SecurityEventType(event_data['event_type'])
            except ValueError:
                pass
        
        # 基于HTTP状态码
        status_code = event_data.get('response_status')
        if status_code == 401:
            return SecurityEventType.LOGIN_FAILURE
        elif status_code == 403:
            return SecurityEventType.UNAUTHORIZED_ACCESS
        
        # 默认为可疑活动
        return SecurityEventType.SUSPICIOUS_ACTIVITY
    
    def _determine_security_level(self, event_data: Dict[str, Any], 
                                 detected_attacks: List[str]) -> SecurityLevel:
        """确定安全级别"""
        # 高危攻击
        high_risk_attacks = ['sql_injection', 'command_injection']
        if any(attack in detected_attacks for attack in high_risk_attacks):
            return SecurityLevel.HIGH
        
        # 中等风险攻击
        medium_risk_attacks = ['xss', 'directory_traversal']
        if any(attack in detected_attacks for attack in medium_risk_attacks):
            return SecurityLevel.MEDIUM
        
        # 基于状态码
        status_code = event_data.get('response_status')
        if status_code and status_code >= 500:
            return SecurityLevel.MEDIUM
        elif status_code and status_code >= 400:
            return SecurityLevel.LOW
        
        return SecurityLevel.INFO
    
    def _determine_compliance_tags(self, event_type: SecurityEventType) -> List[ComplianceStandard]:
        """确定合规标签"""
        tags = []
        
        # 所有安全事件都与ISO27001相关
        tags.append(ComplianceStandard.ISO27001)
        
        # 登录相关事件与PCI DSS相关
        if event_type in [SecurityEventType.LOGIN_ATTEMPT, SecurityEventType.LOGIN_SUCCESS, 
                         SecurityEventType.LOGIN_FAILURE, SecurityEventType.BRUTE_FORCE_ATTACK]:
            tags.append(ComplianceStandard.PCI_DSS)
        
        # 数据相关事件与GDPR相关
        if event_type in [SecurityEventType.DATA_EXFILTRATION, SecurityEventType.UNAUTHORIZED_ACCESS]:
            tags.append(ComplianceStandard.GDPR)
        
        return tags
    
    def _update_statistics(self, event: SecurityEvent) -> None:
        """更新统计信息"""
        self.stats['total_events_processed'] += 1
        self.stats['events_by_type'][event.event_type.value] += 1
        self.stats['events_by_level'][event.security_level.value] += 1
        
        threat_score = event.details.get('threat_score', 0)
        self.stats['threat_scores'].append(threat_score)
    
    async def get_security_dashboard(self) -> Dict[str, Any]:
        """获取安全仪表板数据"""
        # 获取统计信息
        audit_stats = await self.audit_logger.get_security_statistics()
        
        # 计算威胁分数统计
        threat_scores = list(self.stats['threat_scores'])
        threat_stats = {}
        if threat_scores:
            threat_stats = {
                'avg_threat_score': sum(threat_scores) / len(threat_scores),
                'max_threat_score': max(threat_scores),
                'high_threat_events': len([s for s in threat_scores if s >= 70])
            }
        
        return {
            'audit_statistics': audit_stats,
            'processing_statistics': dict(self.stats),
            'threat_statistics': threat_stats,
            'recent_events': [asdict(event) for event in list(self.event_cache)[-10:]],
            'threat_intelligence_status': {
                'malicious_ips_count': len(self.threat_intelligence.malicious_ips),
                'malicious_domains_count': len(self.threat_intelligence.malicious_domains),
                'last_update': self.threat_intelligence.last_update.isoformat()
            }
        }
    
    async def generate_compliance_report(self, standard: ComplianceStandard,
                                        start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """生成合规报告"""
        return await self.compliance_reporter.generate_compliance_report(
            standard, start_time, end_time
        )
    
    async def search_security_events(self, query: Dict[str, Any]) -> List[SecurityEvent]:
        """搜索安全事件"""
        return await self.audit_logger.query_security_events(
            start_time=query.get('start_time'),
            end_time=query.get('end_time'),
            event_types=query.get('event_types'),
            security_levels=query.get('security_levels'),
            source_ips=query.get('source_ips'),
            limit=query.get('limit', 1000)
        )