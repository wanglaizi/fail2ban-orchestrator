#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 多租户支持

实现租户隔离、权限管理、资源配额和数据隔离等功能
"""

import asyncio
import json
import logging
import hashlib
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Union, Callable
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum
import uuid

import yaml
from cryptography.fernet import Fernet
from passlib.context import CryptContext

# 数据库支持
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import motor.motor_asyncio
    MONGODB_AVAILABLE = True
except ImportError:
    MONGODB_AVAILABLE = False

try:
    import aiosqlite
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False


class TenantStatus(Enum):
    """租户状态"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    INACTIVE = "inactive"
    DELETED = "deleted"


class UserRole(Enum):
    """用户角色"""
    SUPER_ADMIN = "super_admin"  # 超级管理员
    TENANT_ADMIN = "tenant_admin"  # 租户管理员
    SECURITY_ADMIN = "security_admin"  # 安全管理员
    OPERATOR = "operator"  # 操作员
    VIEWER = "viewer"  # 只读用户


class Permission(Enum):
    """权限类型"""
    # 系统管理
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_CONFIG = "system:config"
    SYSTEM_MONITOR = "system:monitor"
    
    # 租户管理
    TENANT_CREATE = "tenant:create"
    TENANT_UPDATE = "tenant:update"
    TENANT_DELETE = "tenant:delete"
    TENANT_VIEW = "tenant:view"
    
    # 用户管理
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_VIEW = "user:view"
    
    # IP管理
    IP_BAN = "ip:ban"
    IP_UNBAN = "ip:unban"
    IP_VIEW = "ip:view"
    IP_WHITELIST = "ip:whitelist"
    
    # 规则管理
    RULE_CREATE = "rule:create"
    RULE_UPDATE = "rule:update"
    RULE_DELETE = "rule:delete"
    RULE_VIEW = "rule:view"
    
    # 日志查看
    LOG_VIEW = "log:view"
    LOG_EXPORT = "log:export"
    
    # 报告查看
    REPORT_VIEW = "report:view"
    REPORT_EXPORT = "report:export"


@dataclass
class ResourceQuota:
    """资源配额"""
    max_banned_ips: int = 1000  # 最大封禁IP数量
    max_rules: int = 100  # 最大规则数量
    max_users: int = 10  # 最大用户数量
    max_api_requests_per_hour: int = 10000  # 每小时最大API请求数
    max_log_retention_days: int = 30  # 日志保留天数
    max_storage_mb: int = 1000  # 最大存储空间(MB)
    max_concurrent_sessions: int = 10  # 最大并发会话数
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResourceQuota':
        return cls(**data)


@dataclass
class Tenant:
    """租户信息"""
    id: str
    name: str
    description: str
    status: TenantStatus
    created_at: datetime
    updated_at: datetime
    quota: ResourceQuota
    settings: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['status'] = self.status.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Tenant':
        data['status'] = TenantStatus(data['status'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        data['quota'] = ResourceQuota.from_dict(data['quota'])
        return cls(**data)


@dataclass
class User:
    """用户信息"""
    id: str
    tenant_id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    permissions: Set[Permission]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['role'] = self.role.value
        data['permissions'] = [p.value for p in self.permissions]
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        if self.last_login:
            data['last_login'] = self.last_login.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        data['role'] = UserRole(data['role'])
        data['permissions'] = {Permission(p) for p in data['permissions']}
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        if data.get('last_login'):
            data['last_login'] = datetime.fromisoformat(data['last_login'])
        return cls(**data)


@dataclass
class Session:
    """用户会话"""
    id: str
    user_id: str
    tenant_id: str
    token: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_active: bool = True
    
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'user_id': self.user_id,
            'tenant_id': self.tenant_id,
            'token': self.token,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'is_active': self.is_active
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        data['last_activity'] = datetime.fromisoformat(data['last_activity'])
        return cls(**data)


class TenantStorage(ABC):
    """租户存储接口"""
    
    @abstractmethod
    async def create_tenant(self, tenant: Tenant) -> bool:
        """创建租户"""
        pass
    
    @abstractmethod
    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """获取租户"""
        pass
    
    @abstractmethod
    async def update_tenant(self, tenant: Tenant) -> bool:
        """更新租户"""
        pass
    
    @abstractmethod
    async def delete_tenant(self, tenant_id: str) -> bool:
        """删除租户"""
        pass
    
    @abstractmethod
    async def list_tenants(self, status: Optional[TenantStatus] = None) -> List[Tenant]:
        """列出租户"""
        pass
    
    @abstractmethod
    async def create_user(self, user: User) -> bool:
        """创建用户"""
        pass
    
    @abstractmethod
    async def get_user(self, user_id: str) -> Optional[User]:
        """获取用户"""
        pass
    
    @abstractmethod
    async def get_user_by_username(self, tenant_id: str, username: str) -> Optional[User]:
        """根据用户名获取用户"""
        pass
    
    @abstractmethod
    async def update_user(self, user: User) -> bool:
        """更新用户"""
        pass
    
    @abstractmethod
    async def delete_user(self, user_id: str) -> bool:
        """删除用户"""
        pass
    
    @abstractmethod
    async def list_users(self, tenant_id: str) -> List[User]:
        """列出租户用户"""
        pass
    
    @abstractmethod
    async def create_session(self, session: Session) -> bool:
        """创建会话"""
        pass
    
    @abstractmethod
    async def get_session(self, token: str) -> Optional[Session]:
        """获取会话"""
        pass
    
    @abstractmethod
    async def update_session(self, session: Session) -> bool:
        """更新会话"""
        pass
    
    @abstractmethod
    async def delete_session(self, token: str) -> bool:
        """删除会话"""
        pass
    
    @abstractmethod
    async def cleanup_expired_sessions(self) -> int:
        """清理过期会话"""
        pass


class SQLiteTenantStorage(TenantStorage):
    """SQLite租户存储"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self) -> None:
        """初始化数据库"""
        async with aiosqlite.connect(self.db_path) as db:
            # 创建租户表
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    quota TEXT NOT NULL,
                    settings TEXT,
                    metadata TEXT
                )
            """)
            
            # 创建用户表
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    metadata TEXT,
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
                    UNIQUE (tenant_id, username)
                )
            """)
            
            # 创建会话表
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (tenant_id) REFERENCES tenants (id)
                )
            """)
            
            await db.commit()
    
    async def create_tenant(self, tenant: Tenant) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO tenants (id, name, description, status, created_at, updated_at, quota, settings, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tenant.id, tenant.name, tenant.description, tenant.status.value,
                    tenant.created_at.isoformat(), tenant.updated_at.isoformat(),
                    json.dumps(tenant.quota.to_dict()),
                    json.dumps(tenant.settings),
                    json.dumps(tenant.metadata)
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"创建租户失败: {e}")
            return False
    
    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT * FROM tenants WHERE id = ?", (tenant_id,)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_tenant(row)
                    return None
        except Exception as e:
            self.logger.error(f"获取租户失败: {e}")
            return None
    
    async def update_tenant(self, tenant: Tenant) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE tenants SET name = ?, description = ?, status = ?, updated_at = ?,
                           quota = ?, settings = ?, metadata = ?
                    WHERE id = ?
                """, (
                    tenant.name, tenant.description, tenant.status.value,
                    tenant.updated_at.isoformat(),
                    json.dumps(tenant.quota.to_dict()),
                    json.dumps(tenant.settings),
                    json.dumps(tenant.metadata),
                    tenant.id
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"更新租户失败: {e}")
            return False
    
    async def delete_tenant(self, tenant_id: str) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # 删除相关会话
                await db.execute("DELETE FROM sessions WHERE tenant_id = ?", (tenant_id,))
                # 删除相关用户
                await db.execute("DELETE FROM users WHERE tenant_id = ?", (tenant_id,))
                # 删除租户
                await db.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"删除租户失败: {e}")
            return False
    
    async def list_tenants(self, status: Optional[TenantStatus] = None) -> List[Tenant]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                if status:
                    query = "SELECT * FROM tenants WHERE status = ? ORDER BY created_at"
                    params = (status.value,)
                else:
                    query = "SELECT * FROM tenants ORDER BY created_at"
                    params = ()
                
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_tenant(row) for row in rows]
        except Exception as e:
            self.logger.error(f"列出租户失败: {e}")
            return []
    
    async def create_user(self, user: User) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO users (id, tenant_id, username, email, password_hash, role, permissions,
                                     is_active, created_at, updated_at, last_login, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.id, user.tenant_id, user.username, user.email, user.password_hash,
                    user.role.value, json.dumps([p.value for p in user.permissions]),
                    user.is_active, user.created_at.isoformat(), user.updated_at.isoformat(),
                    user.last_login.isoformat() if user.last_login else None,
                    json.dumps(user.metadata)
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"创建用户失败: {e}")
            return False
    
    async def get_user(self, user_id: str) -> Optional[User]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT * FROM users WHERE id = ?", (user_id,)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_user(row)
                    return None
        except Exception as e:
            self.logger.error(f"获取用户失败: {e}")
            return None
    
    async def get_user_by_username(self, tenant_id: str, username: str) -> Optional[User]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT * FROM users WHERE tenant_id = ? AND username = ?",
                    (tenant_id, username)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_user(row)
                    return None
        except Exception as e:
            self.logger.error(f"根据用户名获取用户失败: {e}")
            return None
    
    async def update_user(self, user: User) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE users SET email = ?, password_hash = ?, role = ?, permissions = ?,
                           is_active = ?, updated_at = ?, last_login = ?, metadata = ?
                    WHERE id = ?
                """, (
                    user.email, user.password_hash, user.role.value,
                    json.dumps([p.value for p in user.permissions]),
                    user.is_active, user.updated_at.isoformat(),
                    user.last_login.isoformat() if user.last_login else None,
                    json.dumps(user.metadata), user.id
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"更新用户失败: {e}")
            return False
    
    async def delete_user(self, user_id: str) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # 删除相关会话
                await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                # 删除用户
                await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"删除用户失败: {e}")
            return False
    
    async def list_users(self, tenant_id: str) -> List[User]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at",
                    (tenant_id,)
                ) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_user(row) for row in rows]
        except Exception as e:
            self.logger.error(f"列出用户失败: {e}")
            return []
    
    async def create_session(self, session: Session) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO sessions (id, user_id, tenant_id, token, created_at, expires_at,
                                        last_activity, ip_address, user_agent, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session.id, session.user_id, session.tenant_id, session.token,
                    session.created_at.isoformat(), session.expires_at.isoformat(),
                    session.last_activity.isoformat(), session.ip_address,
                    session.user_agent, session.is_active
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"创建会话失败: {e}")
            return False
    
    async def get_session(self, token: str) -> Optional[Session]:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT * FROM sessions WHERE token = ? AND is_active = 1",
                    (token,)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_session(row)
                    return None
        except Exception as e:
            self.logger.error(f"获取会话失败: {e}")
            return None
    
    async def update_session(self, session: Session) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE sessions SET last_activity = ?, is_active = ?
                    WHERE token = ?
                """, (
                    session.last_activity.isoformat(), session.is_active, session.token
                ))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"更新会话失败: {e}")
            return False
    
    async def delete_session(self, token: str) -> bool:
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
                await db.commit()
                return True
        except Exception as e:
            self.logger.error(f"删除会话失败: {e}")
            return False
    
    async def cleanup_expired_sessions(self) -> int:
        try:
            now = datetime.now().isoformat()
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "DELETE FROM sessions WHERE expires_at < ? OR is_active = 0",
                    (now,)
                )
                await db.commit()
                return cursor.rowcount
        except Exception as e:
            self.logger.error(f"清理过期会话失败: {e}")
            return 0
    
    def _row_to_tenant(self, row) -> Tenant:
        """将数据库行转换为租户对象"""
        return Tenant(
            id=row[0],
            name=row[1],
            description=row[2],
            status=TenantStatus(row[3]),
            created_at=datetime.fromisoformat(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
            quota=ResourceQuota.from_dict(json.loads(row[6])),
            settings=json.loads(row[7]) if row[7] else {},
            metadata=json.loads(row[8]) if row[8] else {}
        )
    
    def _row_to_user(self, row) -> User:
        """将数据库行转换为用户对象"""
        return User(
            id=row[0],
            tenant_id=row[1],
            username=row[2],
            email=row[3],
            password_hash=row[4],
            role=UserRole(row[5]),
            permissions={Permission(p) for p in json.loads(row[6])},
            is_active=bool(row[7]),
            created_at=datetime.fromisoformat(row[8]),
            updated_at=datetime.fromisoformat(row[9]),
            last_login=datetime.fromisoformat(row[10]) if row[10] else None,
            metadata=json.loads(row[11]) if row[11] else {}
        )
    
    def _row_to_session(self, row) -> Session:
        """将数据库行转换为会话对象"""
        return Session(
            id=row[0],
            user_id=row[1],
            tenant_id=row[2],
            token=row[3],
            created_at=datetime.fromisoformat(row[4]),
            expires_at=datetime.fromisoformat(row[5]),
            last_activity=datetime.fromisoformat(row[6]),
            ip_address=row[7],
            user_agent=row[8],
            is_active=bool(row[9])
        )


class AuthenticationManager:
    """认证管理器"""
    
    def __init__(self, storage: TenantStorage, secret_key: str):
        self.storage = storage
        self.secret_key = secret_key
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.logger = logging.getLogger(__name__)
        
        # 会话配置
        self.session_timeout = timedelta(hours=24)
        self.max_sessions_per_user = 5
    
    def hash_password(self, password: str) -> str:
        """哈希密码"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """验证密码"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def generate_token(self) -> str:
        """生成访问令牌"""
        return secrets.token_urlsafe(32)
    
    async def authenticate_user(self, tenant_id: str, username: str, password: str) -> Optional[User]:
        """认证用户"""
        try:
            user = await self.storage.get_user_by_username(tenant_id, username)
            if not user:
                self.logger.warning(f"用户不存在: {tenant_id}/{username}")
                return None
            
            if not user.is_active:
                self.logger.warning(f"用户已禁用: {tenant_id}/{username}")
                return None
            
            if not self.verify_password(password, user.password_hash):
                self.logger.warning(f"密码错误: {tenant_id}/{username}")
                return None
            
            # 更新最后登录时间
            user.last_login = datetime.now()
            await self.storage.update_user(user)
            
            return user
            
        except Exception as e:
            self.logger.error(f"用户认证失败: {e}")
            return None
    
    async def create_session(self, user: User, ip_address: str, user_agent: str) -> Optional[Session]:
        """创建用户会话"""
        try:
            # 检查并发会话限制
            # 这里可以添加检查逻辑
            
            session = Session(
                id=str(uuid.uuid4()),
                user_id=user.id,
                tenant_id=user.tenant_id,
                token=self.generate_token(),
                created_at=datetime.now(),
                expires_at=datetime.now() + self.session_timeout,
                last_activity=datetime.now(),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            success = await self.storage.create_session(session)
            if success:
                return session
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"创建会话失败: {e}")
            return None
    
    async def validate_session(self, token: str) -> Optional[Session]:
        """验证会话"""
        try:
            session = await self.storage.get_session(token)
            if not session:
                return None
            
            if session.is_expired():
                # 会话已过期，删除
                await self.storage.delete_session(token)
                return None
            
            # 更新最后活动时间
            session.last_activity = datetime.now()
            await self.storage.update_session(session)
            
            return session
            
        except Exception as e:
            self.logger.error(f"验证会话失败: {e}")
            return None
    
    async def logout(self, token: str) -> bool:
        """用户登出"""
        try:
            return await self.storage.delete_session(token)
        except Exception as e:
            self.logger.error(f"用户登出失败: {e}")
            return False
    
    async def cleanup_expired_sessions(self) -> int:
        """清理过期会话"""
        return await self.storage.cleanup_expired_sessions()


class AuthorizationManager:
    """授权管理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 角色权限映射
        self.role_permissions = {
            UserRole.SUPER_ADMIN: set(Permission),  # 所有权限
            UserRole.TENANT_ADMIN: {
                Permission.TENANT_VIEW, Permission.TENANT_UPDATE,
                Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE, Permission.USER_VIEW,
                Permission.IP_BAN, Permission.IP_UNBAN, Permission.IP_VIEW, Permission.IP_WHITELIST,
                Permission.RULE_CREATE, Permission.RULE_UPDATE, Permission.RULE_DELETE, Permission.RULE_VIEW,
                Permission.LOG_VIEW, Permission.LOG_EXPORT,
                Permission.REPORT_VIEW, Permission.REPORT_EXPORT
            },
            UserRole.SECURITY_ADMIN: {
                Permission.IP_BAN, Permission.IP_UNBAN, Permission.IP_VIEW, Permission.IP_WHITELIST,
                Permission.RULE_CREATE, Permission.RULE_UPDATE, Permission.RULE_DELETE, Permission.RULE_VIEW,
                Permission.LOG_VIEW, Permission.LOG_EXPORT,
                Permission.REPORT_VIEW, Permission.REPORT_EXPORT
            },
            UserRole.OPERATOR: {
                Permission.IP_BAN, Permission.IP_UNBAN, Permission.IP_VIEW,
                Permission.RULE_VIEW,
                Permission.LOG_VIEW,
                Permission.REPORT_VIEW
            },
            UserRole.VIEWER: {
                Permission.IP_VIEW,
                Permission.RULE_VIEW,
                Permission.LOG_VIEW,
                Permission.REPORT_VIEW
            }
        }
    
    def get_role_permissions(self, role: UserRole) -> Set[Permission]:
        """获取角色权限"""
        return self.role_permissions.get(role, set())
    
    def has_permission(self, user: User, permission: Permission) -> bool:
        """检查用户是否有指定权限"""
        if not user.is_active:
            return False
        
        # 检查用户直接权限
        if permission in user.permissions:
            return True
        
        # 检查角色权限
        role_permissions = self.get_role_permissions(user.role)
        return permission in role_permissions
    
    def has_any_permission(self, user: User, permissions: List[Permission]) -> bool:
        """检查用户是否有任一权限"""
        return any(self.has_permission(user, perm) for perm in permissions)
    
    def has_all_permissions(self, user: User, permissions: List[Permission]) -> bool:
        """检查用户是否有所有权限"""
        return all(self.has_permission(user, perm) for perm in permissions)
    
    def can_access_tenant(self, user: User, tenant_id: str) -> bool:
        """检查用户是否可以访问指定租户"""
        # 超级管理员可以访问所有租户
        if user.role == UserRole.SUPER_ADMIN:
            return True
        
        # 其他用户只能访问自己的租户
        return user.tenant_id == tenant_id
    
    def can_manage_user(self, manager: User, target_user: User) -> bool:
        """检查用户是否可以管理目标用户"""
        # 超级管理员可以管理所有用户
        if manager.role == UserRole.SUPER_ADMIN:
            return True
        
        # 租户管理员可以管理同租户的非超级管理员用户
        if (manager.role == UserRole.TENANT_ADMIN and 
            manager.tenant_id == target_user.tenant_id and
            target_user.role != UserRole.SUPER_ADMIN):
            return True
        
        return False


class ResourceQuotaManager:
    """资源配额管理器"""
    
    def __init__(self, storage: TenantStorage):
        self.storage = storage
        self.logger = logging.getLogger(__name__)
        
        # 资源使用统计缓存
        self.usage_cache = {}
        self.cache_ttl = timedelta(minutes=5)
        self.last_cache_update = {}
    
    async def get_tenant_usage(self, tenant_id: str) -> Dict[str, int]:
        """获取租户资源使用情况"""
        # 检查缓存
        now = datetime.now()
        if (tenant_id in self.usage_cache and 
            tenant_id in self.last_cache_update and
            now - self.last_cache_update[tenant_id] < self.cache_ttl):
            return self.usage_cache[tenant_id]
        
        # 计算实际使用量（这里需要根据实际系统实现）
        usage = {
            'banned_ips': 0,  # 需要从IP管理器获取
            'rules': 0,  # 需要从规则管理器获取
            'users': len(await self.storage.list_users(tenant_id)),
            'api_requests_last_hour': 0,  # 需要从API统计获取
            'storage_mb': 0,  # 需要从存储系统获取
            'concurrent_sessions': 0  # 需要从会话管理器获取
        }
        
        # 更新缓存
        self.usage_cache[tenant_id] = usage
        self.last_cache_update[tenant_id] = now
        
        return usage
    
    async def check_quota(self, tenant_id: str, resource: str, requested: int = 1) -> bool:
        """检查资源配额"""
        try:
            tenant = await self.storage.get_tenant(tenant_id)
            if not tenant:
                return False
            
            usage = await self.get_tenant_usage(tenant_id)
            quota = tenant.quota
            
            quota_limits = {
                'banned_ips': quota.max_banned_ips,
                'rules': quota.max_rules,
                'users': quota.max_users,
                'api_requests_per_hour': quota.max_api_requests_per_hour,
                'storage_mb': quota.max_storage_mb,
                'concurrent_sessions': quota.max_concurrent_sessions
            }
            
            if resource not in quota_limits:
                return True
            
            current_usage = usage.get(resource, 0)
            limit = quota_limits[resource]
            
            return current_usage + requested <= limit
            
        except Exception as e:
            self.logger.error(f"检查配额失败: {e}")
            return False
    
    async def get_quota_status(self, tenant_id: str) -> Dict[str, Any]:
        """获取配额状态"""
        try:
            tenant = await self.storage.get_tenant(tenant_id)
            if not tenant:
                return {}
            
            usage = await self.get_tenant_usage(tenant_id)
            quota = tenant.quota
            
            status = {}
            quota_limits = {
                'banned_ips': quota.max_banned_ips,
                'rules': quota.max_rules,
                'users': quota.max_users,
                'api_requests_per_hour': quota.max_api_requests_per_hour,
                'storage_mb': quota.max_storage_mb,
                'concurrent_sessions': quota.max_concurrent_sessions
            }
            
            for resource, limit in quota_limits.items():
                current = usage.get(resource, 0)
                status[resource] = {
                    'current': current,
                    'limit': limit,
                    'usage_percent': (current / limit * 100) if limit > 0 else 0,
                    'available': max(0, limit - current)
                }
            
            return status
            
        except Exception as e:
            self.logger.error(f"获取配额状态失败: {e}")
            return {}


class MultiTenancyManager:
    """多租户管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 初始化存储
        storage_config = config.get('storage', {})
        storage_type = storage_config.get('type', 'sqlite')
        
        if storage_type == 'sqlite':
            db_path = storage_config.get('db_path', 'tenants.db')
            self.storage = SQLiteTenantStorage(db_path)
        else:
            raise ValueError(f"不支持的存储类型: {storage_type}")
        
        # 初始化管理器
        secret_key = config.get('secret_key', secrets.token_urlsafe(32))
        self.auth_manager = AuthenticationManager(self.storage, secret_key)
        self.authz_manager = AuthorizationManager()
        self.quota_manager = ResourceQuotaManager(self.storage)
        
        # 默认配额
        self.default_quota = ResourceQuota.from_dict(
            config.get('default_quota', {})
        )
    
    async def initialize(self) -> None:
        """初始化多租户系统"""
        if hasattr(self.storage, 'initialize'):
            await self.storage.initialize()
        
        # 创建默认超级管理员租户和用户
        await self._create_default_admin()
        
        self.logger.info("多租户系统初始化完成")
    
    async def _create_default_admin(self) -> None:
        """创建默认超级管理员"""
        admin_tenant_id = "system"
        admin_username = "admin"
        admin_password = self.config.get('admin_password', 'admin123')
        
        # 检查是否已存在
        existing_tenant = await self.storage.get_tenant(admin_tenant_id)
        if existing_tenant:
            return
        
        # 创建系统租户
        admin_tenant = Tenant(
            id=admin_tenant_id,
            name="系统管理",
            description="系统管理租户",
            status=TenantStatus.ACTIVE,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            quota=ResourceQuota(max_users=100, max_banned_ips=100000)  # 更高配额
        )
        
        await self.storage.create_tenant(admin_tenant)
        
        # 创建超级管理员用户
        admin_user = User(
            id=str(uuid.uuid4()),
            tenant_id=admin_tenant_id,
            username=admin_username,
            email="admin@system.local",
            password_hash=self.auth_manager.hash_password(admin_password),
            role=UserRole.SUPER_ADMIN,
            permissions=set(),  # 超级管理员通过角色获得所有权限
            is_active=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        await self.storage.create_user(admin_user)
        
        self.logger.info(f"已创建默认超级管理员: {admin_username}")
    
    async def create_tenant(self, name: str, description: str, 
                          quota: Optional[ResourceQuota] = None) -> Optional[Tenant]:
        """创建租户"""
        try:
            tenant = Tenant(
                id=str(uuid.uuid4()),
                name=name,
                description=description,
                status=TenantStatus.ACTIVE,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                quota=quota or self.default_quota
            )
            
            success = await self.storage.create_tenant(tenant)
            if success:
                self.logger.info(f"已创建租户: {name} ({tenant.id})")
                return tenant
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"创建租户失败: {e}")
            return None
    
    async def create_user(self, tenant_id: str, username: str, email: str, 
                         password: str, role: UserRole) -> Optional[User]:
        """创建用户"""
        try:
            # 检查配额
            if not await self.quota_manager.check_quota(tenant_id, 'users'):
                self.logger.warning(f"租户 {tenant_id} 用户配额已满")
                return None
            
            user = User(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                username=username,
                email=email,
                password_hash=self.auth_manager.hash_password(password),
                role=role,
                permissions=set(),
                is_active=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            success = await self.storage.create_user(user)
            if success:
                self.logger.info(f"已创建用户: {username} ({user.id})")
                return user
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"创建用户失败: {e}")
            return None
    
    async def login(self, tenant_id: str, username: str, password: str, 
                   ip_address: str, user_agent: str) -> Optional[Session]:
        """用户登录"""
        user = await self.auth_manager.authenticate_user(tenant_id, username, password)
        if not user:
            return None
        
        return await self.auth_manager.create_session(user, ip_address, user_agent)
    
    async def validate_session(self, token: str) -> Optional[tuple[Session, User, Tenant]]:
        """验证会话并返回相关信息"""
        session = await self.auth_manager.validate_session(token)
        if not session:
            return None
        
        user = await self.storage.get_user(session.user_id)
        if not user:
            return None
        
        tenant = await self.storage.get_tenant(session.tenant_id)
        if not tenant:
            return None
        
        return session, user, tenant
    
    async def logout(self, token: str) -> bool:
        """用户登出"""
        return await self.auth_manager.logout(token)
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """检查权限"""
        return self.authz_manager.has_permission(user, permission)
    
    def check_tenant_access(self, user: User, tenant_id: str) -> bool:
        """检查租户访问权限"""
        return self.authz_manager.can_access_tenant(user, tenant_id)
    
    async def get_tenant_statistics(self, tenant_id: str) -> Dict[str, Any]:
        """获取租户统计信息"""
        try:
            tenant = await self.storage.get_tenant(tenant_id)
            if not tenant:
                return {}
            
            users = await self.storage.list_users(tenant_id)
            quota_status = await self.quota_manager.get_quota_status(tenant_id)
            
            return {
                'tenant': tenant.to_dict(),
                'user_count': len(users),
                'active_user_count': len([u for u in users if u.is_active]),
                'quota_status': quota_status
            }
            
        except Exception as e:
            self.logger.error(f"获取租户统计失败: {e}")
            return {}
    
    async def cleanup_expired_sessions(self) -> int:
        """清理过期会话"""
        return await self.auth_manager.cleanup_expired_sessions()
    
    async def start_background_tasks(self) -> None:
        """启动后台任务"""
        # 定期清理过期会话
        asyncio.create_task(self._periodic_cleanup())
        
        self.logger.info("多租户后台任务已启动")
    
    async def _periodic_cleanup(self) -> None:
        """定期清理任务"""
        while True:
            try:
                await asyncio.sleep(3600)  # 每小时执行一次
                
                # 清理过期会话
                cleaned = await self.cleanup_expired_sessions()
                if cleaned > 0:
                    self.logger.info(f"已清理 {cleaned} 个过期会话")
                
            except Exception as e:
                self.logger.error(f"定期清理任务失败: {e}")


if __name__ == "__main__":
    # 示例配置
    config = {
        'storage': {
            'type': 'sqlite',
            'db_path': 'tenants.db'
        },
        'secret_key': 'your-secret-key-here',
        'admin_password': 'admin123',
        'default_quota': {
            'max_banned_ips': 1000,
            'max_rules': 50,
            'max_users': 5,
            'max_api_requests_per_hour': 5000,
            'max_log_retention_days': 30,
            'max_storage_mb': 500,
            'max_concurrent_sessions': 5
        }
    }
    
    # 示例用法
    async def main():
        manager = MultiTenancyManager(config)
        await manager.initialize()
        await manager.start_background_tasks()
        
        # 创建租户
        tenant = await manager.create_tenant(
            name="测试公司",
            description="测试租户"
        )
        
        if tenant:
            print(f"已创建租户: {tenant.name} ({tenant.id})")
            
            # 创建用户
            user = await manager.create_user(
                tenant_id=tenant.id,
                username="testuser",
                email="test@example.com",
                password="password123",
                role=UserRole.TENANT_ADMIN
            )
            
            if user:
                print(f"已创建用户: {user.username} ({user.id})")
                
                # 用户登录
                session = await manager.login(
                    tenant_id=tenant.id,
                    username="testuser",
                    password="password123",
                    ip_address="127.0.0.1",
                    user_agent="Test Client"
                )
                
                if session:
                    print(f"登录成功，会话令牌: {session.token}")
                    
                    # 验证会话
                    result = await manager.validate_session(session.token)
                    if result:
                        session, user, tenant = result
                        print(f"会话验证成功: {user.username}@{tenant.name}")
                        
                        # 检查权限
                        has_perm = manager.check_permission(user, Permission.IP_BAN)
                        print(f"用户是否有封禁IP权限: {has_perm}")
                        
                        # 获取统计信息
                        stats = await manager.get_tenant_statistics(tenant.id)
                        print(f"租户统计: {json.dumps(stats, ensure_ascii=False, indent=2)}")
    
    # 运行示例
    # asyncio.run(main())