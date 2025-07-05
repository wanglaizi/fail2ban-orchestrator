#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 多数据源和通知渠道支持

实现对多种数据源的支持和多样化的通知方式
"""

import asyncio
import json
import logging
import smtplib
import ssl
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from urllib.parse import urljoin
import re

import aiohttp
import aiofiles
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yaml

# 数据库驱动
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

try:
    import aiomysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

try:
    import asyncpg
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False

# 消息队列
try:
    import aio_pika
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False

try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

# 通知服务
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class LogEntry:
    """日志条目"""
    timestamp: datetime
    source: str
    level: str
    message: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    response_status: Optional[int] = None
    response_size: Optional[int] = None
    extra_fields: Optional[Dict[str, Any]] = None


@dataclass
class NotificationMessage:
    """通知消息"""
    title: str
    content: str
    level: str  # info, warning, error, critical
    timestamp: datetime
    source: str
    tags: List[str]
    metadata: Dict[str, Any]


class DataSource(ABC):
    """数据源基类"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.is_connected = False
        self.error_count = 0
        self.last_error = None
    
    @abstractmethod
    async def connect(self) -> bool:
        """连接数据源"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """断开连接"""
        pass
    
    @abstractmethod
    async def read_logs(self, since: Optional[datetime] = None, 
                       limit: Optional[int] = None) -> List[LogEntry]:
        """读取日志"""
        pass
    
    @abstractmethod
    async def write_log(self, entry: LogEntry) -> bool:
        """写入日志"""
        pass
    
    async def health_check(self) -> bool:
        """健康检查"""
        try:
            # 尝试读取少量数据
            await self.read_logs(limit=1)
            return True
        except Exception as e:
            self.logger.error(f"健康检查失败: {e}")
            return False


class FileDataSource(DataSource):
    """文件数据源"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.file_path = Path(config['file_path'])
        self.log_format = config.get('log_format', 'common')
        self.encoding = config.get('encoding', 'utf-8')
        self.tail_mode = config.get('tail_mode', True)
        self.last_position = 0
        
        # 日志格式解析器
        self.parsers = {
            'common': self._parse_common_log,
            'combined': self._parse_combined_log,
            'nginx': self._parse_nginx_log,
            'apache': self._parse_apache_log,
            'json': self._parse_json_log,
            'custom': self._parse_custom_log
        }
    
    async def connect(self) -> bool:
        """连接文件数据源"""
        try:
            if not self.file_path.exists():
                self.logger.error(f"日志文件不存在: {self.file_path}")
                return False
            
            # 获取文件大小作为初始位置
            if self.tail_mode:
                self.last_position = self.file_path.stat().st_size
            
            self.is_connected = True
            self.logger.info(f"已连接到文件数据源: {self.file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"连接文件数据源失败: {e}")
            self.last_error = str(e)
            return False
    
    async def disconnect(self) -> None:
        """断开连接"""
        self.is_connected = False
    
    async def read_logs(self, since: Optional[datetime] = None, 
                       limit: Optional[int] = None) -> List[LogEntry]:
        """读取日志"""
        if not self.is_connected:
            return []
        
        try:
            async with aiofiles.open(self.file_path, 'r', encoding=self.encoding) as f:
                # 移动到上次读取位置
                await f.seek(self.last_position)
                
                lines = []
                count = 0
                
                async for line in f:
                    if limit and count >= limit:
                        break
                    
                    line = line.strip()
                    if line:
                        lines.append(line)
                        count += 1
                
                # 更新位置
                self.last_position = await f.tell()
                
                # 解析日志条目
                entries = []
                parser = self.parsers.get(self.log_format, self._parse_common_log)
                
                for line in lines:
                    try:
                        entry = parser(line)
                        if entry and (not since or entry.timestamp >= since):
                            entries.append(entry)
                    except Exception as e:
                        self.logger.warning(f"解析日志行失败: {line[:100]}... 错误: {e}")
                
                return entries
                
        except Exception as e:
            self.logger.error(f"读取日志文件失败: {e}")
            self.error_count += 1
            self.last_error = str(e)
            return []
    
    async def write_log(self, entry: LogEntry) -> bool:
        """写入日志"""
        try:
            log_line = self._format_log_entry(entry)
            
            async with aiofiles.open(self.file_path, 'a', encoding=self.encoding) as f:
                await f.write(log_line + '\n')
            
            return True
            
        except Exception as e:
            self.logger.error(f"写入日志失败: {e}")
            return False
    
    def _parse_common_log(self, line: str) -> Optional[LogEntry]:
        """解析通用日志格式"""
        # 通用日志格式: IP - - [timestamp] "method url protocol" status size
        pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp_str, method, url, protocol, status, size = match.groups()
            
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                timestamp = datetime.now()
            
            return LogEntry(
                timestamp=timestamp,
                source=self.name,
                level='INFO',
                message=line,
                ip_address=ip,
                request_method=method,
                request_url=url,
                response_status=int(status),
                response_size=int(size) if size != '-' else None
            )
        
        return None
    
    def _parse_combined_log(self, line: str) -> Optional[LogEntry]:
        """解析组合日志格式"""
        # 组合日志格式: IP - - [timestamp] "method url protocol" status size "referer" "user-agent"
        pattern = r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp_str, method, url, protocol, status, size, referer, user_agent = match.groups()
            
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                timestamp = datetime.now()
            
            return LogEntry(
                timestamp=timestamp,
                source=self.name,
                level='INFO',
                message=line,
                ip_address=ip,
                user_agent=user_agent,
                request_method=method,
                request_url=url,
                response_status=int(status),
                response_size=int(size) if size != '-' else None,
                extra_fields={'referer': referer}
            )
        
        return None
    
    def _parse_nginx_log(self, line: str) -> Optional[LogEntry]:
        """解析Nginx日志格式"""
        return self._parse_combined_log(line)
    
    def _parse_apache_log(self, line: str) -> Optional[LogEntry]:
        """解析Apache日志格式"""
        return self._parse_combined_log(line)
    
    def _parse_json_log(self, line: str) -> Optional[LogEntry]:
        """解析JSON日志格式"""
        try:
            data = json.loads(line)
            
            timestamp_str = data.get('timestamp', data.get('time', data.get('@timestamp')))
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            return LogEntry(
                timestamp=timestamp,
                source=self.name,
                level=data.get('level', 'INFO'),
                message=data.get('message', line),
                ip_address=data.get('ip', data.get('remote_addr')),
                user_agent=data.get('user_agent'),
                request_method=data.get('method'),
                request_url=data.get('url', data.get('path')),
                response_status=data.get('status'),
                response_size=data.get('size'),
                extra_fields={k: v for k, v in data.items() if k not in [
                    'timestamp', 'time', '@timestamp', 'level', 'message', 
                    'ip', 'remote_addr', 'user_agent', 'method', 'url', 'path', 'status', 'size'
                ]}
            )
            
        except json.JSONDecodeError:
            return None
    
    def _parse_custom_log(self, line: str) -> Optional[LogEntry]:
        """解析自定义日志格式"""
        # 可以根据配置中的自定义格式进行解析
        custom_pattern = self.config.get('custom_pattern')
        if custom_pattern:
            try:
                match = re.match(custom_pattern, line)
                if match:
                    groups = match.groupdict()
                    return LogEntry(
                        timestamp=datetime.now(),
                        source=self.name,
                        level='INFO',
                        message=line,
                        ip_address=groups.get('ip'),
                        user_agent=groups.get('user_agent'),
                        request_method=groups.get('method'),
                        request_url=groups.get('url'),
                        response_status=int(groups.get('status', 0)) if groups.get('status') else None,
                        extra_fields=groups
                    )
            except Exception as e:
                self.logger.warning(f"自定义格式解析失败: {e}")
        
        return None
    
    def _format_log_entry(self, entry: LogEntry) -> str:
        """格式化日志条目"""
        if self.log_format == 'json':
            data = {
                'timestamp': entry.timestamp.isoformat(),
                'source': entry.source,
                'level': entry.level,
                'message': entry.message
            }
            
            if entry.ip_address:
                data['ip'] = entry.ip_address
            if entry.user_agent:
                data['user_agent'] = entry.user_agent
            if entry.request_method:
                data['method'] = entry.request_method
            if entry.request_url:
                data['url'] = entry.request_url
            if entry.response_status:
                data['status'] = entry.response_status
            if entry.response_size:
                data['size'] = entry.response_size
            if entry.extra_fields:
                data.update(entry.extra_fields)
            
            return json.dumps(data, ensure_ascii=False)
        else:
            # 使用通用格式
            timestamp_str = entry.timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')
            return f"{entry.ip_address or '-'} - - [{timestamp_str}] \"{entry.request_method or '-'} {entry.request_url or '-'} HTTP/1.1\" {entry.response_status or '-'} {entry.response_size or '-'}"


class DatabaseDataSource(DataSource):
    """数据库数据源基类"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.connection = None
        self.table_name = config.get('table_name', 'logs')
    
    @abstractmethod
    async def _create_connection(self):
        """创建数据库连接"""
        pass
    
    @abstractmethod
    async def _execute_query(self, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """执行查询"""
        pass
    
    @abstractmethod
    async def _execute_insert(self, query: str, params: tuple) -> bool:
        """执行插入"""
        pass


class RedisDataSource(DataSource):
    """Redis数据源"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.redis_client = None
        self.key_prefix = config.get('key_prefix', 'fail2ban:logs')
        self.max_entries = config.get('max_entries', 10000)
    
    async def connect(self) -> bool:
        """连接Redis"""
        if not REDIS_AVAILABLE:
            self.logger.error("Redis库未安装")
            return False
        
        try:
            self.redis_client = redis.Redis(
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 6379),
                password=self.config.get('password'),
                db=self.config.get('db', 0),
                decode_responses=True
            )
            
            # 测试连接
            await self.redis_client.ping()
            self.is_connected = True
            self.logger.info(f"已连接到Redis: {self.config.get('host')}:{self.config.get('port')}")
            return True
            
        except Exception as e:
            self.logger.error(f"连接Redis失败: {e}")
            self.last_error = str(e)
            return False
    
    async def disconnect(self) -> None:
        """断开连接"""
        if self.redis_client:
            await self.redis_client.close()
        self.is_connected = False
    
    async def read_logs(self, since: Optional[datetime] = None, 
                       limit: Optional[int] = None) -> List[LogEntry]:
        """读取日志"""
        if not self.is_connected or not self.redis_client:
            return []
        
        try:
            # 从Redis列表中获取日志
            count = limit or 100
            log_data = await self.redis_client.lrange(self.key_prefix, -count, -1)
            
            entries = []
            for data in log_data:
                try:
                    log_dict = json.loads(data)
                    entry = LogEntry(
                        timestamp=datetime.fromisoformat(log_dict['timestamp']),
                        source=log_dict['source'],
                        level=log_dict['level'],
                        message=log_dict['message'],
                        ip_address=log_dict.get('ip_address'),
                        user_agent=log_dict.get('user_agent'),
                        request_method=log_dict.get('request_method'),
                        request_url=log_dict.get('request_url'),
                        response_status=log_dict.get('response_status'),
                        response_size=log_dict.get('response_size'),
                        extra_fields=log_dict.get('extra_fields')
                    )
                    
                    if not since or entry.timestamp >= since:
                        entries.append(entry)
                        
                except Exception as e:
                    self.logger.warning(f"解析Redis日志条目失败: {e}")
            
            return entries
            
        except Exception as e:
            self.logger.error(f"从Redis读取日志失败: {e}")
            self.error_count += 1
            return []
    
    async def write_log(self, entry: LogEntry) -> bool:
        """写入日志"""
        if not self.is_connected or not self.redis_client:
            return False
        
        try:
            log_dict = {
                'timestamp': entry.timestamp.isoformat(),
                'source': entry.source,
                'level': entry.level,
                'message': entry.message,
                'ip_address': entry.ip_address,
                'user_agent': entry.user_agent,
                'request_method': entry.request_method,
                'request_url': entry.request_url,
                'response_status': entry.response_status,
                'response_size': entry.response_size,
                'extra_fields': entry.extra_fields
            }
            
            # 添加到Redis列表
            await self.redis_client.lpush(self.key_prefix, json.dumps(log_dict, ensure_ascii=False))
            
            # 限制列表长度
            await self.redis_client.ltrim(self.key_prefix, 0, self.max_entries - 1)
            
            return True
            
        except Exception as e:
            self.logger.error(f"写入Redis日志失败: {e}")
            return False


class NotificationChannel(ABC):
    """通知渠道基类"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.is_enabled = config.get('enabled', True)
        self.rate_limit = config.get('rate_limit', 60)  # 秒
        self.last_sent = {}
    
    @abstractmethod
    async def send_notification(self, message: NotificationMessage) -> bool:
        """发送通知"""
        pass
    
    def _should_send(self, message: NotificationMessage) -> bool:
        """检查是否应该发送通知（速率限制）"""
        if not self.is_enabled:
            return False
        
        now = datetime.now()
        key = f"{message.level}_{message.source}"
        
        if key in self.last_sent:
            time_diff = (now - self.last_sent[key]).total_seconds()
            if time_diff < self.rate_limit:
                return False
        
        self.last_sent[key] = now
        return True
    
    async def test_connection(self) -> bool:
        """测试连接"""
        test_message = NotificationMessage(
            title="测试通知",
            content="这是一条测试通知消息",
            level="info",
            timestamp=datetime.now(),
            source="test",
            tags=["test"],
            metadata={}
        )
        
        return await self.send_notification(test_message)


class EmailNotificationChannel(NotificationChannel):
    """邮件通知渠道"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.smtp_server = config.get('smtp_server')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_email = config.get('from_email', self.username)
        self.to_emails = config.get('to_emails', [])
        self.use_tls = config.get('use_tls', True)
    
    async def send_notification(self, message: NotificationMessage) -> bool:
        """发送邮件通知"""
        if not self._should_send(message):
            return True
        
        try:
            # 创建邮件消息
            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[{message.level.upper()}] {message.title}"
            
            # 邮件内容
            body = f"""
时间: {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
来源: {message.source}
级别: {message.level.upper()}
标签: {', '.join(message.tags)}

内容:
{message.content}

元数据:
{json.dumps(message.metadata, ensure_ascii=False, indent=2)}
            """
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # 发送邮件
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)
            
            self.logger.info(f"邮件通知发送成功: {message.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"发送邮件通知失败: {e}")
            return False


class WebhookNotificationChannel(NotificationChannel):
    """Webhook通知渠道"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.webhook_url = config.get('webhook_url')
        self.method = config.get('method', 'POST')
        self.headers = config.get('headers', {'Content-Type': 'application/json'})
        self.timeout = config.get('timeout', 30)
    
    async def send_notification(self, message: NotificationMessage) -> bool:
        """发送Webhook通知"""
        if not self._should_send(message):
            return True
        
        try:
            payload = {
                'title': message.title,
                'content': message.content,
                'level': message.level,
                'timestamp': message.timestamp.isoformat(),
                'source': message.source,
                'tags': message.tags,
                'metadata': message.metadata
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=self.method,
                    url=self.webhook_url,
                    json=payload,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status < 400:
                        self.logger.info(f"Webhook通知发送成功: {message.title}")
                        return True
                    else:
                        self.logger.error(f"Webhook通知发送失败，状态码: {response.status}")
                        return False
            
        except Exception as e:
            self.logger.error(f"发送Webhook通知失败: {e}")
            return False


class SlackNotificationChannel(NotificationChannel):
    """Slack通知渠道"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.webhook_url = config.get('webhook_url')
        self.channel = config.get('channel', '#general')
        self.username = config.get('username', 'Fail2ban Bot')
        self.icon_emoji = config.get('icon_emoji', ':shield:')
    
    async def send_notification(self, message: NotificationMessage) -> bool:
        """发送Slack通知"""
        if not self._should_send(message):
            return True
        
        try:
            # 根据级别选择颜色
            color_map = {
                'info': 'good',
                'warning': 'warning',
                'error': 'danger',
                'critical': 'danger'
            }
            
            payload = {
                'channel': self.channel,
                'username': self.username,
                'icon_emoji': self.icon_emoji,
                'attachments': [{
                    'color': color_map.get(message.level, 'good'),
                    'title': message.title,
                    'text': message.content,
                    'fields': [
                        {'title': '时间', 'value': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'short': True},
                        {'title': '来源', 'value': message.source, 'short': True},
                        {'title': '级别', 'value': message.level.upper(), 'short': True},
                        {'title': '标签', 'value': ', '.join(message.tags), 'short': True}
                    ],
                    'timestamp': int(message.timestamp.timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack通知发送成功: {message.title}")
                        return True
                    else:
                        self.logger.error(f"Slack通知发送失败，状态码: {response.status}")
                        return False
            
        except Exception as e:
            self.logger.error(f"发送Slack通知失败: {e}")
            return False


class DingTalkNotificationChannel(NotificationChannel):
    """钉钉通知渠道"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.webhook_url = config.get('webhook_url')
        self.secret = config.get('secret')
    
    async def send_notification(self, message: NotificationMessage) -> bool:
        """发送钉钉通知"""
        if not self._should_send(message):
            return True
        
        try:
            # 构建消息内容
            content = f"""
**{message.title}**

**时间:** {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
**来源:** {message.source}
**级别:** {message.level.upper()}
**标签:** {', '.join(message.tags)}

**内容:**
{message.content}
            """
            
            payload = {
                'msgtype': 'markdown',
                'markdown': {
                    'title': message.title,
                    'text': content
                }
            }
            
            # 如果配置了签名，添加签名
            url = self.webhook_url
            if self.secret:
                import time
                import hmac
                import hashlib
                import base64
                from urllib.parse import quote_plus
                
                timestamp = str(round(time.time() * 1000))
                secret_enc = self.secret.encode('utf-8')
                string_to_sign = f'{timestamp}\n{self.secret}'
                string_to_sign_enc = string_to_sign.encode('utf-8')
                hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
                sign = quote_plus(base64.b64encode(hmac_code))
                url = f'{self.webhook_url}&timestamp={timestamp}&sign={sign}'
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        if result.get('errcode') == 0:
                            self.logger.info(f"钉钉通知发送成功: {message.title}")
                            return True
                        else:
                            self.logger.error(f"钉钉通知发送失败: {result.get('errmsg')}")
                            return False
                    else:
                        self.logger.error(f"钉钉通知发送失败，状态码: {response.status}")
                        return False
            
        except Exception as e:
            self.logger.error(f"发送钉钉通知失败: {e}")
            return False


class MultiDataSourceManager:
    """多数据源管理器"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_sources: Dict[str, DataSource] = {}
        self.notification_channels: Dict[str, NotificationChannel] = {}
        self.logger = logging.getLogger(__name__)
        
        # 初始化数据源
        self._initialize_data_sources()
        
        # 初始化通知渠道
        self._initialize_notification_channels()
        
        # 统计信息
        self.stats = {
            'total_logs_read': 0,
            'total_logs_written': 0,
            'total_notifications_sent': 0,
            'data_source_errors': defaultdict(int),
            'notification_errors': defaultdict(int)
        }
    
    def _initialize_data_sources(self) -> None:
        """初始化数据源"""
        data_sources_config = self.config.get('data_sources', {})
        
        for name, config in data_sources_config.items():
            if not config.get('enabled', True):
                continue
            
            source_type = config.get('type')
            
            try:
                if source_type == 'file':
                    self.data_sources[name] = FileDataSource(name, config)
                elif source_type == 'redis':
                    self.data_sources[name] = RedisDataSource(name, config)
                # 可以添加更多数据源类型
                else:
                    self.logger.warning(f"不支持的数据源类型: {source_type}")
                    
            except Exception as e:
                self.logger.error(f"初始化数据源 {name} 失败: {e}")
    
    def _initialize_notification_channels(self) -> None:
        """初始化通知渠道"""
        channels_config = self.config.get('notification_channels', {})
        
        for name, config in channels_config.items():
            if not config.get('enabled', True):
                continue
            
            channel_type = config.get('type')
            
            try:
                if channel_type == 'email':
                    self.notification_channels[name] = EmailNotificationChannel(name, config)
                elif channel_type == 'webhook':
                    self.notification_channels[name] = WebhookNotificationChannel(name, config)
                elif channel_type == 'slack':
                    self.notification_channels[name] = SlackNotificationChannel(name, config)
                elif channel_type == 'dingtalk':
                    self.notification_channels[name] = DingTalkNotificationChannel(name, config)
                else:
                    self.logger.warning(f"不支持的通知渠道类型: {channel_type}")
                    
            except Exception as e:
                self.logger.error(f"初始化通知渠道 {name} 失败: {e}")
    
    async def connect_all_data_sources(self) -> Dict[str, bool]:
        """连接所有数据源"""
        results = {}
        
        for name, source in self.data_sources.items():
            try:
                success = await source.connect()
                results[name] = success
                if success:
                    self.logger.info(f"数据源 {name} 连接成功")
                else:
                    self.logger.error(f"数据源 {name} 连接失败")
            except Exception as e:
                self.logger.error(f"连接数据源 {name} 时发生异常: {e}")
                results[name] = False
        
        return results
    
    async def disconnect_all_data_sources(self) -> None:
        """断开所有数据源连接"""
        for name, source in self.data_sources.items():
            try:
                await source.disconnect()
                self.logger.info(f"数据源 {name} 已断开连接")
            except Exception as e:
                self.logger.error(f"断开数据源 {name} 连接时发生异常: {e}")
    
    async def read_logs_from_all_sources(self, since: Optional[datetime] = None, 
                                        limit: Optional[int] = None) -> List[LogEntry]:
        """从所有数据源读取日志"""
        all_logs = []
        
        for name, source in self.data_sources.items():
            if not source.is_connected:
                continue
            
            try:
                logs = await source.read_logs(since, limit)
                all_logs.extend(logs)
                self.stats['total_logs_read'] += len(logs)
                
            except Exception as e:
                self.logger.error(f"从数据源 {name} 读取日志失败: {e}")
                self.stats['data_source_errors'][name] += 1
        
        # 按时间排序
        all_logs.sort(key=lambda x: x.timestamp)
        
        return all_logs
    
    async def write_log_to_sources(self, entry: LogEntry, 
                                  target_sources: Optional[List[str]] = None) -> Dict[str, bool]:
        """写入日志到指定数据源"""
        results = {}
        sources_to_write = target_sources or list(self.data_sources.keys())
        
        for name in sources_to_write:
            if name not in self.data_sources:
                continue
            
            source = self.data_sources[name]
            if not source.is_connected:
                results[name] = False
                continue
            
            try:
                success = await source.write_log(entry)
                results[name] = success
                if success:
                    self.stats['total_logs_written'] += 1
                else:
                    self.stats['data_source_errors'][name] += 1
                    
            except Exception as e:
                self.logger.error(f"写入日志到数据源 {name} 失败: {e}")
                results[name] = False
                self.stats['data_source_errors'][name] += 1
        
        return results
    
    async def send_notification_to_all_channels(self, message: NotificationMessage) -> Dict[str, bool]:
        """发送通知到所有渠道"""
        results = {}
        
        for name, channel in self.notification_channels.items():
            try:
                success = await channel.send_notification(message)
                results[name] = success
                if success:
                    self.stats['total_notifications_sent'] += 1
                else:
                    self.stats['notification_errors'][name] += 1
                    
            except Exception as e:
                self.logger.error(f"通过渠道 {name} 发送通知失败: {e}")
                results[name] = False
                self.stats['notification_errors'][name] += 1
        
        return results
    
    async def health_check_all_sources(self) -> Dict[str, bool]:
        """检查所有数据源健康状态"""
        results = {}
        
        for name, source in self.data_sources.items():
            try:
                is_healthy = await source.health_check()
                results[name] = is_healthy
            except Exception as e:
                self.logger.error(f"数据源 {name} 健康检查失败: {e}")
                results[name] = False
        
        return results
    
    async def test_all_notification_channels(self) -> Dict[str, bool]:
        """测试所有通知渠道"""
        results = {}
        
        for name, channel in self.notification_channels.items():
            try:
                success = await channel.test_connection()
                results[name] = success
            except Exception as e:
                self.logger.error(f"测试通知渠道 {name} 失败: {e}")
                results[name] = False
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'data_sources': {
                'total': len(self.data_sources),
                'connected': sum(1 for source in self.data_sources.values() if source.is_connected),
                'error_counts': dict(self.stats['data_source_errors'])
            },
            'notification_channels': {
                'total': len(self.notification_channels),
                'enabled': sum(1 for channel in self.notification_channels.values() if channel.is_enabled),
                'error_counts': dict(self.stats['notification_errors'])
            },
            'operations': {
                'total_logs_read': self.stats['total_logs_read'],
                'total_logs_written': self.stats['total_logs_written'],
                'total_notifications_sent': self.stats['total_notifications_sent']
            }
        }
    
    async def start_monitoring(self) -> None:
        """开始监控"""
        # 连接所有数据源
        await self.connect_all_data_sources()
        
        # 启动定期健康检查
        asyncio.create_task(self._periodic_health_check())
        
        self.logger.info("多数据源管理器已启动")
    
    async def stop_monitoring(self) -> None:
        """停止监控"""
        await self.disconnect_all_data_sources()
        self.logger.info("多数据源管理器已停止")
    
    async def _periodic_health_check(self) -> None:
        """定期健康检查"""
        while True:
            try:
                await asyncio.sleep(300)  # 5分钟检查一次
                
                health_results = await self.health_check_all_sources()
                unhealthy_sources = [name for name, healthy in health_results.items() if not healthy]
                
                if unhealthy_sources:
                    # 发送健康检查告警
                    message = NotificationMessage(
                        title="数据源健康检查告警",
                        content=f"以下数据源健康检查失败: {', '.join(unhealthy_sources)}",
                        level="warning",
                        timestamp=datetime.now(),
                        source="health_check",
                        tags=["health_check", "data_source"],
                        metadata={"unhealthy_sources": unhealthy_sources}
                    )
                    
                    await self.send_notification_to_all_channels(message)
                
            except Exception as e:
                self.logger.error(f"定期健康检查失败: {e}")


if __name__ == "__main__":
    # 示例配置
    config = {
        'data_sources': {
            'nginx_access': {
                'type': 'file',
                'enabled': True,
                'file_path': '/var/log/nginx/access.log',
                'log_format': 'combined',
                'encoding': 'utf-8',
                'tail_mode': True
            },
            'redis_cache': {
                'type': 'redis',
                'enabled': True,
                'host': 'localhost',
                'port': 6379,
                'db': 0,
                'key_prefix': 'fail2ban:logs',
                'max_entries': 10000
            }
        },
        'notification_channels': {
            'email_admin': {
                'type': 'email',
                'enabled': True,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'admin@example.com',
                'password': 'password',
                'to_emails': ['admin@example.com'],
                'rate_limit': 300
            },
            'slack_alerts': {
                'type': 'slack',
                'enabled': True,
                'webhook_url': 'https://hooks.slack.com/services/...',
                'channel': '#security',
                'username': 'Fail2ban Bot',
                'rate_limit': 60
            }
        }
    }
    
    # 示例用法
    async def main():
        manager = MultiDataSourceManager(config)
        await manager.start_monitoring()
        
        # 读取日志
        logs = await manager.read_logs_from_all_sources(limit=10)
        print(f"读取到 {len(logs)} 条日志")
        
        # 发送测试通知
        test_message = NotificationMessage(
            title="测试通知",
            content="这是一条测试通知消息",
            level="info",
            timestamp=datetime.now(),
            source="test",
            tags=["test"],
            metadata={}
        )
        
        results = await manager.send_notification_to_all_channels(test_message)
        print(f"通知发送结果: {results}")
        
        # 获取统计信息
        stats = manager.get_statistics()
        print(f"统计信息: {json.dumps(stats, ensure_ascii=False, indent=2)}")
        
        await manager.stop_monitoring()
    
    # 运行示例
    # asyncio.run(main())