#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 通知模块
"""

import asyncio
import json
import smtplib
import time
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

import aiohttp


class BaseNotifier(ABC):
    """通知器基类"""
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled = config.get('enabled', False)
        self.rate_limit = config.get('rate_limit', 60)  # 秒
        self.last_sent = {}
    
    def _should_send(self, notification_type: str) -> bool:
        """检查是否应该发送通知（基于速率限制）
        
        Args:
            notification_type: 通知类型
        
        Returns:
            是否应该发送
        """
        if not self.enabled:
            return False
        
        current_time = time.time()
        last_time = self.last_sent.get(notification_type, 0)
        
        if current_time - last_time >= self.rate_limit:
            self.last_sent[notification_type] = current_time
            return True
        
        return False
    
    @abstractmethod
    async def send(self, title: str, message: str, notification_type: str = 'info') -> bool:
        """发送通知
        
        Args:
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
        
        Returns:
            是否发送成功
        """
        pass


class EmailNotifier(BaseNotifier):
    """邮件通知器"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.from_email = config.get('from_email', '')
        self.to_emails = config.get('to_emails', [])
        self.use_tls = config.get('use_tls', True)
    
    async def send(self, title: str, message: str, notification_type: str = 'info') -> bool:
        """发送邮件通知
        
        Args:
            title: 邮件标题
            message: 邮件内容
            notification_type: 通知类型
        
        Returns:
            是否发送成功
        """
        if not self._should_send(notification_type):
            return False
        
        try:
            # 创建邮件
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[Fail2ban] {title}"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            # 添加时间戳
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            full_message = f"时间: {timestamp}\n\n{message}"
            
            # 创建文本和HTML版本
            text_part = MIMEText(full_message, 'plain', 'utf-8')
            html_message = self._create_html_message(title, full_message, notification_type)
            html_part = MIMEText(html_message, 'html', 'utf-8')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # 发送邮件
            await self._send_email(msg)
            
            print(f"邮件通知发送成功: {title}")
            return True
        
        except Exception as e:
            print(f"邮件发送失败: {e}")
            return False
    
    def _create_html_message(self, title: str, message: str, notification_type: str) -> str:
        """创建HTML格式的邮件内容
        
        Args:
            title: 标题
            message: 消息内容
            notification_type: 通知类型
        
        Returns:
            HTML内容
        """
        # 根据通知类型选择颜色
        colors = {
            'info': '#17a2b8',
            'warning': '#ffc107',
            'error': '#dc3545',
            'success': '#28a745',
            'ban': '#fd7e14',
            'unban': '#6f42c1'
        }
        
        color = colors.get(notification_type, '#17a2b8')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{title}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: {color};
                    color: white;
                    padding: 20px;
                    border-radius: 5px 5px 0 0;
                    text-align: center;
                }}
                .content {{
                    background-color: #f8f9fa;
                    padding: 20px;
                    border: 1px solid #dee2e6;
                    border-radius: 0 0 5px 5px;
                }}
                .message {{
                    background-color: white;
                    padding: 15px;
                    border-radius: 5px;
                    white-space: pre-wrap;
                    font-family: monospace;
                    font-size: 14px;
                }}
                .footer {{
                    text-align: center;
                    margin-top: 20px;
                    color: #6c757d;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🛡️ Fail2ban 分布式系统通知</h2>
                <h3>{title}</h3>
            </div>
            <div class="content">
                <div class="message">{message}</div>
            </div>
            <div class="footer">
                <p>此邮件由 Fail2ban 分布式系统自动发送</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    async def _send_email(self, msg: MIMEMultipart):
        """发送邮件（异步包装）
        
        Args:
            msg: 邮件消息对象
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_email_sync, msg)
    
    def _send_email_sync(self, msg: MIMEMultipart):
        """同步发送邮件
        
        Args:
            msg: 邮件消息对象
        """
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            if self.use_tls:
                server.starttls()
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            server.send_message(msg)


class DingTalkNotifier(BaseNotifier):
    """钉钉通知器"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url', '')
        self.secret = config.get('secret', '')
        self.at_mobiles = config.get('at_mobiles', [])
        self.at_all = config.get('at_all', False)
    
    async def send(self, title: str, message: str, notification_type: str = 'info') -> bool:
        """发送钉钉通知
        
        Args:
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
        
        Returns:
            是否发送成功
        """
        if not self._should_send(notification_type) or not self.webhook_url:
            return False
        
        try:
            # 构建消息
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 根据通知类型选择emoji
            emojis = {
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌',
                'success': '✅',
                'ban': '🚫',
                'unban': '🔓'
            }
            
            emoji = emojis.get(notification_type, 'ℹ️')
            
            # 构建Markdown消息
            markdown_text = f"""
# {emoji} {title}

**时间:** {timestamp}

**详情:**
```
{message}
```

---
*Fail2ban 分布式系统自动通知*
            """
            
            payload = {
                'msgtype': 'markdown',
                'markdown': {
                    'title': title,
                    'text': markdown_text
                }
            }
            
            # 添加@功能
            if self.at_mobiles or self.at_all:
                payload['at'] = {
                    'atMobiles': self.at_mobiles,
                    'isAtAll': self.at_all
                }
            
            # 如果配置了签名，添加签名
            url = self.webhook_url
            if self.secret:
                url = self._sign_url(url)
            
            # 发送请求
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as response:
                    result = await response.json()
                    
                    if result.get('errcode') == 0:
                        print(f"钉钉通知发送成功: {title}")
                        return True
                    else:
                        print(f"钉钉通知发送失败: {result.get('errmsg')}")
                        return False
        
        except Exception as e:
            print(f"钉钉通知发送异常: {e}")
            return False
    
    def _sign_url(self, url: str) -> str:
        """为钉钉webhook URL添加签名
        
        Args:
            url: 原始URL
        
        Returns:
            带签名的URL
        """
        import base64
        import hashlib
        import hmac
        import urllib.parse
        
        timestamp = str(round(time.time() * 1000))
        secret_enc = self.secret.encode('utf-8')
        string_to_sign = f'{timestamp}\n{self.secret}'
        string_to_sign_enc = string_to_sign.encode('utf-8')
        
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        
        return f"{url}&timestamp={timestamp}&sign={sign}"


class WeChatNotifier(BaseNotifier):
    """企业微信通知器"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url', '')
        self.mentioned_list = config.get('mentioned_list', [])
        self.mentioned_mobile_list = config.get('mentioned_mobile_list', [])
    
    async def send(self, title: str, message: str, notification_type: str = 'info') -> bool:
        """发送企业微信通知
        
        Args:
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
        
        Returns:
            是否发送成功
        """
        if not self._should_send(notification_type) or not self.webhook_url:
            return False
        
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 根据通知类型选择颜色
            colors = {
                'info': 'info',
                'warning': 'warning',
                'error': 'warning',  # 企业微信没有error颜色
                'success': 'info',
                'ban': 'warning',
                'unban': 'info'
            }
            
            color = colors.get(notification_type, 'info')
            
            # 构建Markdown消息
            markdown_content = f"""
# {title}

> **时间:** {timestamp}
> **类型:** {notification_type.upper()}

**详细信息:**
```
{message}
```

---
<font color="comment">Fail2ban 分布式系统</font>
            """
            
            payload = {
                'msgtype': 'markdown',
                'markdown': {
                    'content': markdown_content
                }
            }
            
            # 添加@功能
            if self.mentioned_list or self.mentioned_mobile_list:
                payload['markdown']['mentioned_list'] = self.mentioned_list
                payload['markdown']['mentioned_mobile_list'] = self.mentioned_mobile_list
            
            # 发送请求
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    result = await response.json()
                    
                    if result.get('errcode') == 0:
                        print(f"企业微信通知发送成功: {title}")
                        return True
                    else:
                        print(f"企业微信通知发送失败: {result.get('errmsg')}")
                        return False
        
        except Exception as e:
            print(f"企业微信通知发送异常: {e}")
            return False


class SlackNotifier(BaseNotifier):
    """Slack通知器"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        self.webhook_url = config.get('webhook_url', '')
        self.channel = config.get('channel', '#general')
        self.username = config.get('username', 'Fail2ban Bot')
        self.icon_emoji = config.get('icon_emoji', ':shield:')
    
    async def send(self, title: str, message: str, notification_type: str = 'info') -> bool:
        """发送Slack通知
        
        Args:
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
        
        Returns:
            是否发送成功
        """
        if not self._should_send(notification_type) or not self.webhook_url:
            return False
        
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 根据通知类型选择颜色
            colors = {
                'info': '#36a64f',
                'warning': '#ff9500',
                'error': '#ff0000',
                'success': '#36a64f',
                'ban': '#ff9500',
                'unban': '#36a64f'
            }
            
            color = colors.get(notification_type, '#36a64f')
            
            payload = {
                'channel': self.channel,
                'username': self.username,
                'icon_emoji': self.icon_emoji,
                'attachments': [
                    {
                        'color': color,
                        'title': title,
                        'text': message,
                        'footer': 'Fail2ban 分布式系统',
                        'ts': int(time.time())
                    }
                ]
            }
            
            # 发送请求
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        print(f"Slack通知发送成功: {title}")
                        return True
                    else:
                        print(f"Slack通知发送失败: HTTP {response.status}")
                        return False
        
        except Exception as e:
            print(f"Slack通知发送异常: {e}")
            return False


class NotificationManager:
    """通知管理器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.notifiers = []
        
        # 初始化各种通知器
        self._init_notifiers()
        
        # 通知级别配置
        self.notification_levels = config.get('levels', {
            'info': ['email'],
            'warning': ['email', 'dingtalk'],
            'error': ['email', 'dingtalk', 'wechat'],
            'ban': ['email', 'dingtalk'],
            'unban': ['email']
        })
    
    def _init_notifiers(self):
        """初始化通知器"""
        notification_config = self.config.get('notifications', {})
        
        # 邮件通知器
        if 'email' in notification_config:
            email_config = notification_config['email']
            if email_config.get('enabled', False):
                self.notifiers.append(('email', EmailNotifier(email_config)))
        
        # 钉钉通知器
        if 'dingtalk' in notification_config:
            dingtalk_config = notification_config['dingtalk']
            if dingtalk_config.get('enabled', False):
                self.notifiers.append(('dingtalk', DingTalkNotifier(dingtalk_config)))
        
        # 企业微信通知器
        if 'wechat' in notification_config:
            wechat_config = notification_config['wechat']
            if wechat_config.get('enabled', False):
                self.notifiers.append(('wechat', WeChatNotifier(wechat_config)))
        
        # Slack通知器
        if 'slack' in notification_config:
            slack_config = notification_config['slack']
            if slack_config.get('enabled', False):
                self.notifiers.append(('slack', SlackNotifier(slack_config)))
        
        print(f"已初始化 {len(self.notifiers)} 个通知器")
    
    async def send_notification(self, title: str, message: str, notification_type: str = 'info') -> Dict[str, bool]:
        """发送通知
        
        Args:
            title: 通知标题
            message: 通知内容
            notification_type: 通知类型
        
        Returns:
            各通知器的发送结果
        """
        results = {}
        
        # 获取该级别应该使用的通知器
        enabled_notifiers = self.notification_levels.get(notification_type, [])
        
        # 发送通知
        tasks = []
        for notifier_name, notifier in self.notifiers:
            if notifier_name in enabled_notifiers:
                task = asyncio.create_task(
                    self._send_with_retry(notifier, title, message, notification_type)
                )
                tasks.append((notifier_name, task))
        
        # 等待所有通知发送完成
        for notifier_name, task in tasks:
            try:
                result = await task
                results[notifier_name] = result
            except Exception as e:
                print(f"通知器 {notifier_name} 发送异常: {e}")
                results[notifier_name] = False
        
        return results
    
    async def _send_with_retry(self, notifier: BaseNotifier, title: str, message: str, 
                              notification_type: str, max_retries: int = 3) -> bool:
        """带重试的发送通知
        
        Args:
            notifier: 通知器实例
            title: 标题
            message: 消息
            notification_type: 通知类型
            max_retries: 最大重试次数
        
        Returns:
            是否发送成功
        """
        for attempt in range(max_retries):
            try:
                result = await notifier.send(title, message, notification_type)
                if result:
                    return True
                
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # 指数退避
            
            except Exception as e:
                print(f"通知发送尝试 {attempt + 1} 失败: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        
        return False
    
    async def send_ban_notification(self, ip: str, reason: str, duration: int, 
                                   server_info: Dict) -> Dict[str, bool]:
        """发送封禁通知
        
        Args:
            ip: 被封禁的IP
            reason: 封禁原因
            duration: 封禁时长（秒）
            server_info: 服务器信息
        
        Returns:
            发送结果
        """
        title = f"IP封禁通知 - {ip}"
        
        duration_str = self._format_duration(duration)
        
        message = f"""
IP地址: {ip}
封禁原因: {reason}
封禁时长: {duration_str}
服务器: {server_info.get('hostname', 'Unknown')}
节点ID: {server_info.get('node_id', 'Unknown')}
地区: {server_info.get('region', 'Unknown')}

请注意监控该IP的后续行为。
        """
        
        return await self.send_notification(title, message, 'ban')
    
    async def send_unban_notification(self, ip: str, reason: str, 
                                     server_info: Dict) -> Dict[str, bool]:
        """发送解封通知
        
        Args:
            ip: 被解封的IP
            reason: 解封原因
            server_info: 服务器信息
        
        Returns:
            发送结果
        """
        title = f"IP解封通知 - {ip}"
        
        message = f"""
IP地址: {ip}
解封原因: {reason}
服务器: {server_info.get('hostname', 'Unknown')}
节点ID: {server_info.get('node_id', 'Unknown')}
地区: {server_info.get('region', 'Unknown')}

IP已从封禁列表中移除。
        """
        
        return await self.send_notification(title, message, 'unban')
    
    async def send_attack_notification(self, attack_info: Dict) -> Dict[str, bool]:
        """发送攻击检测通知
        
        Args:
            attack_info: 攻击信息
        
        Returns:
            发送结果
        """
        ip = attack_info.get('ip', 'Unknown')
        attack_type = attack_info.get('type', 'Unknown')
        
        title = f"攻击检测 - {attack_type}"
        
        message = f"""
攻击IP: {ip}
攻击类型: {attack_type}
攻击路径: {attack_info.get('path', 'Unknown')}
用户代理: {attack_info.get('user_agent', 'Unknown')}
服务器: {attack_info.get('server', 'Unknown')}
检测时间: {attack_info.get('timestamp', 'Unknown')}

建议立即检查服务器安全状态。
        """
        
        return await self.send_notification(title, message, 'warning')
    
    async def send_system_notification(self, event_type: str, details: Dict) -> Dict[str, bool]:
        """发送系统事件通知
        
        Args:
            event_type: 事件类型
            details: 事件详情
        
        Returns:
            发送结果
        """
        title = f"系统事件 - {event_type}"
        
        message = f"""
事件类型: {event_type}
服务器: {details.get('server', 'Unknown')}
节点ID: {details.get('node_id', 'Unknown')}
事件时间: {details.get('timestamp', 'Unknown')}

详细信息:
{details.get('message', '无详细信息')}
        """
        
        # 根据事件类型确定通知级别
        notification_level = 'info'
        if 'error' in event_type.lower() or 'fail' in event_type.lower():
            notification_level = 'error'
        elif 'warning' in event_type.lower() or 'warn' in event_type.lower():
            notification_level = 'warning'
        
        return await self.send_notification(title, message, notification_level)
    
    def _format_duration(self, seconds: int) -> str:
        """格式化时长
        
        Args:
            seconds: 秒数
        
        Returns:
            格式化的时长字符串
        """
        if seconds < 60:
            return f"{seconds}秒"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes}分钟"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours}小时"
        else:
            days = seconds // 86400
            return f"{days}天"
    
    def get_statistics(self) -> Dict:
        """获取通知统计信息
        
        Returns:
            统计信息
        """
        stats = {
            'enabled_notifiers': len(self.notifiers),
            'notifier_types': [name for name, _ in self.notifiers],
            'notification_levels': self.notification_levels
        }
        
        # 获取各通知器的发送统计
        for name, notifier in self.notifiers:
            stats[f'{name}_last_sent'] = notifier.last_sent
        
        return stats


if __name__ == '__main__':
    # 测试通知管理器
    config = {
        'notifications': {
            'email': {
                'enabled': False,  # 测试时禁用
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'your-email@gmail.com',
                'password': 'your-password',
                'from_email': 'fail2ban@example.com',
                'to_emails': ['admin@example.com']
            },
            'dingtalk': {
                'enabled': False,  # 测试时禁用
                'webhook_url': 'https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN'
            }
        },
        'levels': {
            'ban': ['email', 'dingtalk'],
            'warning': ['dingtalk']
        }
    }
    
    async def test_notifications():
        manager = NotificationManager(config)
        
        print("=== 通知系统测试 ===")
        
        # 测试封禁通知
        server_info = {
            'hostname': 'web-server-01',
            'node_id': 'node-001',
            'region': 'Beijing'
        }
        
        print("\n测试封禁通知...")
        ban_result = await manager.send_ban_notification(
            '192.168.1.100',
            'SQL注入攻击',
            3600,
            server_info
        )
        print(f"封禁通知结果: {ban_result}")
        
        # 测试攻击检测通知
        print("\n测试攻击检测通知...")
        attack_info = {
            'ip': '10.0.0.1',
            'type': 'XSS攻击',
            'path': '/search?q=<script>alert(1)</script>',
            'user_agent': 'Mozilla/5.0',
            'server': 'web-server-02',
            'timestamp': datetime.now().isoformat()
        }
        
        attack_result = await manager.send_attack_notification(attack_info)
        print(f"攻击通知结果: {attack_result}")
        
        # 测试系统事件通知
        print("\n测试系统事件通知...")
        system_details = {
            'server': 'web-server-01',
            'node_id': 'node-001',
            'timestamp': datetime.now().isoformat(),
            'message': 'Fail2ban服务重启完成'
        }
        
        system_result = await manager.send_system_notification('服务重启', system_details)
        print(f"系统通知结果: {system_result}")
        
        # 获取统计信息
        print("\n=== 通知统计 ===")
        stats = manager.get_statistics()
        for key, value in stats.items():
            print(f"{key}: {value}")
    
    asyncio.run(test_notifications())
    print("\n通知系统测试完成")