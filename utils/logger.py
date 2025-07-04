#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 日志记录工具
"""

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


def setup_logger(name: str, config: dict, log_file: Optional[str] = None) -> logging.Logger:
    """设置日志记录器
    
    Args:
        name: 日志记录器名称
        config: 配置字典
        log_file: 可选的日志文件路径，覆盖配置中的设置
    
    Returns:
        配置好的日志记录器
    """
    logger = logging.getLogger(name)
    
    # 避免重复添加处理器
    if logger.handlers:
        return logger
    
    # 获取日志级别
    log_level = config.get('system', {}).get('log_level', 'INFO')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 文件处理器
    if log_file:
        file_path = log_file
    else:
        file_path = config.get('system', {}).get('log_file', f'/var/log/fail2ban-distributed/{name}.log')
    
    if file_path:
        try:
            # 确保日志目录存在
            log_dir = Path(file_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # 使用RotatingFileHandler进行日志轮转
            file_handler = logging.handlers.RotatingFileHandler(
                file_path,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_level.upper()))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
        except Exception as e:
            logger.warning(f"无法创建文件日志处理器: {e}")
    
    return logger


class StructuredLogger:
    """结构化日志记录器"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def log_event(self, level: str, event_type: str, message: str, **kwargs):
        """记录结构化事件
        
        Args:
            level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            event_type: 事件类型 (ban, unban, attack_detected, etc.)
            message: 日志消息
            **kwargs: 额外的结构化数据
        """
        extra_data = {
            'event_type': event_type,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        
        # 构建结构化消息
        structured_msg = f"[{event_type}] {message}"
        if kwargs:
            details = ', '.join([f"{k}={v}" for k, v in kwargs.items()])
            structured_msg += f" | {details}"
        
        # 记录日志
        log_method = getattr(self.logger, level.lower())
        log_method(structured_msg, extra=extra_data)
    
    def log_ban(self, ip: str, reason: str, duration: int, node_id: str = None):
        """记录封禁事件"""
        self.log_event(
            'WARNING',
            'ip_banned',
            f"IP {ip} has been banned",
            ip=ip,
            reason=reason,
            duration_minutes=duration,
            node_id=node_id
        )
    
    def log_unban(self, ip: str, node_id: str = None):
        """记录解封事件"""
        self.log_event(
            'INFO',
            'ip_unbanned',
            f"IP {ip} has been unbanned",
            ip=ip,
            node_id=node_id
        )
    
    def log_attack(self, ip: str, attack_type: str, details: dict = None):
        """记录攻击检测事件"""
        self.log_event(
            'WARNING',
            'attack_detected',
            f"Attack detected from IP {ip}",
            ip=ip,
            attack_type=attack_type,
            details=details or {}
        )
    
    def log_system_event(self, event: str, status: str, details: dict = None):
        """记录系统事件"""
        level = 'INFO' if status == 'success' else 'ERROR'
        self.log_event(
            level,
            'system_event',
            f"System event: {event}",
            event=event,
            status=status,
            details=details or {}
        )


class LogAnalyzer:
    """日志分析器"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
    
    def get_recent_events(self, hours: int = 24, event_type: str = None) -> list:
        """获取最近的事件
        
        Args:
            hours: 时间范围（小时）
            event_type: 事件类型过滤
        
        Returns:
            事件列表
        """
        events = []
        
        try:
            if not Path(self.log_file).exists():
                return events
            
            cutoff_time = datetime.now().timestamp() - (hours * 3600)
            
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        # 简单的日志解析
                        if '[' in line and ']' in line:
                            # 提取时间戳
                            timestamp_str = line.split(' - ')[0]
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            
                            if timestamp.timestamp() >= cutoff_time:
                                # 提取事件类型
                                if '[' in line and ']' in line:
                                    start = line.find('[') + 1
                                    end = line.find(']')
                                    current_event_type = line[start:end]
                                    
                                    if not event_type or current_event_type == event_type:
                                        events.append({
                                            'timestamp': timestamp,
                                            'event_type': current_event_type,
                                            'message': line.strip()
                                        })
                    except Exception:
                        continue
        
        except Exception as e:
            print(f"分析日志文件失败: {e}")
        
        return sorted(events, key=lambda x: x['timestamp'], reverse=True)
    
    def get_ban_statistics(self, hours: int = 24) -> dict:
        """获取封禁统计信息"""
        ban_events = self.get_recent_events(hours, 'ip_banned')
        unban_events = self.get_recent_events(hours, 'ip_unbanned')
        
        # 统计IP
        banned_ips = set()
        unbanned_ips = set()
        
        for event in ban_events:
            # 从消息中提取IP
            message = event['message']
            if 'IP ' in message:
                try:
                    ip_start = message.find('IP ') + 3
                    ip_end = message.find(' ', ip_start)
                    if ip_end == -1:
                        ip_end = len(message)
                    ip = message[ip_start:ip_end]
                    banned_ips.add(ip)
                except Exception:
                    continue
        
        for event in unban_events:
            message = event['message']
            if 'IP ' in message:
                try:
                    ip_start = message.find('IP ') + 3
                    ip_end = message.find(' ', ip_start)
                    if ip_end == -1:
                        ip_end = len(message)
                    ip = message[ip_start:ip_end]
                    unbanned_ips.add(ip)
                except Exception:
                    continue
        
        return {
            'total_bans': len(ban_events),
            'total_unbans': len(unban_events),
            'unique_banned_ips': len(banned_ips),
            'unique_unbanned_ips': len(unbanned_ips),
            'currently_banned': len(banned_ips - unbanned_ips)
        }


def setup_system_logging():
    """设置系统级日志记录"""
    # 确保日志目录存在
    log_dir = Path('/var/log/fail2ban-distributed')
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 设置权限
    try:
        os.chmod(log_dir, 0o755)
    except Exception:
        pass
    
    # 配置根日志记录器
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.handlers.RotatingFileHandler(
                log_dir / 'system.log',
                maxBytes=10 * 1024 * 1024,
                backupCount=5
            )
        ]
    )


if __name__ == '__main__':
    # 测试日志记录器
    config = {
        'system': {
            'log_level': 'DEBUG',
            'log_file': '/tmp/test.log'
        }
    }
    
    logger = setup_logger('test', config)
    structured_logger = StructuredLogger(logger)
    
    # 测试各种日志记录
    logger.info("测试普通日志")
    structured_logger.log_ban('192.168.1.100', 'Too many 404 errors', 60, 'node-001')
    structured_logger.log_attack('10.0.0.1', 'sql_injection', {'pattern': 'union select'})
    structured_logger.log_system_event('service_start', 'success', {'component': 'central_server'})
    
    print("日志记录测试完成")