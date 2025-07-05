#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 日志记录工具

提供结构化日志记录、日志分析和系统级日志配置功能
"""

import json
import logging
import logging.handlers
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Union, Set, Tuple, TextIO


class LoggerConfigError(Exception):
    """日志配置错误
    
    当日志记录器配置失败时抛出此异常。
    """
    
    def __init__(self, message: str, original_error: Optional[Exception] = None) -> None:
        """初始化日志配置错误
        
        Args:
            message: 错误消息
            original_error: 原始异常
        """
        super().__init__(message)
        self.original_error = original_error
        self.message = message


class LogAnalysisError(Exception):
    """日志分析错误
    
    当日志分析过程中发生错误时抛出此异常。
    """
    
    def __init__(self, message: str, original_error: Optional[Exception] = None) -> None:
        """初始化日志分析错误
        
        Args:
            message: 错误消息
            original_error: 原始异常
        """
        super().__init__(message)
        self.original_error = original_error
        self.message = message


class LogFileError(Exception):
    """日志文件错误
    
    当日志文件操作失败时抛出此异常。
    """
    
    def __init__(self, message: str, file_path: Optional[str] = None, original_error: Optional[Exception] = None) -> None:
        """初始化日志文件错误
        
        Args:
            message: 错误消息
            file_path: 文件路径
            original_error: 原始异常
        """
        super().__init__(message)
        self.file_path = file_path
        self.original_error = original_error
        self.message = message


def setup_logger(
    name: str, 
    level: str = 'INFO', 
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    console_output: bool = True
) -> logging.Logger:
    """设置日志记录器
    
    Args:
        name: 日志记录器名称
        level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: 日志文件路径
        max_bytes: 单个日志文件最大字节数
        backup_count: 备份文件数量
        console_output: 是否输出到控制台
    
    Returns:
        配置好的日志记录器
        
    Raises:
        LoggerConfigError: 日志配置错误
    """
    # 参数验证
    if not name or not isinstance(name, str):
        raise LoggerConfigError("日志记录器名称必须是非空字符串")
    
    if not isinstance(level, str):
        raise LoggerConfigError("日志级别必须是字符串")
    
    if not isinstance(max_bytes, int) or max_bytes <= 0:
        raise LoggerConfigError("日志文件最大字节数必须是正整数")
    
    if not isinstance(backup_count, int) or backup_count < 0:
        raise LoggerConfigError("备份文件数量必须是非负整数")
    
    if not isinstance(console_output, bool):
        raise LoggerConfigError("控制台输出标志必须是布尔值")
    
    try:
        logger = logging.getLogger(name)
        
        # 避免重复添加处理器
        if logger.handlers:
            return logger
        
        # 验证日志级别
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if level.upper() not in valid_levels:
            raise LoggerConfigError(f"无效的日志级别: {level}")
        
        logger.setLevel(getattr(logging, level.upper()))
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 控制台处理器
        if console_output:
            try:
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                console_handler.setFormatter(formatter)
                logger.addHandler(console_handler)
            except Exception as e:
                raise LoggerConfigError(f"无法创建控制台处理器: {e}", e)
        
        # 文件处理器
        if log_file:
            try:
                # 验证文件路径
                if not isinstance(log_file, str):
                    raise LoggerConfigError("日志文件路径必须是字符串")
                
                # 确保日志目录存在
                log_dir = Path(log_file).parent
                log_dir.mkdir(parents=True, exist_ok=True)
                
                # 检查目录权限
                if not os.access(log_dir, os.W_OK):
                    raise LoggerConfigError(f"没有写入权限: {log_dir}")
                
                # 验证参数
                if max_bytes <= 0:
                    raise LoggerConfigError(f"无效的最大字节数: {max_bytes}")
                if backup_count < 0:
                    raise LoggerConfigError(f"无效的备份数量: {backup_count}")
                
                # 使用RotatingFileHandler进行日志轮转
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding='utf-8'
                )
                file_handler.setLevel(getattr(logging, level.upper()))
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
                
            except LoggerConfigError:
                raise
            except Exception as e:
                raise LoggerConfigError(f"无法创建文件日志处理器: {e}", e)
        
        return logger
        
    except LoggerConfigError:
        raise
    except Exception as e:
        raise LoggerConfigError(f"设置日志记录器失败: {e}", e)


def setup_logger_from_config(name: str, config: Dict[str, Any]) -> logging.Logger:
    """从配置字典设置日志记录器
    
    Args:
        name: 日志记录器名称
        config: 配置字典，包含以下可选键:
            - logging.level: 日志级别 (默认: 'INFO')
            - logging.file: 日志文件路径
            - logging.max_size: 最大文件大小 (默认: '10MB')
            - logging.backup_count: 备份文件数量 (默认: 5)
            - logging.console: 是否输出到控制台 (默认: True)
        
    Returns:
        配置好的日志记录器
        
    Raises:
        LoggerConfigError: 配置错误
    """
    if not isinstance(config, dict):
        raise LoggerConfigError("配置必须是字典类型")
    
    try:
        logging_config = config.get('logging', {})
        
        if not isinstance(logging_config, dict):
            raise LoggerConfigError("logging配置必须是字典类型")
        
        # 提取并验证配置参数
        level = logging_config.get('level', 'INFO')
        if not isinstance(level, str):
            raise LoggerConfigError("日志级别必须是字符串")
        
        log_file = logging_config.get('file')
        if log_file is not None and not isinstance(log_file, str):
            raise LoggerConfigError("日志文件路径必须是字符串")
        
        max_size_str = logging_config.get('max_size', '10MB')
        if not isinstance(max_size_str, str):
            raise LoggerConfigError("最大文件大小必须是字符串")
        
        try:
            max_bytes = _parse_size(max_size_str)
        except Exception as e:
            raise LoggerConfigError(f"解析最大文件大小失败: {e}", e)
        
        backup_count = logging_config.get('backup_count', 5)
        if not isinstance(backup_count, int) or backup_count < 0:
            raise LoggerConfigError("备份文件数量必须是非负整数")
        
        console_output = logging_config.get('console', True)
        if not isinstance(console_output, bool):
            raise LoggerConfigError("控制台输出标志必须是布尔值")
        
        return setup_logger(
            name=name,
            level=level,
            log_file=log_file,
            max_bytes=max_bytes,
            backup_count=backup_count,
            console_output=console_output
        )
        
    except LoggerConfigError:
        raise
    except Exception as e:
        raise LoggerConfigError(f"从配置设置日志记录器失败: {e}", e)


def _parse_size(size_str: str) -> int:
    """解析大小字符串
    
    Args:
        size_str: 大小字符串，如 '10MB', '1GB', '512KB'
        
    Returns:
        字节数
        
    Raises:
        ValueError: 无效的大小格式
        LoggerConfigError: 配置错误
    """
    if not isinstance(size_str, str):
        raise LoggerConfigError("大小字符串必须是字符串类型")
    
    if not size_str or not size_str.strip():
        return 10 * 1024 * 1024  # 默认10MB
    
    size_str = size_str.upper().strip()
    
    try:
        # 提取数字和单位
        match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGT]?B?)$', size_str)
        if not match:
            raise ValueError(f"无效的大小格式: {size_str}，支持格式如: 10MB, 1GB, 512KB")
        
        number_str, unit = match.groups()
        
        try:
            number = float(number_str)
        except ValueError:
            raise ValueError(f"无效的数字: {number_str}")
        
        if number < 0:
            raise ValueError("文件大小不能为负数")
        
        if number > 1024 ** 4:  # 限制最大1TB
            raise ValueError("文件大小不能超过1TB")
        
        # 转换为字节
        multipliers: Dict[str, int] = {
            'B': 1,
            'KB': 1024,
            'MB': 1024 ** 2,
            'GB': 1024 ** 3,
            'TB': 1024 ** 4,
            '': 1  # 无单位默认为字节
        }
        
        if unit not in multipliers:
            raise ValueError(f"不支持的单位: {unit}，支持的单位: B, KB, MB, GB, TB")
        
        result = int(number * multipliers[unit])
        
        if result <= 0:
            raise ValueError("文件大小必须大于0")
        
        # 检查合理性（最小1KB，最大1TB）
        if result < 1024:
            raise ValueError("文件大小不能小于1KB")
        
        return result
        
    except ValueError as e:
        raise LoggerConfigError(f"解析大小字符串失败: {e}", e)
    except Exception as e:
        raise LoggerConfigError(f"解析大小字符串时发生未知错误: {e}", e)


class StructuredLogger:
    """结构化日志记录器
    
    提供结构化的日志记录功能，支持事件类型和附加数据。
    包含性能监控、安全事件记录等功能。
    """
    
    def __init__(self, logger: logging.Logger) -> None:
        """初始化结构化日志记录器
        
        Args:
            logger: 基础日志记录器
            
        Raises:
            LoggerConfigError: 初始化失败
        """
        if not isinstance(logger, logging.Logger):
            raise LoggerConfigError("logger必须是logging.Logger实例")
        
        try:
            self.logger = logger
            self.start_time = datetime.now()
            self._event_counts: Dict[str, int] = {}
            self._last_cleanup = datetime.now()
            self._valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        except Exception as e:
            raise LoggerConfigError(f"初始化结构化日志记录器失败: {e}", e)
    
    def _cleanup_event_counts(self) -> None:
        """定期清理事件计数
        
        每小时清理一次事件计数，避免内存泄漏
        """
        try:
            now = datetime.now()
            if (now - self._last_cleanup).total_seconds() > 3600:  # 1小时
                # 保留最近的计数，清理过多的条目
                if len(self._event_counts) > 1000:
                    # 只保留最常见的500个事件类型
                    sorted_counts = sorted(self._event_counts.items(), key=lambda x: x[1], reverse=True)
                    self._event_counts = dict(sorted_counts[:500])
                
                self._last_cleanup = now
        except Exception:
            # 清理失败不应影响主要功能
            pass
    
    def log_event(
        self, 
        level: str, 
        event_type: str, 
        message: str, 
        **kwargs: Any
    ) -> None:
        """记录结构化事件
        
        Args:
            level: 日志级别 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            event_type: 事件类型 (ban, unban, attack_detected, etc.)
            message: 日志消息
            **kwargs: 额外的结构化数据
            
        Raises:
            ValueError: 无效的日志级别
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(event_type, str) or not event_type.strip():
            raise LoggerConfigError("事件类型必须是非空字符串")
        
        if not isinstance(message, str):
            raise LoggerConfigError("消息必须是字符串")
        
        if not isinstance(level, str) or level.upper() not in self._valid_levels:
            raise LoggerConfigError(f"无效的日志级别: {level}，支持的级别: {', '.join(self._valid_levels)}")
        
        try:
            # 更新事件计数
            self._event_counts[event_type] = self._event_counts.get(event_type, 0) + 1
            
            # 验证日志级别
            if level.upper() not in self._valid_levels:
                raise ValueError(f"无效的日志级别: {level}")
            
            # 清理和验证数据
            try:
                cleaned_kwargs = self._clean_log_data(kwargs)
            except Exception as e:
                self.logger.warning(f"清理日志数据失败: {e}")
                cleaned_kwargs = {}
            
            extra_data = {
                'event_type': event_type,
                'timestamp': datetime.now().isoformat(),
                'event_count': self._event_counts[event_type],
                **cleaned_kwargs
            }
            
            # 构建结构化消息
            structured_msg = f"[{event_type}] {message}"
            if cleaned_kwargs:
                details = ', '.join([f"{k}={v}" for k, v in cleaned_kwargs.items()])
                structured_msg += f" | {details}"
            
            # 记录日志
            try:
                log_method = getattr(self.logger, level.lower())
                log_method(structured_msg, extra=extra_data)
            except AttributeError:
                # 如果日志级别方法不存在，使用默认级别
                self.logger.info(structured_msg, extra=extra_data)
            
            # 定期清理事件计数
            self._cleanup_event_counts()
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 确保日志记录错误不会影响主程序
            try:
                self.logger.error(f"记录结构化日志失败: {e}, 事件类型: {event_type}, 消息: {message}")
            except Exception:
                # 如果连普通日志都失败，则静默忽略
                pass
    
    def _clean_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """清理日志数据，移除敏感信息
        
        Args:
            data: 原始数据字典
            
        Returns:
            清理后的数据字典
            
        Raises:
            LoggerConfigError: 数据清理失败
        """
        if not isinstance(data, dict):
            raise LoggerConfigError("数据必须是字典类型")
        
        try:
            cleaned: Dict[str, Any] = {}
            sensitive_keys = {
                'password', 'passwd', 'pwd',
                'token', 'access_token', 'refresh_token',
                'secret', 'api_secret', 'client_secret',
                'key', 'api_key', 'private_key',
                'auth', 'authorization', 'credential',
                'session', 'cookie', 'csrf'
            }
            
            max_depth = 10  # 防止无限递归
            
            def _clean_recursive(obj: Any, depth: int = 0) -> Any:
                """递归清理数据"""
                if depth > max_depth:
                    return '[MAX_DEPTH_EXCEEDED]'
                
                if isinstance(obj, dict):
                    result = {}
                    for k, v in obj.items():
                        if not isinstance(k, str):
                            k = str(k)
                        
                        # 检查敏感键
                        if any(sensitive in k.lower() for sensitive in sensitive_keys):
                            result[k] = '[REDACTED]'
                        else:
                            result[k] = _clean_recursive(v, depth + 1)
                    return result
                
                elif isinstance(obj, (list, tuple)):
                    return [_clean_recursive(item, depth + 1) for item in obj]
                
                elif isinstance(obj, str):
                    # 限制字符串长度，防止日志过大
                    if len(obj) > 1000:
                        return obj[:1000] + '[TRUNCATED]'
                    return obj
                
                elif isinstance(obj, (int, float, bool)):
                    return obj
                
                elif obj is None:
                    return None
                
                else:
                    # 对于其他类型，转换为字符串并限制长度
                    str_obj = str(obj)
                    if len(str_obj) > 500:
                        return str_obj[:500] + '[TRUNCATED]'
                    return str_obj
            
            cleaned = _clean_recursive(data)
            
            # 确保返回的是字典
            if not isinstance(cleaned, dict):
                return {'cleaned_data': cleaned}
            
            return cleaned
            
        except Exception as e:
            raise LoggerConfigError(f"清理日志数据失败: {e}", e)
    
    def log_ban(
        self, 
        ip: str, 
        reason: str, 
        duration: int, 
        node_id: Optional[str] = None,
        additional_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """记录封禁事件
        
        Args:
            ip: 被封禁的IP地址
            reason: 封禁原因
            duration: 封禁时长（分钟）
            node_id: 节点ID
            additional_info: 额外信息
            
        Raises:
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(ip, str) or not ip.strip():
            raise LoggerConfigError("IP地址必须是非空字符串")
        
        if not isinstance(reason, str) or not reason.strip():
            raise LoggerConfigError("封禁原因必须是非空字符串")
        
        if not isinstance(duration, int) or duration < 0:
            raise LoggerConfigError("封禁时长必须是非负整数")
        
        if node_id is not None and not isinstance(node_id, str):
            raise LoggerConfigError("节点ID必须是字符串")
        
        try:
            # 验证IP地址格式（简单验证）
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                for part in ip_parts:
                    if not part.isdigit() or not 0 <= int(part) <= 255:
                        raise LoggerConfigError(f"无效的IPv4地址: {ip}")
            elif ':' not in ip:  # 简单的IPv6检查
                raise LoggerConfigError(f"无效的IP地址格式: {ip}")
            
            log_data = {
                'ip': ip,
                'reason': reason,
                'duration_minutes': duration,
                'duration_seconds': duration * 60,
                'node_id': node_id,
                'ban_timestamp': datetime.now().isoformat()
            }
            
            # 添加额外信息
            if additional_info:
                try:
                    cleaned_info = self._clean_log_data(additional_info)
                    log_data.update(cleaned_info)
                except Exception as e:
                    self.logger.warning(f"清理封禁日志额外数据失败: {e}")
            
            # 构建消息
            duration_str = f"{duration}分钟"
            if duration >= 1440:  # 超过1天
                days = duration // 1440
                hours = (duration % 1440) // 60
                duration_str = f"{days}天{hours}小时"
            elif duration >= 60:  # 超过1小时
                hours = duration // 60
                minutes = duration % 60
                duration_str = f"{hours}小时{minutes}分钟"
            
            message = f"IP {ip} has been banned for {duration_str}: {reason}"
            
            self.log_event(
                'WARNING',
                'ip_banned',
                message,
                **log_data
            )
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 降级记录
            try:
                self.logger.error(f"记录封禁事件失败: {e}, IP: {ip}, 原因: {reason}")
            except Exception:
                pass
    
    def log_unban(
        self, 
        ip: str, 
        node_id: Optional[str] = None,
        reason: Optional[str] = None,
        additional_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """记录解封事件
        
        Args:
            ip: 被解封的IP地址
            node_id: 节点ID
            reason: 解封原因
            additional_info: 额外信息
            
        Raises:
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(ip, str) or not ip.strip():
            raise LoggerConfigError("IP地址必须是非空字符串")
        
        if node_id is not None and not isinstance(node_id, str):
            raise LoggerConfigError("节点ID必须是字符串")
        
        if reason is not None and not isinstance(reason, str):
            raise LoggerConfigError("解封原因必须是字符串")
        
        try:
            # 验证IP地址格式（简单验证）
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                for part in ip_parts:
                    if not part.isdigit() or not 0 <= int(part) <= 255:
                        raise LoggerConfigError(f"无效的IPv4地址: {ip}")
            elif ':' not in ip:  # 简单的IPv6检查
                raise LoggerConfigError(f"无效的IP地址格式: {ip}")
            
            log_data = {
                'ip': ip,
                'node_id': node_id,
                'unban_timestamp': datetime.now().isoformat()
            }
            
            if reason:
                log_data['reason'] = reason
            
            # 添加额外信息
            if additional_info:
                try:
                    cleaned_info = self._clean_log_data(additional_info)
                    log_data.update(cleaned_info)
                except Exception as e:
                    self.logger.warning(f"清理解封日志额外数据失败: {e}")
            
            self.log_event(
                'INFO',
                'ip_unbanned',
                f"IP {ip} has been unbanned" + (f": {reason}" if reason else ""),
                **log_data
            )
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 降级记录
            try:
                self.logger.error(f"记录解封事件失败: {e}, IP: {ip}, 原因: {reason}")
            except Exception:
                pass
    
    def log_attack(
        self, 
        ip: str, 
        attack_type: str, 
        details: Optional[Dict[str, Any]] = None,
        severity: str = 'medium',
        node_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """记录攻击检测事件
        
        Args:
            ip: 攻击来源IP
            attack_type: 攻击类型 (如: 'sql_injection', 'brute_force', 'xss')
            details: 攻击详情字典
            severity: 严重程度 ('low', 'medium', 'high', 'critical')
            node_id: 节点ID
            **kwargs: 额外参数
            
        Raises:
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(ip, str) or not ip.strip():
            raise LoggerConfigError("IP地址必须是非空字符串")
        
        if not isinstance(attack_type, str) or not attack_type.strip():
            raise LoggerConfigError("攻击类型必须是非空字符串")
        
        valid_severities = {'low', 'medium', 'high', 'critical'}
        if not isinstance(severity, str) or severity not in valid_severities:
            raise LoggerConfigError(f"无效的严重程度: {severity}，支持的值: {', '.join(valid_severities)}")
        
        if details is not None and not isinstance(details, dict):
            raise LoggerConfigError("攻击详情必须是字典类型")
        
        if node_id is not None and not isinstance(node_id, str):
            raise LoggerConfigError("节点ID必须是字符串")
        
        try:
            # 验证IP地址格式（简单验证）
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                for part in ip_parts:
                    if not part.isdigit() or not 0 <= int(part) <= 255:
                        raise LoggerConfigError(f"无效的IPv4地址: {ip}")
            elif ':' not in ip:  # 简单的IPv6检查
                raise LoggerConfigError(f"无效的IP地址格式: {ip}")
            
            log_data = {
                'ip': ip,
                'attack_type': attack_type,
                'severity': severity,
                'attack_timestamp': datetime.now().isoformat(),
                'detection_source': node_id or 'unknown'
            }
            
            # 添加攻击详情
            if details:
                try:
                    cleaned_details = self._clean_log_data(details)
                    log_data['attack_details'] = cleaned_details
                except Exception as e:
                    self.logger.warning(f"清理攻击详情失败: {e}")
                    log_data['attack_details_error'] = str(e)
            
            # 添加额外参数
            if kwargs:
                try:
                    cleaned_kwargs = self._clean_log_data(kwargs)
                    log_data.update(cleaned_kwargs)
                except Exception as e:
                    self.logger.warning(f"清理攻击日志额外数据失败: {e}")
            
            # 根据严重程度选择日志级别
            level_map = {
                'low': 'INFO',
                'medium': 'WARNING',
                'high': 'ERROR',
                'critical': 'CRITICAL'
            }
            level = level_map[severity]
            
            # 构建消息
            severity_emoji = {
                'low': '🟡',
                'medium': '🟠',
                'high': '🔴',
                'critical': '🚨'
            }
            
            message = f"{severity_emoji.get(severity, '')} Attack detected from IP {ip}: {attack_type} (severity: {severity})"
            
            self.log_event(
                level,
                'attack_detected',
                message,
                **log_data
            )
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 降级记录
            try:
                self.logger.error(f"记录攻击事件失败: {e}, IP: {ip}, 类型: {attack_type}")
            except Exception:
                pass
    
    def log_system_event(
        self, 
        event: str, 
        status: str, 
        details: Optional[Dict[str, Any]] = None,
        component: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """记录系统事件
        
        Args:
            event: 事件名称 (如: 'service_start', 'config_reload', 'node_join')
            status: 事件状态 ('success', 'error', 'warning', 'critical')
            details: 事件详情字典
            component: 组件名称
            **kwargs: 额外参数
            
        Raises:
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(event, str) or not event.strip():
            raise LoggerConfigError("事件名称必须是非空字符串")
        
        valid_statuses = {'success', 'error', 'warning', 'critical', 'info'}
        if not isinstance(status, str) or status not in valid_statuses:
            raise LoggerConfigError(f"无效的事件状态: {status}，支持的值: {', '.join(valid_statuses)}")
        
        if details is not None and not isinstance(details, dict):
            raise LoggerConfigError("事件详情必须是字典类型")
        
        if component is not None and not isinstance(component, str):
            raise LoggerConfigError("组件名称必须是字符串")
        
        try:
            level_map = {
                'success': 'INFO',
                'info': 'INFO',
                'warning': 'WARNING',
                'error': 'ERROR',
                'critical': 'CRITICAL'
            }
            level = level_map.get(status, 'INFO')
            
            log_data = {
                'event': event,
                'status': status,
                'component': component,
                'system_timestamp': datetime.now().isoformat()
            }
            
            # 添加事件详情
            if details:
                try:
                    cleaned_details = self._clean_log_data(details)
                    log_data['details'] = cleaned_details
                except Exception as e:
                    self.logger.warning(f"清理系统事件详情失败: {e}")
                    log_data['details'] = {}
            else:
                log_data['details'] = {}
            
            # 添加额外参数
            if kwargs:
                try:
                    cleaned_kwargs = self._clean_log_data(kwargs)
                    log_data.update(cleaned_kwargs)
                except Exception as e:
                    self.logger.warning(f"清理系统事件额外数据失败: {e}")
            
            # 构建消息
            status_emoji = {
                'success': '✅',
                'info': 'ℹ️',
                'warning': '⚠️',
                'error': '❌',
                'critical': '🚨'
            }
            
            message = f"{status_emoji.get(status, '')} System event: {event} ({status})"
            if component:
                message += f" in {component}"
            
            self.log_event(
                level,
                'system_event',
                message,
                **log_data
            )
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 降级记录
            try:
                self.logger.error(f"记录系统事件失败: {e}, 事件: {event}, 状态: {status}")
            except Exception:
                pass
    
    def log_performance(
        self,
        metric_name: str,
        value: Union[int, float],
        unit: str = '',
        threshold: Optional[Union[int, float]] = None,
        component: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """记录性能指标
        
        Args:
            metric_name: 指标名称 (如: 'response_time', 'memory_usage', 'cpu_usage')
            value: 指标值
            unit: 单位 (如: 'ms', 'MB', '%')
            threshold: 阈值，超过此值将记录为WARNING
            component: 组件名称
            **kwargs: 额外参数
            
        Raises:
            LoggerConfigError: 参数验证失败
        """
        # 参数验证
        if not isinstance(metric_name, str) or not metric_name.strip():
            raise LoggerConfigError("指标名称必须是非空字符串")
        
        if not isinstance(value, (int, float)):
            raise LoggerConfigError("指标值必须是数字")
        
        if not isinstance(unit, str):
            raise LoggerConfigError("单位必须是字符串")
        
        if threshold is not None and not isinstance(threshold, (int, float)):
            raise LoggerConfigError("阈值必须是数字")
        
        if component is not None and not isinstance(component, str):
            raise LoggerConfigError("组件名称必须是字符串")
        
        try:
            log_data = {
                'metric_name': metric_name,
                'value': value,
                'unit': unit,
                'component': component,
                'measurement_timestamp': datetime.now().isoformat()
            }
            
            # 处理阈值
            if threshold is not None:
                log_data['threshold'] = threshold
                exceeded = value > threshold
                log_data['threshold_exceeded'] = exceeded
                
                # 计算超出百分比
                if threshold > 0:
                    percentage = ((value - threshold) / threshold) * 100
                    log_data['threshold_exceeded_percentage'] = round(percentage, 2)
                
                level = 'WARNING' if exceeded else 'INFO'
            else:
                log_data['threshold_exceeded'] = False
                level = 'INFO'
            
            # 添加额外参数
            if kwargs:
                try:
                    cleaned_kwargs = self._clean_log_data(kwargs)
                    log_data.update(cleaned_kwargs)
                except Exception as e:
                    self.logger.warning(f"清理性能指标额外数据失败: {e}")
            
            # 构建消息
            threshold_info = ""
            if threshold is not None:
                if log_data.get('threshold_exceeded', False):
                    threshold_info = f" (⚠️ 超过阈值 {threshold}{unit})"
                else:
                    threshold_info = f" (✅ 低于阈值 {threshold}{unit})"
            
            component_info = f" [{component}]" if component else ""
            message = f"📊 Performance metric{component_info} {metric_name}: {value}{unit}{threshold_info}"
            
            self.log_event(
                level,
                'performance_metric',
                message,
                **log_data
            )
            
        except LoggerConfigError:
            raise
        except Exception as e:
            # 降级记录
            try:
                self.logger.error(f"记录性能指标失败: {e}, 指标: {metric_name}, 值: {value}")
            except Exception:
                pass


class LogAnalyzer:
    """日志分析器
    
    提供日志文件分析功能，包括事件统计、趋势分析等。
    支持结构化和非结构化日志的解析。
    """
    
    def __init__(self, log_file: str) -> None:
        """初始化日志分析器
        
        Args:
            log_file: 日志文件路径
            
        Raises:
            LogAnalysisError: 日志文件不存在或无法访问
            LogFileError: 文件操作失败
        """
        if not isinstance(log_file, str) or not log_file.strip():
            raise LogAnalysisError("日志文件路径必须是非空字符串")
        
        try:
            self.log_file = Path(log_file)
            
            # 验证文件存在性和可访问性
            if not self.log_file.exists():
                raise LogFileError(f"日志文件不存在: {log_file}", log_file)
            
            if not self.log_file.is_file():
                raise LogFileError(f"路径不是文件: {log_file}", log_file)
            
            # 检查文件权限
            if not os.access(self.log_file, os.R_OK):
                raise LogFileError(f"没有读取权限: {log_file}", log_file)
            
            # 检查文件大小（防止处理过大的文件）
            file_size = self.log_file.stat().st_size
            max_size = 100 * 1024 * 1024  # 100MB
            if file_size > max_size:
                raise LogAnalysisError(f"日志文件过大: {file_size / (1024*1024):.1f}MB，最大支持: {max_size / (1024*1024)}MB")
            
            # 编译正则表达式以提高性能
            try:
                self._timestamp_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
                self._event_pattern = re.compile(r'\[([^\]]+)\]')
                self._ip_pattern = re.compile(r'\bIP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
                self._level_pattern = re.compile(r'- (DEBUG|INFO|WARNING|ERROR|CRITICAL) -')
                self._message_pattern = re.compile(r'"message":\s*"([^"]+)"')
                
                # 结构化日志的模式
                self._structured_timestamp_pattern = re.compile(r'"timestamp":\s*"([^"]+)"')
                self._structured_event_pattern = re.compile(r'"event_type":\s*"([^"]+)"')
                self._structured_ip_pattern = re.compile(r'"ip":\s*"([^"]+)"')
                
            except re.error as e:
                raise LogAnalysisError(f"编译正则表达式失败: {e}", e)
            
            # 初始化缓存
            self._cache: Dict[str, Any] = {}
            self._cache_timeout = 300  # 5分钟缓存
            self._last_modified = self.log_file.stat().st_mtime
            
        except (LogAnalysisError, LogFileError):
            raise
        except Exception as e:
            raise LogAnalysisError(f"初始化日志分析器失败: {e}", e)
    
    def get_recent_events(
        self, 
        hours: int = 24, 
        event_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """获取最近的事件
        
        Args:
            hours: 时间范围（小时），必须大于0
            event_type: 事件类型过滤 (如: 'ip_banned', 'attack_detected')
            limit: 最大返回数量，必须大于0
        
        Returns:
            事件列表，按时间倒序排列
            
        Raises:
            LogAnalysisError: 日志分析失败
            LogFileError: 文件读取失败
        """
        # 参数验证
        if not isinstance(hours, int) or hours <= 0:
            raise LogAnalysisError("时间范围必须是正整数")
        
        if hours > 8760:  # 一年
            raise LogAnalysisError("时间范围不能超过8760小时（一年）")
        
        if event_type is not None and (not isinstance(event_type, str) or not event_type.strip()):
            raise LogAnalysisError("事件类型必须是非空字符串")
        
        if limit is not None and (not isinstance(limit, int) or limit <= 0):
            raise LogAnalysisError("结果数量限制必须是正整数")
        
        if limit is not None and limit > 10000:
            raise LogAnalysisError("结果数量限制不能超过10000")
        
        try:
            # 检查文件是否被修改
            current_mtime = self.log_file.stat().st_mtime
            cache_key = f"recent_events_{hours}_{event_type}_{limit}"
            
            if (cache_key in self._cache and 
                current_mtime == self._last_modified and 
                (datetime.now() - self._cache[cache_key]['timestamp']).seconds < self._cache_timeout):
                return self._cache[cache_key]['data']
            
            events: List[Dict[str, Any]] = []
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            try:
                with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = 0
                    for line_num, line in enumerate(f, 1):
                        line_count += 1
                        if line_count > 100000:  # 限制处理的行数
                            break
                        
                        try:
                            line = line.strip()
                            if not line:
                                continue
                            
                            event = self._parse_log_line(line)
                            if not event:
                                continue
                            
                            # 时间过滤
                            if event.get('timestamp') and event['timestamp'] < cutoff_time:
                                continue
                            
                            # 事件类型过滤
                            if event_type and event.get('event_type') != event_type:
                                continue
                            
                            event['line_number'] = line_num
                            events.append(event)
                            
                            # 早期退出优化
                            if limit and len(events) >= limit * 2:
                                break
                                
                        except Exception:
                            # 记录解析错误但继续处理
                            continue
            
            except IOError as e:
                raise LogFileError(f"读取日志文件失败: {e}", str(self.log_file), e)
            
            # 按时间排序（最新的在前）
            events.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
            
            # 应用数量限制
            if limit and len(events) > limit:
                events = events[:limit]
            
            # 缓存结果
            self._cache[cache_key] = {
                'data': events,
                'timestamp': datetime.now()
            }
            self._last_modified = current_mtime
            
            return events
            
        except (LogAnalysisError, LogFileError):
            raise
        except Exception as e:
            raise LogAnalysisError(f"分析日志文件失败: {e}", e)
    
    def _parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """解析单行日志
        
        Args:
            line: 日志行，必须是非空字符串
            
        Returns:
            解析后的事件字典，如果解析失败返回None
            包含字段: timestamp, event_type, level, ip_address, message, raw_line
        """
        if not isinstance(line, str) or not line.strip():
            return None
        
        try:
            line = line.strip()
            
            # 尝试解析结构化日志（JSON格式）
            if line.startswith('{') and line.endswith('}'):
                try:
                    import json
                    data = json.loads(line)
                    
                    # 提取时间戳
                    timestamp_str = data.get('timestamp')
                    if timestamp_str:
                        try:
                            # 支持多种时间戳格式
                            if 'T' in timestamp_str:
                                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            else:
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            timestamp = datetime.now()
                    else:
                        timestamp = datetime.now()
                    
                    return {
                        'timestamp': timestamp,
                        'event_type': data.get('event_type', 'unknown'),
                        'level': data.get('level', 'INFO'),
                        'ip_address': data.get('ip') or data.get('ip_address'),
                        'message': data.get('message', line),
                        'raw_line': line,
                        'structured': True,
                        'data': data
                    }
                except (json.JSONDecodeError, ValueError):
                    # 如果JSON解析失败，继续使用正则表达式解析
                    pass
            
            # 解析传统格式日志
            # 提取时间戳
            timestamp_match = self._timestamp_pattern.match(line)
            if not timestamp_match:
                # 尝试其他时间戳格式
                alt_patterns = [
                    re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'),
                    re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'),
                    re.compile(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})')  # syslog格式
                ]
                
                timestamp = None
                for pattern in alt_patterns:
                    match = pattern.match(line)
                    if match:
                        timestamp_str = match.group(1)
                        try:
                            if '/' in timestamp_str:
                                timestamp = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
                            elif timestamp_str.startswith('['):
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            else:
                                # syslog格式，假设当前年份
                                current_year = datetime.now().year
                                timestamp = datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                            break
                        except ValueError:
                            continue
                
                if not timestamp:
                    return None
            else:
                timestamp_str = timestamp_match.group(1)
                try:
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return None
            
            # 提取事件类型
            event_type = 'unknown'
            event_match = self._event_pattern.search(line)
            if event_match:
                event_type = event_match.group(1)
            else:
                # 尝试从消息内容推断事件类型
                if 'banned' in line.lower():
                    event_type = 'ip_banned'
                elif 'unbanned' in line.lower():
                    event_type = 'ip_unbanned'
                elif 'attack' in line.lower():
                    event_type = 'attack_detected'
                elif 'system' in line.lower():
                    event_type = 'system_event'
                elif 'performance' in line.lower():
                    event_type = 'performance_metric'
            
            # 提取IP地址（支持IPv4和IPv6）
            ip_address = None
            ip_match = self._ip_pattern.search(line)
            if ip_match:
                ip_address = ip_match.group(1)
            else:
                # 尝试IPv6模式
                ipv6_pattern = re.compile(r'\b([0-9a-fA-F:]+::[0-9a-fA-F:]*|[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+)\b')
                ipv6_match = ipv6_pattern.search(line)
                if ipv6_match:
                    ip_address = ipv6_match.group(1)
            
            # 提取日志级别
            level = 'INFO'
            level_match = self._level_pattern.search(line)
            if level_match:
                level = level_match.group(1)
            else:
                # 按优先级检查级别关键词
                for log_level in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']:
                    if log_level.lower() in line.lower():
                        level = log_level
                        break
            
            # 提取消息内容
            message = line
            message_match = self._message_pattern.search(line)
            if message_match:
                message = message_match.group(1)
            
            return {
                'timestamp': timestamp,
                'event_type': event_type,
                'level': level,
                'ip_address': ip_address,
                'message': message,
                'raw_line': line,
                'structured': False
            }
            
        except Exception as e:
            # 记录解析错误但不抛出异常
            return None
    
    def get_ban_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """获取封禁统计信息
        
        Args:
            hours: 时间范围（小时），必须大于0
            
        Returns:
            封禁统计信息，包含以下字段:
            - total_bans: 总封禁数
            - total_unbans: 总解封数
            - unique_banned_ips: 唯一被封IP数
            - unique_unbanned_ips: 唯一被解封IP数
            - currently_banned: 当前仍被封禁的IP数
            - ban_reasons: 封禁原因统计
            - hourly_stats: 按小时统计
            - top_banned_ips: 被封次数最多的IP
            
        Raises:
            LogAnalysisError: 统计分析失败
        """
        # 参数验证
        if not isinstance(hours, int) or hours <= 0:
            raise LogAnalysisError("时间范围必须是正整数")
        
        if hours > 8760:  # 一年
            raise LogAnalysisError("时间范围不能超过8760小时（一年）")
        
        try:
            ban_events = self.get_recent_events(hours, 'ip_banned')
            unban_events = self.get_recent_events(hours, 'ip_unbanned')
            
            # 统计数据结构
            banned_ips: Set[str] = set()
            unbanned_ips: Set[str] = set()
            ban_reasons: Dict[str, int] = {}
            hourly_stats: Dict[str, int] = {}
            ip_ban_counts: Dict[str, int] = {}
            
            # 处理封禁事件
            for event in ban_events:
                ip = event.get('ip_address')
                if ip:
                    banned_ips.add(ip)
                    ip_ban_counts[ip] = ip_ban_counts.get(ip, 0) + 1
                    
                    # 统计封禁原因
                    try:
                        reason = self._extract_ban_reason(event.get('message', ''))
                        if reason:
                            ban_reasons[reason] = ban_reasons.get(reason, 0) + 1
                    except Exception:
                        ban_reasons['unknown'] = ban_reasons.get('unknown', 0) + 1
                    
                    # 按小时统计
                    try:
                        timestamp = event.get('timestamp')
                        if timestamp:
                            hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                            hourly_stats[hour_key] = hourly_stats.get(hour_key, 0) + 1
                    except Exception:
                        continue
            
            # 处理解封事件
            for event in unban_events:
                ip = event.get('ip_address')
                if ip:
                    unbanned_ips.add(ip)
            
            # 计算当前仍被封禁的IP
            currently_banned = banned_ips - unbanned_ips
            
            # 获取被封次数最多的IP（前10个）
            top_banned_ips = sorted(ip_ban_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # 构建统计结果
            stats = {
                'total_bans': len(ban_events),
                'total_unbans': len(unban_events),
                'unique_banned_ips': len(banned_ips),
                'unique_unbanned_ips': len(unbanned_ips),
                'currently_banned': len(currently_banned),
                'currently_banned_ips': list(currently_banned),
                'ban_reasons': ban_reasons,
                'hourly_stats': hourly_stats,
                'top_banned_ips': [{'ip': ip, 'count': count} for ip, count in top_banned_ips],
                'analysis_period_hours': hours,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            return stats
            
        except (LogAnalysisError, LogFileError):
            raise
        except Exception as e:
            raise LogAnalysisError(f"获取封禁统计失败: {e}", e)
    
    def _extract_ban_reason(self, message: str) -> str:
        """从日志消息中提取封禁原因
        
        Args:
            message: 日志消息，必须是字符串
            
        Returns:
            封禁原因字符串，如果无法提取则返回分类后的原因
        """
        if not isinstance(message, str):
            return 'Unknown'
        
        if not message.strip():
            return 'Unknown'
        
        try:
            message = message.strip()
            
            # 尝试从结构化消息中提取原因
            reason_patterns = [
                r'reason[=:]\s*["\']?([^"\',|]+)["\']?',
                r'ban_reason[=:]\s*["\']?([^"\',|]+)["\']?',
                r'因为[：:]?\s*([^，,|]+)',
                r'due to[：:]?\s*([^，,|]+)'
            ]
            
            for pattern in reason_patterns:
                match = re.search(pattern, message, re.IGNORECASE)
                if match:
                    reason = match.group(1).strip()
                    if reason and len(reason) > 2:  # 确保原因不是太短
                        return reason
            
            # 基于关键词的原因分类
            message_lower = message.lower()
            
            # SQL注入相关
            if any(keyword in message_lower for keyword in ['sql', 'injection', 'union', 'select', 'drop', 'insert']):
                return 'SQL Injection'
            
            # XSS相关
            elif any(keyword in message_lower for keyword in ['xss', 'script', 'javascript', 'onload', 'onerror']):
                return 'XSS Attack'
            
            # 路径遍历
            elif any(keyword in message_lower for keyword in ['../', '..\\', 'path traversal', 'directory traversal']):
                return 'Path Traversal'
            
            # 暴力破解
            elif any(keyword in message_lower for keyword in ['brute', 'force', 'login', 'password', 'auth']):
                return 'Brute Force'
            
            # 404错误
            elif any(keyword in message_lower for keyword in ['404', 'not found', 'missing']):
                return 'Too Many 404s'
            
            # DDoS/DoS
            elif any(keyword in message_lower for keyword in ['ddos', 'dos', 'flood', 'rate limit']):
                return 'DoS/DDoS'
            
            # 恶意爬虫
            elif any(keyword in message_lower for keyword in ['bot', 'crawler', 'spider', 'scraper']):
                return 'Malicious Bot'
            
            # 扫描器
            elif any(keyword in message_lower for keyword in ['scan', 'probe', 'vulnerability']):
                return 'Security Scanner'
            
            # 恶意文件上传
            elif any(keyword in message_lower for keyword in ['upload', 'shell', 'webshell', 'backdoor']):
                return 'Malicious Upload'
            
            # 其他恶意行为
            elif any(keyword in message_lower for keyword in ['malicious', 'suspicious', 'attack', 'exploit']):
                return 'Malicious Activity'
            
            else:
                return 'Unknown'
                
        except Exception:
            return 'Unknown'
    
    def get_attack_trends(self, hours: int = 24) -> Dict[str, Any]:
        """获取攻击趋势分析
        
        Args:
            hours: 时间范围（小时），必须大于0
            
        Returns:
            攻击趋势数据，包含以下字段:
            - total_attacks: 总攻击数
            - attack_types: 攻击类型统计
            - hourly_attack_stats: 按小时攻击统计
            - top_attackers: 攻击次数最多的IP
            - severity_distribution: 攻击严重程度分布
            - analysis_period_hours: 分析时间范围
            
        Raises:
            LogAnalysisError: 攻击趋势分析失败
        """
        # 参数验证
        if not isinstance(hours, int) or hours <= 0:
            raise LogAnalysisError("时间范围必须是正整数")
        
        if hours > 8760:  # 一年
            raise LogAnalysisError("时间范围不能超过8760小时（一年）")
        
        try:
            attack_events = self.get_recent_events(hours, 'attack_detected')
            
            attack_types: Dict[str, int] = {}
            hourly_attacks: Dict[str, int] = {}
            top_attackers: Dict[str, int] = {}
            severity_distribution: Dict[str, int] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            
            for event in attack_events:
                try:
                    # 攻击类型统计
                    attack_type = self._extract_attack_type(event.get('message', ''))
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                    
                    # 按小时统计
                    timestamp = event.get('timestamp')
                    if timestamp:
                        hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                        hourly_attacks[hour_key] = hourly_attacks.get(hour_key, 0) + 1
                    
                    # 攻击者IP统计
                    ip = event.get('ip_address')
                    if ip:
                        top_attackers[ip] = top_attackers.get(ip, 0) + 1
                    
                    # 严重程度统计
                    severity = self._extract_attack_severity(event.get('message', ''), event.get('level', 'INFO'))
                    severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
                    
                except Exception:
                    # 跳过有问题的事件但继续处理
                    continue
            
            # 排序top攻击者（前10个）
            sorted_attackers = sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:10]
            
            # 计算攻击趋势（与前一时间段比较）
            trend_direction = 'stable'
            if len(attack_events) > 0:
                # 简单的趋势计算：比较前半段和后半段的攻击数量
                mid_time = datetime.now() - timedelta(hours=hours//2)
                recent_attacks = sum(1 for event in attack_events 
                                   if event.get('timestamp') and event['timestamp'] >= mid_time)
                older_attacks = len(attack_events) - recent_attacks
                
                if recent_attacks > older_attacks * 1.2:
                    trend_direction = 'increasing'
                elif recent_attacks < older_attacks * 0.8:
                    trend_direction = 'decreasing'
            
            return {
                'total_attacks': len(attack_events),
                'attack_types': attack_types,
                'hourly_attack_stats': hourly_attacks,
                'top_attackers': [{'ip': ip, 'count': count} for ip, count in sorted_attackers],
                'severity_distribution': severity_distribution,
                'trend_direction': trend_direction,
                'analysis_period_hours': hours,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except (LogAnalysisError, LogFileError):
            raise
        except Exception as e:
            raise LogAnalysisError(f"获取攻击趋势失败: {e}", e)
    
    def _extract_attack_type(self, message: str) -> str:
        """从日志消息中提取攻击类型
        
        Args:
            message: 日志消息，必须是字符串
            
        Returns:
            攻击类型字符串，如果无法识别则返回'Other'
        """
        if not isinstance(message, str):
            return 'Other'
        
        if not message.strip():
            return 'Other'
        
        try:
            message_lower = message.lower()
            
            # SQL注入检测
            if any(keyword in message_lower for keyword in [
                'sql', 'injection', 'union', 'select', 'drop', 'insert', 
                'update', 'delete', 'exec', 'sp_', 'xp_', 'information_schema'
            ]):
                return 'SQL Injection'
            
            # XSS检测
            elif any(keyword in message_lower for keyword in [
                'xss', 'script', 'javascript', 'onload', 'onerror', 'onclick',
                'alert(', 'document.', 'window.', '<script', '</script>'
            ]):
                return 'XSS'
            
            # 路径遍历检测
            elif any(keyword in message_lower for keyword in [
                '../', '..\\', 'path traversal', 'directory traversal',
                '/etc/passwd', '/proc/', 'c:\\windows', '..%2f', '%2e%2e'
            ]):
                return 'Path Traversal'
            
            # 暴力破解检测
            elif any(keyword in message_lower for keyword in [
                'brute', 'force', 'login', 'password', 'auth', 'credential',
                'dictionary', 'wordlist', 'hydra', 'medusa'
            ]):
                return 'Brute Force'
            
            # DoS/DDoS检测
            elif any(keyword in message_lower for keyword in [
                'dos', 'ddos', 'flood', 'rate limit', 'slowloris',
                'syn flood', 'udp flood', 'amplification'
            ]):
                return 'DoS/DDoS'
            
            # 文件包含检测
            elif any(keyword in message_lower for keyword in [
                'file inclusion', 'lfi', 'rfi', 'include', 'require',
                'php://filter', 'data://', 'expect://'
            ]):
                return 'File Inclusion'
            
            # 命令注入检测
            elif any(keyword in message_lower for keyword in [
                'command injection', 'cmd', 'exec', 'system', 'shell',
                '|', '&&', '||', ';', '`', '$('
            ]):
                return 'Command Injection'
            
            # 恶意爬虫检测
            elif any(keyword in message_lower for keyword in [
                'bot', 'crawler', 'spider', 'scraper', 'scanner',
                'nikto', 'nmap', 'sqlmap', 'dirb', 'gobuster'
            ]):
                return 'Malicious Bot'
            
            # 文件上传攻击
            elif any(keyword in message_lower for keyword in [
                'upload', 'shell', 'webshell', 'backdoor', '.php',
                '.jsp', '.asp', '.aspx', 'eval(', 'base64_decode'
            ]):
                return 'Malicious Upload'
            
            # CSRF检测
            elif any(keyword in message_lower for keyword in [
                'csrf', 'cross-site request', 'forgery'
            ]):
                return 'CSRF'
            
            # 其他已知攻击
            elif any(keyword in message_lower for keyword in [
                'exploit', 'vulnerability', 'cve-', 'metasploit',
                'payload', 'shellcode', 'buffer overflow'
            ]):
                return 'Exploit'
            
            else:
                return 'Other'
                
        except Exception:
            return 'Other'
    
    def _extract_attack_severity(self, message: str, log_level: str) -> str:
        """从日志消息和级别中提取攻击严重程度
        
        Args:
            message: 日志消息
            log_level: 日志级别
            
        Returns:
            攻击严重程度: 'low', 'medium', 'high', 'critical'
        """
        if not isinstance(message, str) or not isinstance(log_level, str):
            return 'medium'
        
        try:
            message_lower = message.lower()
            level_lower = log_level.lower()
            
            # 基于日志级别的初始严重程度
            if level_lower in ['critical', 'fatal']:
                base_severity = 'critical'
            elif level_lower == 'error':
                base_severity = 'high'
            elif level_lower == 'warning':
                base_severity = 'medium'
            else:
                base_severity = 'low'
            
            # 基于攻击类型调整严重程度
            critical_keywords = [
                'sql injection', 'command injection', 'rce', 'remote code',
                'shell', 'backdoor', 'privilege escalation', 'root access'
            ]
            
            high_keywords = [
                'xss', 'csrf', 'file inclusion', 'path traversal',
                'authentication bypass', 'unauthorized access'
            ]
            
            medium_keywords = [
                'brute force', 'dos', 'ddos', 'scanner', 'probe'
            ]
            
            low_keywords = [
                '404', 'not found', 'timeout', 'connection'
            ]
            
            # 检查关键词并调整严重程度
            if any(keyword in message_lower for keyword in critical_keywords):
                return 'critical'
            elif any(keyword in message_lower for keyword in high_keywords):
                return 'high' if base_severity in ['low', 'medium'] else base_severity
            elif any(keyword in message_lower for keyword in medium_keywords):
                return 'medium' if base_severity == 'low' else base_severity
            elif any(keyword in message_lower for keyword in low_keywords):
                return 'low'
            else:
                return base_severity
                
        except Exception:
            return 'medium'


def setup_system_logging(
    log_dir: str = '/var/log/fail2ban-distributed',
    level: str = 'INFO',
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True
) -> None:
    """设置系统级日志记录
    
    Args:
        log_dir: 日志目录路径，必须是有效的目录路径字符串
        level: 日志级别，支持DEBUG、INFO、WARNING、ERROR、CRITICAL
        max_bytes: 单个日志文件最大字节数，必须是正整数，最小1MB，最大100MB
        backup_count: 备份文件数量，必须是非负整数，最大20个
        enable_console: 是否启用控制台输出
        
    Raises:
        LoggerConfigError: 系统日志设置失败
    """
    # 参数验证
    if not isinstance(log_dir, str) or not log_dir.strip():
        raise LoggerConfigError("log_dir must be a non-empty string")
    
    if not isinstance(level, str) or level.upper() not in [
        'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    ]:
        raise LoggerConfigError(
            "level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        )
    
    if not isinstance(max_bytes, int) or max_bytes < 1048576 or max_bytes > 104857600:
        raise LoggerConfigError(
            "max_bytes must be an integer between 1MB and 100MB"
        )
    
    if not isinstance(backup_count, int) or backup_count < 0 or backup_count > 20:
        raise LoggerConfigError(
            "backup_count must be a non-negative integer not exceeding 20"
        )
    
    if not isinstance(enable_console, bool):
        raise LoggerConfigError("enable_console must be a boolean")
    
    try:
        # 确保日志目录存在
        log_path = Path(log_dir).resolve()
        log_path.mkdir(parents=True, exist_ok=True)
        
        # 验证目录权限
        if not os.access(log_path, os.W_OK):
            raise LoggerConfigError(f"No write permission for log directory: {log_path}")
        
        # 设置目录权限
        try:
            os.chmod(log_path, 0o755)
        except OSError as e:
            # 记录权限设置失败，但不中断程序
            print(f"Warning: Failed to set directory permissions: {e}")
        
        # 清除现有的根日志记录器配置
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
            except Exception:
                pass
            root_logger.removeHandler(handler)
        
        # 创建处理器列表
        handlers = []
        
        # 添加文件处理器
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_path / 'system.log',
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            file_handler.setLevel(getattr(logging, level.upper()))
            handlers.append(file_handler)
        except Exception as e:
            raise LoggerConfigError(f"Failed to create file handler: {e}")
        
        # 添加控制台处理器（如果启用）
        if enable_console:
            try:
                console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(
                    '%(levelname)s: %(name)s - %(message)s'
                )
                console_handler.setFormatter(console_formatter)
                # 控制台只显示WARNING及以上级别
                console_handler.setLevel(logging.WARNING)
                handlers.append(console_handler)
            except Exception as e:
                # 控制台处理器失败不应该中断程序
                print(f"Warning: Failed to create console handler: {e}")
        
        # 配置根日志记录器
        logging.basicConfig(
            level=getattr(logging, level.upper()),
            handlers=handlers,
            force=True  # 强制重新配置
        )
        
        # 设置日志文件权限
        log_file = log_path / 'system.log'
        if log_file.exists():
            try:
                os.chmod(log_file, 0o644)
            except OSError as e:
                print(f"Warning: Failed to set log file permissions: {e}")
        
        # 记录配置成功
        root_logger.info(f"System logging configured: {log_path} (level: {level})")
        
    except Exception as e:
        if isinstance(e, LoggerConfigError):
            raise
        else:
            raise LoggerConfigError(f"设置系统日志失败: {e}") from e


def get_log_file_info(log_file: str) -> Dict[str, Any]:
    """获取日志文件信息
    
    Args:
        log_file: 日志文件路径，必须是有效的文件路径字符串
        
    Returns:
        日志文件信息字典，包含以下字段：
        - exists: 文件是否存在
        - size_bytes: 文件大小（字节）
        - size_mb: 文件大小（MB）
        - size_gb: 文件大小（GB）
        - modified_time: 最后修改时间
        - created_time: 创建时间
        - accessed_time: 最后访问时间
        - is_readable: 是否可读
        - is_writable: 是否可写
        - is_executable: 是否可执行
        - file_type: 文件类型
        - encoding: 文件编码（如果可检测）
        - line_count: 行数（如果是文本文件且小于10MB）
        - error: 错误信息（如果有）
        
    Raises:
        LogFileError: 当参数验证失败时
    """
    # 参数验证
    if not isinstance(log_file, str):
        raise LogFileError("log_file must be a string")
    
    if not log_file.strip():
        raise LogFileError("log_file cannot be empty")
    
    try:
        log_path = Path(log_file).resolve()
        
        # 基础信息
        result = {
            'path': str(log_path),
            'exists': log_path.exists(),
            'is_file': log_path.is_file() if log_path.exists() else False,
            'is_directory': log_path.is_dir() if log_path.exists() else False,
            'is_symlink': log_path.is_symlink() if log_path.exists() else False
        }
        
        if not log_path.exists():
            result.update({
                'size_bytes': 0,
                'size_mb': 0.0,
                'size_gb': 0.0,
                'is_readable': False,
                'is_writable': False,
                'is_executable': False,
                'parent_exists': log_path.parent.exists(),
                'parent_writable': os.access(log_path.parent, os.W_OK) if log_path.parent.exists() else False
            })
            return result
        
        # 文件统计信息
        try:
            stat = log_path.stat()
            size_bytes = stat.st_size
            
            result.update({
                'size_bytes': size_bytes,
                'size_mb': round(size_bytes / (1024 * 1024), 2),
                'size_gb': round(size_bytes / (1024 * 1024 * 1024), 4),
                'modified_time': datetime.fromtimestamp(stat.st_mtime),
                'created_time': datetime.fromtimestamp(stat.st_ctime),
                'accessed_time': datetime.fromtimestamp(stat.st_atime),
                'is_readable': os.access(log_path, os.R_OK),
                'is_writable': os.access(log_path, os.W_OK),
                'is_executable': os.access(log_path, os.X_OK),
                'mode': oct(stat.st_mode)[-3:],  # 文件权限
                'owner_uid': stat.st_uid,
                'group_gid': stat.st_gid
            })
        except OSError as e:
            result['stat_error'] = str(e)
        
        # 文件类型检测
        if log_path.is_file():
            try:
                suffix = log_path.suffix.lower()
                if suffix in ['.log', '.txt']:
                    result['file_type'] = 'text'
                elif suffix in ['.json']:
                    result['file_type'] = 'json'
                elif suffix in ['.xml']:
                    result['file_type'] = 'xml'
                elif suffix in ['.csv']:
                    result['file_type'] = 'csv'
                elif suffix in ['.gz', '.bz2', '.xz']:
                    result['file_type'] = 'compressed'
                else:
                    result['file_type'] = 'unknown'
            except Exception:
                result['file_type'] = 'unknown'
        
        # 编码检测（仅对小文件）
        if (log_path.is_file() and result.get('size_bytes', 0) < 1024 * 1024 and  # 小于1MB
            result.get('file_type') in ['text', 'json', 'xml', 'csv']):
            try:
                import chardet
                with open(log_path, 'rb') as f:
                    raw_data = f.read(min(8192, result.get('size_bytes', 0)))  # 读取前8KB
                    if raw_data:
                        encoding_result = chardet.detect(raw_data)
                        if encoding_result and encoding_result.get('confidence', 0) > 0.7:
                            result['encoding'] = encoding_result['encoding']
                            result['encoding_confidence'] = encoding_result['confidence']
            except (ImportError, Exception):
                # chardet不可用或检测失败
                pass
        
        # 行数统计（仅对文本文件且小于10MB）
        if (log_path.is_file() and result.get('size_bytes', 0) < 10 * 1024 * 1024 and  # 小于10MB
            result.get('file_type') in ['text', 'json', 'xml', 'csv'] and
            result.get('is_readable', False)):
            try:
                line_count = 0
                encoding = result.get('encoding', 'utf-8')
                with open(log_path, 'r', encoding=encoding, errors='ignore') as f:
                    for _ in f:
                        line_count += 1
                        if line_count > 1000000:  # 限制最大行数统计
                            result['line_count'] = f"{line_count}+"
                            break
                    else:
                        result['line_count'] = line_count
            except Exception as e:
                result['line_count_error'] = str(e)
        
        # 最近修改时间的人性化显示
        if 'modified_time' in result:
            try:
                now = datetime.now()
                modified = result['modified_time']
                diff = now - modified
                
                if diff.days > 0:
                    result['modified_ago'] = f"{diff.days} days ago"
                elif diff.seconds > 3600:
                    hours = diff.seconds // 3600
                    result['modified_ago'] = f"{hours} hours ago"
                elif diff.seconds > 60:
                    minutes = diff.seconds // 60
                    result['modified_ago'] = f"{minutes} minutes ago"
                else:
                    result['modified_ago'] = "just now"
            except Exception:
                pass
        
        return result
        
    except Exception as e:
        if isinstance(e, LogFileError):
            raise
        else:
            return {
                'exists': False, 
                'error': str(e),
                'error_type': type(e).__name__
            }


def run_logger_tests() -> None:
    """运行日志记录器的全面测试
    
    测试包括：
    1. 基础日志记录器功能
    2. 结构化日志记录
    3. 日志分析器功能
    4. 系统日志配置
    5. 文件信息获取
    6. 错误处理和边界情况
    """
    import tempfile
    import shutil
    from pathlib import Path
    
    test_results = []
    
    def log_test_result(test_name: str, success: bool, message: str = ""):
        """记录测试结果"""
        status = "✅ PASS" if success else "❌ FAIL"
        result = f"{status} {test_name}"
        if message:
            result += f": {message}"
        test_results.append((test_name, success, message))
        print(result)
    
    # 创建临时测试目录
    with tempfile.TemporaryDirectory() as temp_dir:
        test_log_file = Path(temp_dir) / 'test.log'
        
        print("🧪 开始日志记录器测试...\n")
        
        # 测试1: 基础日志记录器设置
        try:
            logger = setup_logger('test_logger', 'DEBUG', str(test_log_file))
            log_test_result("基础日志记录器设置", True)
        except Exception as e:
            log_test_result("基础日志记录器设置", False, str(e))
            return
        
        # 测试2: 结构化日志记录器
        try:
            structured_logger = StructuredLogger(logger)
            log_test_result("结构化日志记录器创建", True)
        except Exception as e:
            log_test_result("结构化日志记录器创建", False, str(e))
            return
        
        # 测试3: 各种日志记录功能
        test_cases = [
            ("普通日志记录", lambda: logger.info("测试普通日志消息")),
            ("封禁日志记录", lambda: structured_logger.log_ban(
                '192.168.1.100', 'Too many failed login attempts', 3600, 'test-node'
            )),
            ("攻击日志记录", lambda: structured_logger.log_attack(
                '10.0.0.1', 'sql_injection', {'pattern': 'UNION SELECT', 'severity': 'high'}, 'critical'
            )),
            ("系统事件日志记录", lambda: structured_logger.log_system_event(
                'service_start', 'success', {'startup_time': 2.5, 'memory_usage': '128MB'}, 'central-server'
            )),
            ("性能日志记录", lambda: structured_logger.log_performance(
                'response_time', 250, 'ms', 200
            )),
            ("解封日志记录", lambda: structured_logger.log_unban(
                '192.168.1.100', 'Manual unban by admin', 'admin-user'
            ))
        ]
        
        for test_name, test_func in test_cases:
            try:
                test_func()
                log_test_result(test_name, True)
            except Exception as e:
                log_test_result(test_name, False, str(e))
        
        # 测试4: 参数验证和错误处理
        error_test_cases = [
            ("无效IP地址处理", lambda: structured_logger.log_ban(
                'invalid_ip', 'test reason', 60, 'test-node'
            ), False),
            ("负数持续时间处理", lambda: structured_logger.log_ban(
                '192.168.1.1', 'test reason', -60, 'test-node'
            ), False),
            ("空原因处理", lambda: structured_logger.log_ban(
                '192.168.1.1', '', 60, 'test-node'
            ), False),
            ("无效性能值处理", lambda: structured_logger.log_performance(
                'test_metric', 'invalid_value', 'ms', 100
            ), False)
        ]
        
        for test_name, test_func, should_succeed in error_test_cases:
            try:
                test_func()
                log_test_result(test_name, should_succeed, "应该失败但成功了" if not should_succeed else "")
            except Exception as e:
                log_test_result(test_name, not should_succeed, str(e) if not should_succeed else f"意外错误: {e}")
        
        # 测试5: 日志分析器
        if test_log_file.exists():
            try:
                analyzer = LogAnalyzer(str(test_log_file))
                log_test_result("日志分析器创建", True)
                
                # 测试获取最近事件
                try:
                    events = analyzer.get_recent_events(24)
                    log_test_result("获取最近事件", True, f"找到 {len(events)} 个事件")
                except Exception as e:
                    log_test_result("获取最近事件", False, str(e))
                
                # 测试封禁统计
                try:
                    ban_stats = analyzer.get_ban_statistics(24)
                    log_test_result("封禁统计分析", True, f"总封禁: {ban_stats.get('total_bans', 0)}")
                except Exception as e:
                    log_test_result("封禁统计分析", False, str(e))
                
                # 测试攻击趋势
                try:
                    attack_trends = analyzer.get_attack_trends(24)
                    log_test_result("攻击趋势分析", True, f"攻击类型: {len(attack_trends.get('attack_types', {}))}")
                except Exception as e:
                    log_test_result("攻击趋势分析", False, str(e))
                    
            except Exception as e:
                log_test_result("日志分析器创建", False, str(e))
        
        # 测试6: 系统日志配置
        try:
            setup_system_logging(temp_dir, 'INFO', enable_console=False)
            log_test_result("系统日志配置", True)
        except Exception as e:
            log_test_result("系统日志配置", False, str(e))
        
        # 测试7: 文件信息获取
        try:
            file_info = get_log_file_info(str(test_log_file))
            log_test_result("日志文件信息获取", True, f"文件大小: {file_info.get('size_bytes', 0)} 字节")
        except Exception as e:
            log_test_result("日志文件信息获取", False, str(e))
        
        # 测试8: 不存在文件的信息获取
        try:
            nonexistent_file = Path(temp_dir) / 'nonexistent.log'
            file_info = get_log_file_info(str(nonexistent_file))
            success = not file_info.get('exists', True)
            log_test_result("不存在文件信息获取", success, "正确识别文件不存在" if success else "错误识别文件存在")
        except Exception as e:
            log_test_result("不存在文件信息获取", False, str(e))
    
    # 输出测试总结
    print("\n📊 测试总结:")
    total_tests = len(test_results)
    passed_tests = sum(1 for _, success, _ in test_results if success)
    failed_tests = total_tests - passed_tests
    
    print(f"总测试数: {total_tests}")
    print(f"通过: {passed_tests} ✅")
    print(f"失败: {failed_tests} ❌")
    print(f"成功率: {(passed_tests/total_tests*100):.1f}%")
    
    if failed_tests > 0:
        print("\n❌ 失败的测试:")
        for test_name, success, message in test_results:
            if not success:
                print(f"  - {test_name}: {message}")
    
    print("\n🎉 日志记录器测试完成!")


if __name__ == '__main__':
    """运行测试套件"""
    try:
        run_logger_tests()
    except KeyboardInterrupt:
        print("\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"\n💥 测试运行失败: {e}")
        import traceback
        traceback.print_exc()