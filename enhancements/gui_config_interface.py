#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 图形化配置界面

实现基于Web的配置管理系统
"""

import asyncio
import json
import logging
import os
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, Request, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, validator
import uvicorn
from passlib.context import CryptContext
import secrets


@dataclass
class ConfigSection:
    """配置节"""
    name: str
    title: str
    description: str
    fields: List[Dict[str, Any]]
    advanced: bool = False


@dataclass
class ConfigField:
    """配置字段"""
    name: str
    title: str
    field_type: str  # text, number, boolean, select, textarea, file, password
    description: str
    default_value: Any = None
    required: bool = False
    options: Optional[List[Dict[str, str]]] = None  # for select type
    validation: Optional[Dict[str, Any]] = None
    advanced: bool = False


class ConfigValidationError(Exception):
    """配置验证错误"""
    pass


class ConfigTemplate:
    """配置模板"""
    
    def __init__(self):
        self.sections = self._define_config_sections()
    
    def _define_config_sections(self) -> List[ConfigSection]:
        """定义配置节"""
        return [
            ConfigSection(
                name="general",
                title="常规设置",
                description="系统基本配置",
                fields=[
                    {
                        "name": "system_name",
                        "title": "系统名称",
                        "type": "text",
                        "description": "Fail2ban系统的显示名称",
                        "default": "分布式Fail2ban系统",
                        "required": True
                    },
                    {
                        "name": "log_level",
                        "title": "日志级别",
                        "type": "select",
                        "description": "系统日志记录级别",
                        "default": "INFO",
                        "options": [
                            {"value": "DEBUG", "label": "调试"},
                            {"value": "INFO", "label": "信息"},
                            {"value": "WARNING", "label": "警告"},
                            {"value": "ERROR", "label": "错误"},
                            {"value": "CRITICAL", "label": "严重"}
                        ],
                        "required": True
                    },
                    {
                        "name": "max_log_size",
                        "title": "最大日志文件大小(MB)",
                        "type": "number",
                        "description": "单个日志文件的最大大小",
                        "default": 100,
                        "validation": {"min": 1, "max": 1000}
                    },
                    {
                        "name": "log_retention_days",
                        "title": "日志保留天数",
                        "type": "number",
                        "description": "日志文件保留的天数",
                        "default": 30,
                        "validation": {"min": 1, "max": 365}
                    }
                ]
            ),
            ConfigSection(
                name="server",
                title="服务器设置",
                description="中央服务器配置",
                fields=[
                    {
                        "name": "host",
                        "title": "监听地址",
                        "type": "text",
                        "description": "服务器监听的IP地址",
                        "default": "0.0.0.0",
                        "required": True
                    },
                    {
                        "name": "port",
                        "title": "监听端口",
                        "type": "number",
                        "description": "服务器监听的端口号",
                        "default": 8080,
                        "required": True,
                        "validation": {"min": 1, "max": 65535}
                    },
                    {
                        "name": "workers",
                        "title": "工作进程数",
                        "type": "number",
                        "description": "服务器工作进程数量",
                        "default": 4,
                        "validation": {"min": 1, "max": 32}
                    },
                    {
                        "name": "ssl_enabled",
                        "title": "启用SSL",
                        "type": "boolean",
                        "description": "是否启用HTTPS",
                        "default": False
                    },
                    {
                        "name": "ssl_cert_file",
                        "title": "SSL证书文件",
                        "type": "file",
                        "description": "SSL证书文件路径",
                        "default": "",
                        "advanced": True
                    },
                    {
                        "name": "ssl_key_file",
                        "title": "SSL私钥文件",
                        "type": "file",
                        "description": "SSL私钥文件路径",
                        "default": "",
                        "advanced": True
                    }
                ]
            ),
            ConfigSection(
                name="database",
                title="数据库设置",
                description="数据存储配置",
                fields=[
                    {
                        "name": "type",
                        "title": "数据库类型",
                        "type": "select",
                        "description": "选择数据库类型",
                        "default": "redis",
                        "options": [
                            {"value": "redis", "label": "Redis"},
                            {"value": "mongodb", "label": "MongoDB"},
                            {"value": "sqlite", "label": "SQLite"}
                        ],
                        "required": True
                    },
                    {
                        "name": "host",
                        "title": "数据库主机",
                        "type": "text",
                        "description": "数据库服务器地址",
                        "default": "localhost"
                    },
                    {
                        "name": "port",
                        "title": "数据库端口",
                        "type": "number",
                        "description": "数据库服务器端口",
                        "default": 6379,
                        "validation": {"min": 1, "max": 65535}
                    },
                    {
                        "name": "username",
                        "title": "用户名",
                        "type": "text",
                        "description": "数据库用户名",
                        "default": ""
                    },
                    {
                        "name": "password",
                        "title": "密码",
                        "type": "password",
                        "description": "数据库密码",
                        "default": ""
                    },
                    {
                        "name": "database_name",
                        "title": "数据库名称",
                        "type": "text",
                        "description": "数据库名称",
                        "default": "fail2ban"
                    }
                ]
            ),
            ConfigSection(
                name="detection",
                title="检测设置",
                description="攻击检测配置",
                fields=[
                    {
                        "name": "enabled",
                        "title": "启用检测",
                        "type": "boolean",
                        "description": "是否启用攻击检测",
                        "default": True,
                        "required": True
                    },
                    {
                        "name": "max_attempts",
                        "title": "最大尝试次数",
                        "type": "number",
                        "description": "触发封禁的最大失败尝试次数",
                        "default": 5,
                        "validation": {"min": 1, "max": 100}
                    },
                    {
                        "name": "time_window",
                        "title": "时间窗口(秒)",
                        "type": "number",
                        "description": "检测时间窗口",
                        "default": 600,
                        "validation": {"min": 60, "max": 3600}
                    },
                    {
                        "name": "ban_duration",
                        "title": "封禁时长(秒)",
                        "type": "number",
                        "description": "IP封禁持续时间",
                        "default": 3600,
                        "validation": {"min": 60, "max": 86400}
                    },
                    {
                        "name": "whitelist_enabled",
                        "title": "启用白名单",
                        "type": "boolean",
                        "description": "是否启用IP白名单",
                        "default": True
                    },
                    {
                        "name": "whitelist_ips",
                        "title": "白名单IP",
                        "type": "textarea",
                        "description": "白名单IP地址，每行一个",
                        "default": "127.0.0.1\n::1"
                    }
                ]
            ),
            ConfigSection(
                name="ml_detection",
                title="机器学习检测",
                description="机器学习攻击检测配置",
                fields=[
                    {
                        "name": "enabled",
                        "title": "启用ML检测",
                        "type": "boolean",
                        "description": "是否启用机器学习检测",
                        "default": False
                    },
                    {
                        "name": "random_forest_enabled",
                        "title": "启用随机森林",
                        "type": "boolean",
                        "description": "是否启用随机森林模型",
                        "default": True
                    },
                    {
                        "name": "anomaly_detection_enabled",
                        "title": "启用异常检测",
                        "type": "boolean",
                        "description": "是否启用异常检测模型",
                        "default": True
                    },
                    {
                        "name": "deep_learning_enabled",
                        "title": "启用深度学习",
                        "type": "boolean",
                        "description": "是否启用深度学习模型",
                        "default": False,
                        "advanced": True
                    },
                    {
                        "name": "auto_retrain",
                        "title": "自动重训练",
                        "type": "boolean",
                        "description": "是否自动重新训练模型",
                        "default": True
                    },
                    {
                        "name": "retrain_threshold",
                        "title": "重训练阈值",
                        "type": "number",
                        "description": "触发重训练的新数据数量",
                        "default": 1000,
                        "validation": {"min": 100, "max": 10000},
                        "advanced": True
                    }
                ]
            ),
            ConfigSection(
                name="alerting",
                title="告警设置",
                description="智能告警配置",
                fields=[
                    {
                        "name": "enabled",
                        "title": "启用告警",
                        "type": "boolean",
                        "description": "是否启用告警功能",
                        "default": True
                    },
                    {
                        "name": "email_enabled",
                        "title": "启用邮件告警",
                        "type": "boolean",
                        "description": "是否启用邮件告警",
                        "default": False
                    },
                    {
                        "name": "smtp_server",
                        "title": "SMTP服务器",
                        "type": "text",
                        "description": "邮件服务器地址",
                        "default": ""
                    },
                    {
                        "name": "smtp_port",
                        "title": "SMTP端口",
                        "type": "number",
                        "description": "邮件服务器端口",
                        "default": 587,
                        "validation": {"min": 1, "max": 65535}
                    },
                    {
                        "name": "smtp_username",
                        "title": "SMTP用户名",
                        "type": "text",
                        "description": "邮件服务器用户名",
                        "default": ""
                    },
                    {
                        "name": "smtp_password",
                        "title": "SMTP密码",
                        "type": "password",
                        "description": "邮件服务器密码",
                        "default": ""
                    },
                    {
                        "name": "alert_recipients",
                        "title": "告警接收者",
                        "type": "textarea",
                        "description": "告警邮件接收者，每行一个",
                        "default": ""
                    },
                    {
                        "name": "webhook_enabled",
                        "title": "启用Webhook",
                        "type": "boolean",
                        "description": "是否启用Webhook告警",
                        "default": False,
                        "advanced": True
                    },
                    {
                        "name": "webhook_url",
                        "title": "Webhook URL",
                        "type": "text",
                        "description": "Webhook回调地址",
                        "default": "",
                        "advanced": True
                    }
                ]
            ),
            ConfigSection(
                name="monitoring",
                title="监控设置",
                description="性能监控配置",
                fields=[
                    {
                        "name": "enabled",
                        "title": "启用监控",
                        "type": "boolean",
                        "description": "是否启用性能监控",
                        "default": True
                    },
                    {
                        "name": "metrics_retention_days",
                        "title": "指标保留天数",
                        "type": "number",
                        "description": "性能指标保留天数",
                        "default": 7,
                        "validation": {"min": 1, "max": 30}
                    },
                    {
                        "name": "trace_enabled",
                        "title": "启用链路追踪",
                        "type": "boolean",
                        "description": "是否启用分布式链路追踪",
                        "default": False,
                        "advanced": True
                    },
                    {
                        "name": "trace_sampling_rate",
                        "title": "追踪采样率",
                        "type": "number",
                        "description": "链路追踪采样率(0-1)",
                        "default": 0.1,
                        "validation": {"min": 0, "max": 1},
                        "advanced": True
                    }
                ]
            ),
            ConfigSection(
                name="security",
                title="安全设置",
                description="安全审计配置",
                fields=[
                    {
                        "name": "audit_enabled",
                        "title": "启用安全审计",
                        "type": "boolean",
                        "description": "是否启用安全审计功能",
                        "default": True
                    },
                    {
                        "name": "threat_intelligence_enabled",
                        "title": "启用威胁情报",
                        "type": "boolean",
                        "description": "是否启用威胁情报检测",
                        "default": False
                    },
                    {
                        "name": "compliance_reporting",
                        "title": "合规报告",
                        "type": "select",
                        "description": "合规标准",
                        "default": "none",
                        "options": [
                            {"value": "none", "label": "无"},
                            {"value": "pci_dss", "label": "PCI DSS"},
                            {"value": "gdpr", "label": "GDPR"},
                            {"value": "hipaa", "label": "HIPAA"}
                        ],
                        "advanced": True
                    },
                    {
                        "name": "encryption_enabled",
                        "title": "启用加密",
                        "type": "boolean",
                        "description": "是否加密敏感数据",
                        "default": True,
                        "advanced": True
                    }
                ]
            )
        ]


class ConfigValidator:
    """配置验证器"""
    
    def __init__(self, template: ConfigTemplate):
        self.template = template
    
    def validate_config(self, config_data: Dict[str, Any]) -> List[str]:
        """验证配置数据
        
        Args:
            config_data: 配置数据
            
        Returns:
            错误列表
        """
        errors = []
        
        for section in self.template.sections:
            section_data = config_data.get(section.name, {})
            
            for field in section.fields:
                field_name = field["name"]
                field_value = section_data.get(field_name)
                
                # 检查必填字段
                if field.get("required", False) and not field_value:
                    errors.append(f"{section.title} - {field['title']}: 此字段为必填项")
                    continue
                
                # 类型验证
                if field_value is not None:
                    field_type = field["type"]
                    
                    if field_type == "number":
                        try:
                            value = float(field_value)
                            validation = field.get("validation", {})
                            
                            if "min" in validation and value < validation["min"]:
                                errors.append(f"{section.title} - {field['title']}: 值不能小于 {validation['min']}")
                            
                            if "max" in validation and value > validation["max"]:
                                errors.append(f"{section.title} - {field['title']}: 值不能大于 {validation['max']}")
                                
                        except (ValueError, TypeError):
                            errors.append(f"{section.title} - {field['title']}: 必须是有效的数字")
                    
                    elif field_type == "boolean":
                        if not isinstance(field_value, bool):
                            errors.append(f"{section.title} - {field['title']}: 必须是布尔值")
                    
                    elif field_type == "select":
                        options = field.get("options", [])
                        valid_values = [opt["value"] for opt in options]
                        if field_value not in valid_values:
                            errors.append(f"{section.title} - {field['title']}: 无效的选项值")
        
        return errors
    
    def validate_connectivity(self, config_data: Dict[str, Any]) -> List[str]:
        """验证连接性
        
        Args:
            config_data: 配置数据
            
        Returns:
            错误列表
        """
        errors = []
        
        # 验证数据库连接
        db_config = config_data.get("database", {})
        if db_config.get("type") == "redis":
            try:
                import redis
                r = redis.Redis(
                    host=db_config.get("host", "localhost"),
                    port=db_config.get("port", 6379),
                    password=db_config.get("password", None),
                    socket_timeout=5
                )
                r.ping()
            except Exception as e:
                errors.append(f"Redis连接失败: {str(e)}")
        
        elif db_config.get("type") == "mongodb":
            try:
                from pymongo import MongoClient
                client = MongoClient(
                    host=db_config.get("host", "localhost"),
                    port=db_config.get("port", 27017),
                    username=db_config.get("username"),
                    password=db_config.get("password"),
                    serverSelectionTimeoutMS=5000
                )
                client.server_info()
            except Exception as e:
                errors.append(f"MongoDB连接失败: {str(e)}")
        
        # 验证SMTP连接
        alerting_config = config_data.get("alerting", {})
        if alerting_config.get("email_enabled"):
            try:
                import smtplib
                server = smtplib.SMTP(
                    alerting_config.get("smtp_server"),
                    alerting_config.get("smtp_port", 587),
                    timeout=10
                )
                server.starttls()
                server.login(
                    alerting_config.get("smtp_username"),
                    alerting_config.get("smtp_password")
                )
                server.quit()
            except Exception as e:
                errors.append(f"SMTP连接失败: {str(e)}")
        
        return errors


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_file = Path(config_file)
        self.template = ConfigTemplate()
        self.validator = ConfigValidator(self.template)
        self.current_config = {}
        self.backup_dir = Path("config_backups")
        self.backup_dir.mkdir(exist_ok=True)
        
        # 加载当前配置
        self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.current_config = yaml.safe_load(f) or {}
            except Exception as e:
                logging.error(f"加载配置文件失败: {e}")
                self.current_config = {}
        else:
            # 使用默认配置
            self.current_config = self.get_default_config()
        
        return self.current_config
    
    def save_config(self, config_data: Dict[str, Any], create_backup: bool = True) -> None:
        """保存配置文件
        
        Args:
            config_data: 配置数据
            create_backup: 是否创建备份
        """
        # 验证配置
        errors = self.validator.validate_config(config_data)
        if errors:
            raise ConfigValidationError("\n".join(errors))
        
        # 创建备份
        if create_backup and self.config_file.exists():
            backup_file = self.backup_dir / f"config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
            backup_file.write_text(self.config_file.read_text(encoding='utf-8'), encoding='utf-8')
        
        # 保存新配置
        with open(self.config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
        
        self.current_config = config_data
    
    def get_default_config(self) -> Dict[str, Any]:
        """获取默认配置"""
        config = {}
        
        for section in self.template.sections:
            section_config = {}
            for field in section.fields:
                section_config[field["name"]] = field.get("default")
            config[section.name] = section_config
        
        return config
    
    def get_config_schema(self) -> Dict[str, Any]:
        """获取配置模式"""
        return {
            "sections": [asdict(section) for section in self.template.sections]
        }
    
    def import_config(self, file_path: str) -> None:
        """导入配置文件
        
        Args:
            file_path: 配置文件路径
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            if file_path.endswith('.json'):
                config_data = json.load(f)
            else:
                config_data = yaml.safe_load(f)
        
        self.save_config(config_data)
    
    def export_config(self, file_path: str, format_type: str = "yaml") -> None:
        """导出配置文件
        
        Args:
            file_path: 导出文件路径
            format_type: 格式类型 (yaml/json)
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            if format_type == "json":
                json.dump(self.current_config, f, ensure_ascii=False, indent=2)
            else:
                yaml.dump(self.current_config, f, default_flow_style=False, allow_unicode=True)
    
    def get_backups(self) -> List[Dict[str, Any]]:
        """获取备份列表"""
        backups = []
        
        for backup_file in self.backup_dir.glob("config_*.yaml"):
            stat = backup_file.stat()
            backups.append({
                "filename": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        return sorted(backups, key=lambda x: x["created_time"], reverse=True)
    
    def restore_backup(self, backup_filename: str) -> None:
        """恢复备份
        
        Args:
            backup_filename: 备份文件名
        """
        backup_file = self.backup_dir / backup_filename
        if not backup_file.exists():
            raise FileNotFoundError(f"备份文件不存在: {backup_filename}")
        
        with open(backup_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        self.save_config(config_data, create_backup=False)


class GUIConfigInterface:
    """图形化配置界面"""
    
    def __init__(self, config_file: str = "config.yaml"):
        self.config_manager = ConfigManager(config_file)
        self.app = FastAPI(title="Fail2ban配置管理", version="1.0.0")
        self.templates = Jinja2Templates(directory="templates")
        self.security = HTTPBasic()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # 管理员凭据（实际应用中应该从配置文件或数据库读取）
        self.admin_credentials = {
            "admin": self.pwd_context.hash("admin123")  # 默认密码，应该修改
        }
        
        self._setup_routes()
        self._setup_static_files()
    
    def _setup_static_files(self) -> None:
        """设置静态文件"""
        static_dir = Path("static")
        static_dir.mkdir(exist_ok=True)
        
        # 创建基本的CSS文件
        css_content = """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
            margin-bottom: 2rem;
        }
        
        .nav {
            background-color: #34495e;
            padding: 0.5rem;
            margin-bottom: 2rem;
        }
        
        .nav a {
            color: white;
            text-decoration: none;
            padding: 0.5rem 1rem;
            margin-right: 1rem;
            border-radius: 4px;
        }
        
        .nav a:hover {
            background-color: #2c3e50;
        }
        
        .section {
            background-color: white;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        .form-group textarea {
            height: 100px;
            resize: vertical;
        }
        
        .btn {
            background-color: #3498db;
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin-right: 0.5rem;
        }
        
        .btn:hover {
            background-color: #2980b9;
        }
        
        .btn-success {
            background-color: #27ae60;
        }
        
        .btn-success:hover {
            background-color: #229954;
        }
        
        .btn-danger {
            background-color: #e74c3c;
        }
        
        .btn-danger:hover {
            background-color: #c0392b;
        }
        
        .alert {
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 4px;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .advanced {
            border-left: 3px solid #f39c12;
            padding-left: 1rem;
            margin-top: 1rem;
        }
        
        .toggle-advanced {
            background-color: #f39c12;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 1rem;
        }
        
        .hidden {
            display: none;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        
        .status-ok {
            background-color: #27ae60;
        }
        
        .status-error {
            background-color: #e74c3c;
        }
        
        .status-warning {
            background-color: #f39c12;
        }
        """
        
        (static_dir / "style.css").write_text(css_content, encoding='utf-8')
        
        self.app.mount("/static", StaticFiles(directory="static"), name="static")
    
    def _authenticate_user(self, credentials: HTTPBasicCredentials) -> bool:
        """验证用户凭据"""
        username = credentials.username
        password = credentials.password
        
        if username in self.admin_credentials:
            return self.pwd_context.verify(password, self.admin_credentials[username])
        
        return False
    
    def _setup_routes(self) -> None:
        """设置路由"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "config": self.config_manager.current_config,
                "sections": self.config_manager.template.sections
            })
        
        @self.app.get("/config", response_class=HTMLResponse)
        async def config_page(request: Request, credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            return self.templates.TemplateResponse("config.html", {
                "request": request,
                "config": self.config_manager.current_config,
                "sections": self.config_manager.template.sections
            })
        
        @self.app.post("/config/save")
        async def save_config(request: Request, credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            form_data = await request.form()
            config_data = {}
            
            # 解析表单数据
            for section in self.config_manager.template.sections:
                section_data = {}
                for field in section.fields:
                    field_name = f"{section.name}_{field['name']}"
                    field_value = form_data.get(field_name)
                    
                    if field_value is not None:
                        # 类型转换
                        if field["type"] == "number":
                            try:
                                field_value = float(field_value)
                                if field_value.is_integer():
                                    field_value = int(field_value)
                            except ValueError:
                                field_value = field.get("default", 0)
                        elif field["type"] == "boolean":
                            field_value = field_value == "on"
                        
                        section_data[field["name"]] = field_value
                
                config_data[section.name] = section_data
            
            try:
                self.config_manager.save_config(config_data)
                return JSONResponse({"success": True, "message": "配置保存成功"})
            except ConfigValidationError as e:
                return JSONResponse({"success": False, "message": str(e)}, status_code=400)
            except Exception as e:
                return JSONResponse({"success": False, "message": f"保存失败: {str(e)}"}, status_code=500)
        
        @self.app.get("/config/validate")
        async def validate_config(credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            errors = self.config_manager.validator.validate_config(self.config_manager.current_config)
            connectivity_errors = self.config_manager.validator.validate_connectivity(self.config_manager.current_config)
            
            return JSONResponse({
                "validation_errors": errors,
                "connectivity_errors": connectivity_errors,
                "is_valid": len(errors) == 0 and len(connectivity_errors) == 0
            })
        
        @self.app.get("/config/export")
        async def export_config(format_type: str = "yaml", credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            if format_type == "json":
                content = json.dumps(self.config_manager.current_config, ensure_ascii=False, indent=2)
                media_type = "application/json"
                filename = "config.json"
            else:
                content = yaml.dump(self.config_manager.current_config, default_flow_style=False, allow_unicode=True)
                media_type = "application/x-yaml"
                filename = "config.yaml"
            
            return Response(
                content=content,
                media_type=media_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        
        @self.app.post("/config/import")
        async def import_config(file: UploadFile = File(...), credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            try:
                content = await file.read()
                content_str = content.decode('utf-8')
                
                if file.filename.endswith('.json'):
                    config_data = json.loads(content_str)
                else:
                    config_data = yaml.safe_load(content_str)
                
                self.config_manager.save_config(config_data)
                return JSONResponse({"success": True, "message": "配置导入成功"})
                
            except Exception as e:
                return JSONResponse({"success": False, "message": f"导入失败: {str(e)}"}, status_code=400)
        
        @self.app.get("/backups")
        async def get_backups(credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            backups = self.config_manager.get_backups()
            return JSONResponse(backups)
        
        @self.app.post("/backups/restore/{backup_filename}")
        async def restore_backup(backup_filename: str, credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            try:
                self.config_manager.restore_backup(backup_filename)
                return JSONResponse({"success": True, "message": "备份恢复成功"})
            except Exception as e:
                return JSONResponse({"success": False, "message": f"恢复失败: {str(e)}"}, status_code=400)
        
        @self.app.get("/api/config")
        async def get_config_api(credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            return JSONResponse(self.config_manager.current_config)
        
        @self.app.get("/api/schema")
        async def get_schema_api(credentials: HTTPBasicCredentials = Depends(self.security)):
            if not self._authenticate_user(credentials):
                raise HTTPException(status_code=401, detail="认证失败")
            
            return JSONResponse(self.config_manager.get_config_schema())
    
    def create_templates(self) -> None:
        """创建模板文件"""
        templates_dir = Path("templates")
        templates_dir.mkdir(exist_ok=True)
        
        # 基础模板
        base_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Fail2ban配置管理{% endblock %}</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="header">
        <h1>分布式Fail2ban系统 - 配置管理</h1>
    </div>
    
    <div class="nav">
        <a href="/">仪表板</a>
        <a href="/config">配置管理</a>
        <a href="/backups">备份管理</a>
    </div>
    
    <div class="container">
        {% block content %}{% endblock %}
    </div>
    
    <script>
        function toggleAdvanced() {
            const advancedSections = document.querySelectorAll('.advanced');
            advancedSections.forEach(section => {
                section.classList.toggle('hidden');
            });
        }
        
        function validateConfig() {
            fetch('/config/validate')
                .then(response => response.json())
                .then(data => {
                    const alertDiv = document.getElementById('validation-alert');
                    if (data.is_valid) {
                        alertDiv.innerHTML = '<div class="alert alert-success">配置验证通过</div>';
                    } else {
                        const errors = [...data.validation_errors, ...data.connectivity_errors];
                        alertDiv.innerHTML = '<div class="alert alert-error">配置验证失败:<br>' + errors.join('<br>') + '</div>';
                    }
                });
        }
        
        function saveConfig() {
            const form = document.getElementById('config-form');
            const formData = new FormData(form);
            
            fetch('/config/save', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const alertDiv = document.getElementById('save-alert');
                if (data.success) {
                    alertDiv.innerHTML = '<div class="alert alert-success">' + data.message + '</div>';
                } else {
                    alertDiv.innerHTML = '<div class="alert alert-error">' + data.message + '</div>';
                }
            });
        }
    </script>
</body>
</html>
        """
        
        # 仪表板模板
        dashboard_template = """
{% extends "base.html" %}

{% block title %}仪表板 - Fail2ban配置管理{% endblock %}

{% block content %}
<div class="section">
    <h2>系统状态</h2>
    <div id="system-status">
        <p><span class="status-indicator status-ok"></span>系统运行正常</p>
        <p><span class="status-indicator status-ok"></span>配置文件有效</p>
        <p><span class="status-indicator status-warning"></span>部分功能未启用</p>
    </div>
</div>

<div class="section">
    <h2>快速操作</h2>
    <button class="btn" onclick="validateConfig()">验证配置</button>
    <button class="btn btn-success" onclick="location.href='/config'">编辑配置</button>
    <button class="btn" onclick="location.href='/config/export'">导出配置</button>
</div>

<div id="validation-alert"></div>

<div class="section">
    <h2>配置概览</h2>
    {% for section in sections %}
    <div class="form-group">
        <h3>{{ section.title }}</h3>
        <p>{{ section.description }}</p>
    </div>
    {% endfor %}
</div>
{% endblock %}
        """
        
        # 配置页面模板
        config_template = """
{% extends "base.html" %}

{% block title %}配置管理 - Fail2ban配置管理{% endblock %}

{% block content %}
<div class="section">
    <h2>配置管理</h2>
    <button class="toggle-advanced" onclick="toggleAdvanced()">显示/隐藏高级选项</button>
    <button class="btn" onclick="validateConfig()">验证配置</button>
    <button class="btn btn-success" onclick="saveConfig()">保存配置</button>
</div>

<div id="save-alert"></div>
<div id="validation-alert"></div>

<form id="config-form">
    {% for section in sections %}
    <div class="section">
        <h3>{{ section.title }}</h3>
        <p>{{ section.description }}</p>
        
        {% for field in section.fields %}
        <div class="form-group {% if field.advanced %}advanced hidden{% endif %}">
            <label for="{{ section.name }}_{{ field.name }}">{{ field.title }}</label>
            
            {% if field.type == 'text' or field.type == 'password' %}
            <input type="{{ field.type }}" 
                   id="{{ section.name }}_{{ field.name }}" 
                   name="{{ section.name }}_{{ field.name }}" 
                   value="{{ config.get(section.name, {}).get(field.name, field.default) or '' }}"
                   {% if field.required %}required{% endif %}>
            
            {% elif field.type == 'number' %}
            <input type="number" 
                   id="{{ section.name }}_{{ field.name }}" 
                   name="{{ section.name }}_{{ field.name }}" 
                   value="{{ config.get(section.name, {}).get(field.name, field.default) or '' }}"
                   {% if field.validation and field.validation.min %}min="{{ field.validation.min }}"{% endif %}
                   {% if field.validation and field.validation.max %}max="{{ field.validation.max }}"{% endif %}
                   {% if field.required %}required{% endif %}>
            
            {% elif field.type == 'boolean' %}
            <input type="checkbox" 
                   id="{{ section.name }}_{{ field.name }}" 
                   name="{{ section.name }}_{{ field.name }}"
                   {% if config.get(section.name, {}).get(field.name, field.default) %}checked{% endif %}>
            
            {% elif field.type == 'select' %}
            <select id="{{ section.name }}_{{ field.name }}" 
                    name="{{ section.name }}_{{ field.name }}"
                    {% if field.required %}required{% endif %}>
                {% for option in field.options %}
                <option value="{{ option.value }}"
                        {% if config.get(section.name, {}).get(field.name, field.default) == option.value %}selected{% endif %}>
                    {{ option.label }}
                </option>
                {% endfor %}
            </select>
            
            {% elif field.type == 'textarea' %}
            <textarea id="{{ section.name }}_{{ field.name }}" 
                      name="{{ section.name }}_{{ field.name }}"
                      {% if field.required %}required{% endif %}>{{ config.get(section.name, {}).get(field.name, field.default) or '' }}</textarea>
            
            {% elif field.type == 'file' %}
            <input type="text" 
                   id="{{ section.name }}_{{ field.name }}" 
                   name="{{ section.name }}_{{ field.name }}" 
                   value="{{ config.get(section.name, {}).get(field.name, field.default) or '' }}"
                   placeholder="文件路径">
            {% endif %}
            
            <small>{{ field.description }}</small>
        </div>
        {% endfor %}
    </div>
    {% endfor %}
</form>
{% endblock %}
        """
        
        # 写入模板文件
        (templates_dir / "base.html").write_text(base_template, encoding='utf-8')
        (templates_dir / "dashboard.html").write_text(dashboard_template, encoding='utf-8')
        (templates_dir / "config.html").write_text(config_template, encoding='utf-8')
    
    def run(self, host: str = "0.0.0.0", port: int = 8081, debug: bool = False) -> None:
        """运行配置界面
        
        Args:
            host: 监听地址
            port: 监听端口
            debug: 调试模式
        """
        # 创建必要的目录和文件
        self.create_templates()
        
        # 启动服务器
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="debug" if debug else "info"
        )


if __name__ == "__main__":
    # 示例用法
    gui = GUIConfigInterface()
    gui.run(debug=True)