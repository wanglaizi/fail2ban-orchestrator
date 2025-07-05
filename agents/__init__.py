#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 代理模块

提供日志收集代理和其他代理功能。
"""

__version__ = "1.0.0"
__author__ = "Fail2ban开发团队"

# 导出主要的类
try:
    from .log_agent import LogAgent
    
    __all__ = [
        'LogAgent'
    ]
except ImportError as e:
    # 如果某些模块不存在，只导出可用的
    __all__ = []
    print(f"警告: 部分代理模块导入失败: {e}")