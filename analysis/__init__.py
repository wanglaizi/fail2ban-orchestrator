#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 分析模块

该模块包含攻击模式检测和IP行为分析功能
"""

from .pattern_detector import PatternDetector, AdvancedPatternDetector
from .ip_analyzer import IPAnalyzer

__all__ = [
    'PatternDetector',
    'AdvancedPatternDetector', 
    'IPAnalyzer'
]

__version__ = '1.0.0'
__author__ = 'Distributed Fail2ban System'
__description__ = '分布式Fail2ban系统分析模块'