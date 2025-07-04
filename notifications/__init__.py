#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 通知模块

该模块提供多种通知方式，包括邮件、钉钉、企业微信、Slack等
"""

from .notifier import (
    BaseNotifier,
    EmailNotifier,
    DingTalkNotifier,
    WeChatNotifier,
    SlackNotifier,
    NotificationManager
)

__all__ = [
    'BaseNotifier',
    'EmailNotifier',
    'DingTalkNotifier',
    'WeChatNotifier',
    'SlackNotifier',
    'NotificationManager'
]

__version__ = '1.0.0'
__author__ = 'Distributed Fail2ban System'
__description__ = '分布式Fail2ban系统通知模块'