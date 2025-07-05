#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 智能告警系统

实现基于机器学习的智能告警和动态阈值调整
"""

import asyncio
import json
import logging
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import pickle
from pathlib import Path

# 机器学习相关
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
from sklearn.metrics import classification_report
import pandas as pd


class AlertSeverity(Enum):
    """告警严重级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """告警类型"""
    ATTACK_DETECTED = "attack_detected"
    ANOMALY_DETECTED = "anomaly_detected"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    SYSTEM_HEALTH = "system_health"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    SECURITY_BREACH = "security_breach"


@dataclass
class Alert:
    """告警数据结构"""
    id: str
    type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    source_ip: Optional[str]
    node_id: str
    timestamp: datetime
    metadata: Dict[str, Any]
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None


class DynamicThreshold:
    """动态阈值管理器"""
    
    def __init__(self, metric_name: str, initial_value: float, 
                 sensitivity: float = 0.1, adaptation_rate: float = 0.05):
        self.metric_name = metric_name
        self.current_threshold = initial_value
        self.sensitivity = sensitivity  # 敏感度
        self.adaptation_rate = adaptation_rate  # 适应速率
        self.history = deque(maxlen=1000)  # 历史数据
        self.baseline = initial_value
        self.last_update = datetime.now()
        
    def update(self, value: float, is_anomaly: bool = False) -> None:
        """更新阈值
        
        Args:
            value: 新的度量值
            is_anomaly: 是否为异常值
        """
        self.history.append({
            'value': value,
            'timestamp': datetime.now(),
            'is_anomaly': is_anomaly
        })
        
        # 计算新的基线
        if len(self.history) >= 10:
            recent_normal_values = [
                h['value'] for h in list(self.history)[-50:] 
                if not h['is_anomaly']
            ]
            
            if recent_normal_values:
                new_baseline = np.mean(recent_normal_values)
                std_dev = np.std(recent_normal_values)
                
                # 动态调整阈值
                self.baseline = (
                    self.baseline * (1 - self.adaptation_rate) + 
                    new_baseline * self.adaptation_rate
                )
                
                # 基于标准差调整阈值
                self.current_threshold = self.baseline + (std_dev * self.sensitivity)
                
        self.last_update = datetime.now()
    
    def is_exceeded(self, value: float) -> bool:
        """检查是否超过阈值"""
        return value > self.current_threshold
    
    def get_status(self) -> Dict[str, Any]:
        """获取阈值状态"""
        return {
            'metric_name': self.metric_name,
            'current_threshold': self.current_threshold,
            'baseline': self.baseline,
            'sensitivity': self.sensitivity,
            'adaptation_rate': self.adaptation_rate,
            'history_size': len(self.history),
            'last_update': self.last_update.isoformat()
        }


class AnomalyDetector:
    """异常检测器"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = model_path
        self.feature_names = [
            'request_rate', 'error_rate', 'unique_paths', 
            'user_agent_diversity', 'status_4xx_rate', 
            'attack_frequency', 'response_time'
        ]
        
        # 加载已训练的模型
        if model_path and Path(model_path).exists():
            self.load_model()
    
    def extract_features(self, ip_behavior: Dict[str, Any]) -> np.ndarray:
        """提取特征向量
        
        Args:
            ip_behavior: IP行为数据
            
        Returns:
            特征向量
        """
        # 计算时间窗口（最近1小时）
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        recent_attacks = [
            attack for attack in ip_behavior.get('recent_attacks', [])
            if attack['timestamp'] > hour_ago
        ]
        
        # 提取特征
        features = [
            ip_behavior.get('request_count', 0) / 3600,  # 每秒请求率
            len([a for a in recent_attacks if a.get('status', 200) >= 400]) / max(len(recent_attacks), 1),  # 错误率
            len(ip_behavior.get('paths', set())),  # 唯一路径数
            len(ip_behavior.get('user_agents', set())),  # User-Agent多样性
            sum(1 for code in ip_behavior.get('status_codes', {}).keys() if 400 <= code < 500) / max(ip_behavior.get('request_count', 1), 1),  # 4xx状态码率
            len(recent_attacks) / 3600,  # 攻击频率
            ip_behavior.get('avg_response_time', 0)  # 平均响应时间
        ]
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]]) -> None:
        """训练异常检测模型
        
        Args:
            training_data: 训练数据
        """
        if len(training_data) < 10:
            logging.warning("训练数据不足，无法训练异常检测模型")
            return
        
        # 提取特征
        features = []
        for data in training_data:
            feature_vector = self.extract_features(data)
            features.append(feature_vector.flatten())
        
        features_array = np.array(features)
        
        # 标准化特征
        features_scaled = self.scaler.fit_transform(features_array)
        
        # 训练模型
        self.isolation_forest.fit(features_scaled)
        self.is_trained = True
        
        # 保存模型
        if self.model_path:
            self.save_model()
        
        logging.info(f"异常检测模型训练完成，使用 {len(training_data)} 个样本")
    
    def detect_anomaly(self, ip_behavior: Dict[str, Any]) -> Tuple[bool, float]:
        """检测异常
        
        Args:
            ip_behavior: IP行为数据
            
        Returns:
            (是否异常, 异常分数)
        """
        if not self.is_trained:
            return False, 0.0
        
        # 提取特征
        features = self.extract_features(ip_behavior)
        features_scaled = self.scaler.transform(features)
        
        # 预测
        prediction = self.isolation_forest.predict(features_scaled)[0]
        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        
        is_anomaly = prediction == -1
        
        return is_anomaly, abs(anomaly_score)
    
    def save_model(self) -> None:
        """保存模型"""
        if not self.model_path:
            return
        
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self) -> None:
        """加载模型"""
        if not self.model_path or not Path(self.model_path).exists():
            return
        
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            self.feature_names = model_data.get('feature_names', self.feature_names)
            
            logging.info("异常检测模型加载成功")
        except Exception as e:
            logging.error(f"加载异常检测模型失败: {e}")


class IntelligentAlertingSystem:
    """智能告警系统"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alert_config = config.get('alerting', {})
        self.logger = logging.getLogger(__name__)
        
        # 告警存储
        self.alerts: Dict[str, Alert] = {}
        self.alert_history = deque(maxlen=10000)
        
        # 动态阈值管理
        self.thresholds: Dict[str, DynamicThreshold] = {}
        self._initialize_thresholds()
        
        # 异常检测
        model_path = self.alert_config.get('anomaly_model_path', 'models/anomaly_detector.pkl')
        self.anomaly_detector = AnomalyDetector(model_path)
        
        # 告警抑制和聚合
        self.alert_suppression = defaultdict(datetime)
        self.alert_aggregation = defaultdict(list)
        
        # 通知渠道
        self.notification_channels = []
        self._initialize_notification_channels()
        
        # 统计信息
        self.stats = {
            'total_alerts': 0,
            'alerts_by_severity': defaultdict(int),
            'alerts_by_type': defaultdict(int),
            'false_positive_rate': 0.0,
            'resolution_time_avg': 0.0
        }
    
    def _initialize_thresholds(self) -> None:
        """初始化动态阈值"""
        threshold_config = self.alert_config.get('thresholds', {})
        
        default_thresholds = {
            'request_rate': 100,
            'error_rate': 0.1,
            'attack_frequency': 10,
            'response_time': 1000,
            'cpu_usage': 80,
            'memory_usage': 85,
            'disk_usage': 90
        }
        
        for metric, default_value in default_thresholds.items():
            config_value = threshold_config.get(metric, default_value)
            sensitivity = threshold_config.get(f'{metric}_sensitivity', 0.1)
            adaptation_rate = threshold_config.get(f'{metric}_adaptation_rate', 0.05)
            
            self.thresholds[metric] = DynamicThreshold(
                metric, config_value, sensitivity, adaptation_rate
            )
    
    def _initialize_notification_channels(self) -> None:
        """初始化通知渠道"""
        # 这里可以添加各种通知渠道的初始化
        # 如邮件、Slack、微信、钉钉等
        pass
    
    async def process_event(self, event: Dict[str, Any]) -> Optional[Alert]:
        """处理事件并生成告警
        
        Args:
            event: 事件数据
            
        Returns:
            生成的告警（如果有）
        """
        try:
            # 更新动态阈值
            await self._update_thresholds(event)
            
            # 检查阈值告警
            threshold_alert = await self._check_threshold_alerts(event)
            if threshold_alert:
                return await self._create_alert(threshold_alert)
            
            # 异常检测
            anomaly_alert = await self._check_anomaly_alerts(event)
            if anomaly_alert:
                return await self._create_alert(anomaly_alert)
            
            # 攻击检测告警
            attack_alert = await self._check_attack_alerts(event)
            if attack_alert:
                return await self._create_alert(attack_alert)
            
            # 系统健康告警
            health_alert = await self._check_system_health_alerts(event)
            if health_alert:
                return await self._create_alert(health_alert)
            
            return None
            
        except Exception as e:
            self.logger.error(f"处理事件时发生错误: {e}")
            return None
    
    async def _update_thresholds(self, event: Dict[str, Any]) -> None:
        """更新动态阈值"""
        metrics = event.get('metrics', {})
        
        for metric_name, value in metrics.items():
            if metric_name in self.thresholds:
                is_anomaly = event.get('is_anomaly', False)
                self.thresholds[metric_name].update(value, is_anomaly)
    
    async def _check_threshold_alerts(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检查阈值告警"""
        metrics = event.get('metrics', {})
        
        for metric_name, value in metrics.items():
            if metric_name in self.thresholds:
                threshold = self.thresholds[metric_name]
                
                if threshold.is_exceeded(value):
                    # 检查告警抑制
                    suppression_key = f"threshold_{metric_name}_{event.get('source_ip', 'unknown')}"
                    if self._should_suppress_alert(suppression_key):
                        continue
                    
                    severity = self._calculate_severity(metric_name, value, threshold.current_threshold)
                    
                    return {
                        'type': AlertType.THRESHOLD_EXCEEDED,
                        'severity': severity,
                        'title': f'{metric_name}阈值超限',
                        'description': f'{metric_name}当前值{value}超过阈值{threshold.current_threshold:.2f}',
                        'source_ip': event.get('source_ip'),
                        'metadata': {
                            'metric_name': metric_name,
                            'current_value': value,
                            'threshold': threshold.current_threshold,
                            'baseline': threshold.baseline
                        }
                    }
        
        return None
    
    async def _check_anomaly_alerts(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检查异常告警"""
        ip_behavior = event.get('ip_behavior')
        if not ip_behavior:
            return None
        
        is_anomaly, anomaly_score = self.anomaly_detector.detect_anomaly(ip_behavior)
        
        if is_anomaly and anomaly_score > 0.5:  # 异常分数阈值
            source_ip = event.get('source_ip')
            suppression_key = f"anomaly_{source_ip}"
            
            if self._should_suppress_alert(suppression_key):
                return None
            
            severity = AlertSeverity.HIGH if anomaly_score > 0.8 else AlertSeverity.MEDIUM
            
            return {
                'type': AlertType.ANOMALY_DETECTED,
                'severity': severity,
                'title': 'IP行为异常检测',
                'description': f'IP {source_ip} 检测到异常行为，异常分数: {anomaly_score:.3f}',
                'source_ip': source_ip,
                'metadata': {
                    'anomaly_score': anomaly_score,
                    'ip_behavior': ip_behavior
                }
            }
        
        return None
    
    async def _check_attack_alerts(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检查攻击告警"""
        attack_type = event.get('attack_type')
        if not attack_type:
            return None
        
        source_ip = event.get('source_ip')
        suppression_key = f"attack_{attack_type}_{source_ip}"
        
        if self._should_suppress_alert(suppression_key):
            return None
        
        # 根据攻击类型确定严重级别
        severity_mapping = {
            'sql_injection': AlertSeverity.CRITICAL,
            'xss': AlertSeverity.HIGH,
            'brute_force': AlertSeverity.HIGH,
            'directory_traversal': AlertSeverity.HIGH,
            'command_injection': AlertSeverity.CRITICAL,
            'file_inclusion': AlertSeverity.HIGH,
            'csrf': AlertSeverity.MEDIUM,
            'dos': AlertSeverity.HIGH
        }
        
        severity = severity_mapping.get(attack_type.lower(), AlertSeverity.MEDIUM)
        
        return {
            'type': AlertType.ATTACK_DETECTED,
            'severity': severity,
            'title': f'{attack_type}攻击检测',
            'description': f'检测到来自IP {source_ip}的{attack_type}攻击',
            'source_ip': source_ip,
            'metadata': {
                'attack_type': attack_type,
                'attack_details': event.get('attack_details', {})
            }
        }
    
    async def _check_system_health_alerts(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """检查系统健康告警"""
        system_metrics = event.get('system_metrics', {})
        
        # 检查CPU使用率
        cpu_usage = system_metrics.get('cpu_usage')
        if cpu_usage and cpu_usage > 90:
            return {
                'type': AlertType.SYSTEM_HEALTH,
                'severity': AlertSeverity.HIGH,
                'title': 'CPU使用率过高',
                'description': f'系统CPU使用率达到{cpu_usage}%',
                'source_ip': None,
                'metadata': {'cpu_usage': cpu_usage}
            }
        
        # 检查内存使用率
        memory_usage = system_metrics.get('memory_usage')
        if memory_usage and memory_usage > 95:
            return {
                'type': AlertType.SYSTEM_HEALTH,
                'severity': AlertSeverity.CRITICAL,
                'title': '内存使用率过高',
                'description': f'系统内存使用率达到{memory_usage}%',
                'source_ip': None,
                'metadata': {'memory_usage': memory_usage}
            }
        
        return None
    
    def _should_suppress_alert(self, suppression_key: str, 
                              suppression_window: int = 300) -> bool:
        """检查是否应该抑制告警
        
        Args:
            suppression_key: 抑制键
            suppression_window: 抑制窗口（秒）
            
        Returns:
            是否应该抑制
        """
        now = datetime.now()
        last_alert_time = self.alert_suppression.get(suppression_key)
        
        if last_alert_time and (now - last_alert_time).total_seconds() < suppression_window:
            return True
        
        self.alert_suppression[suppression_key] = now
        return False
    
    def _calculate_severity(self, metric_name: str, value: float, threshold: float) -> AlertSeverity:
        """计算告警严重级别"""
        ratio = value / threshold
        
        if ratio >= 2.0:
            return AlertSeverity.CRITICAL
        elif ratio >= 1.5:
            return AlertSeverity.HIGH
        elif ratio >= 1.2:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    async def _create_alert(self, alert_data: Dict[str, Any]) -> Alert:
        """创建告警"""
        alert_id = f"{alert_data['type'].value}_{int(datetime.now().timestamp())}"
        
        alert = Alert(
            id=alert_id,
            type=alert_data['type'],
            severity=alert_data['severity'],
            title=alert_data['title'],
            description=alert_data['description'],
            source_ip=alert_data.get('source_ip'),
            node_id=alert_data.get('node_id', 'unknown'),
            timestamp=datetime.now(),
            metadata=alert_data.get('metadata', {})
        )
        
        # 存储告警
        self.alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # 更新统计
        self.stats['total_alerts'] += 1
        self.stats['alerts_by_severity'][alert.severity.value] += 1
        self.stats['alerts_by_type'][alert.type.value] += 1
        
        # 发送通知
        await self._send_notifications(alert)
        
        self.logger.info(f"创建告警: {alert.title} (严重级别: {alert.severity.value})")
        
        return alert
    
    async def _send_notifications(self, alert: Alert) -> None:
        """发送通知"""
        # 根据严重级别和配置发送通知
        notification_config = self.alert_config.get('notifications', {})
        
        # 这里可以实现各种通知渠道
        # 如邮件、Slack、微信、钉钉、短信等
        pass
    
    async def resolve_alert(self, alert_id: str, resolution_notes: str = "") -> bool:
        """解决告警
        
        Args:
            alert_id: 告警ID
            resolution_notes: 解决备注
            
        Returns:
            是否成功解决
        """
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.resolved = True
        alert.resolved_at = datetime.now()
        alert.resolution_notes = resolution_notes
        
        # 计算解决时间
        resolution_time = (alert.resolved_at - alert.timestamp).total_seconds()
        
        # 更新平均解决时间
        current_avg = self.stats['resolution_time_avg']
        total_resolved = sum(1 for a in self.alerts.values() if a.resolved)
        
        if total_resolved > 0:
            self.stats['resolution_time_avg'] = (
                (current_avg * (total_resolved - 1) + resolution_time) / total_resolved
            )
        
        self.logger.info(f"告警已解决: {alert.title} (解决时间: {resolution_time:.2f}秒)")
        
        return True
    
    def get_active_alerts(self, severity: Optional[AlertSeverity] = None, 
                         alert_type: Optional[AlertType] = None) -> List[Alert]:
        """获取活跃告警
        
        Args:
            severity: 过滤严重级别
            alert_type: 过滤告警类型
            
        Returns:
            活跃告警列表
        """
        alerts = [alert for alert in self.alerts.values() if not alert.resolved]
        
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]
        
        if alert_type:
            alerts = [alert for alert in alerts if alert.type == alert_type]
        
        return sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """获取告警统计信息"""
        return {
            **self.stats,
            'active_alerts': len([a for a in self.alerts.values() if not a.resolved]),
            'threshold_status': {
                name: threshold.get_status() 
                for name, threshold in self.thresholds.items()
            },
            'anomaly_detector_status': {
                'is_trained': self.anomaly_detector.is_trained,
                'feature_names': self.anomaly_detector.feature_names
            }
        }
    
    async def train_anomaly_detector(self, training_data: List[Dict[str, Any]]) -> None:
        """训练异常检测器
        
        Args:
            training_data: 训练数据
        """
        await asyncio.get_event_loop().run_in_executor(
            None, self.anomaly_detector.train, training_data
        )
    
    def export_alerts(self, start_time: Optional[datetime] = None, 
                     end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """导出告警数据
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            告警数据列表
        """
        alerts = list(self.alert_history)
        
        if start_time:
            alerts = [a for a in alerts if a.timestamp >= start_time]
        
        if end_time:
            alerts = [a for a in alerts if a.timestamp <= end_time]
        
        return [asdict(alert) for alert in alerts]