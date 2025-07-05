#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 性能监控和链路追踪

实现分布式系统的性能监控、链路追踪和性能分析
"""

import asyncio
import json
import logging
import time
import uuid
import psutil
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager, contextmanager
from functools import wraps
import aiohttp
import numpy as np
from pathlib import Path


@dataclass
class TraceSpan:
    """链路追踪跨度"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    end_time: Optional[float]
    duration: Optional[float]
    tags: Dict[str, Any]
    logs: List[Dict[str, Any]]
    status: str  # 'ok', 'error', 'timeout'
    node_id: str
    service_name: str
    
    def finish(self, status: str = 'ok') -> None:
        """结束跨度"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.status = status
    
    def add_tag(self, key: str, value: Any) -> None:
        """添加标签"""
        self.tags[key] = value
    
    def add_log(self, message: str, level: str = 'info', **kwargs) -> None:
        """添加日志"""
        self.logs.append({
            'timestamp': time.time(),
            'message': message,
            'level': level,
            **kwargs
        })


@dataclass
class PerformanceMetric:
    """性能指标"""
    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str]
    node_id: str
    service_name: str


class TraceContext:
    """链路追踪上下文"""
    
    def __init__(self):
        self._context = threading.local()
    
    def get_current_span(self) -> Optional[TraceSpan]:
        """获取当前跨度"""
        return getattr(self._context, 'current_span', None)
    
    def set_current_span(self, span: Optional[TraceSpan]) -> None:
        """设置当前跨度"""
        self._context.current_span = span
    
    def get_trace_id(self) -> Optional[str]:
        """获取当前追踪ID"""
        span = self.get_current_span()
        return span.trace_id if span else None


class PerformanceCollector:
    """性能数据收集器"""
    
    def __init__(self, node_id: str, service_name: str):
        self.node_id = node_id
        self.service_name = service_name
        self.metrics = deque(maxlen=10000)
        self.system_metrics = deque(maxlen=1000)
        self.collection_interval = 5  # 秒
        self.running = False
        self.collection_task = None
        
        # 性能统计
        self.request_counts = defaultdict(int)
        self.response_times = defaultdict(list)
        self.error_counts = defaultdict(int)
        
        # 系统资源监控
        self.cpu_history = deque(maxlen=100)
        self.memory_history = deque(maxlen=100)
        self.disk_history = deque(maxlen=100)
        self.network_history = deque(maxlen=100)
    
    async def start_collection(self) -> None:
        """开始性能数据收集"""
        if self.running:
            return
        
        self.running = True
        self.collection_task = asyncio.create_task(self._collection_loop())
        logging.info("性能数据收集已启动")
    
    async def stop_collection(self) -> None:
        """停止性能数据收集"""
        self.running = False
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
        logging.info("性能数据收集已停止")
    
    async def _collection_loop(self) -> None:
        """性能数据收集循环"""
        while self.running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"收集性能数据时发生错误: {e}")
                await asyncio.sleep(1)
    
    async def _collect_system_metrics(self) -> None:
        """收集系统指标"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_history.append(cpu_percent)
            await self.record_metric('cpu_usage', cpu_percent, 'percent')
            
            # 内存使用率
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            self.memory_history.append(memory_percent)
            await self.record_metric('memory_usage', memory_percent, 'percent')
            await self.record_metric('memory_available', memory.available, 'bytes')
            
            # 磁盘使用率
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.disk_history.append(disk_percent)
            await self.record_metric('disk_usage', disk_percent, 'percent')
            
            # 网络IO
            network = psutil.net_io_counters()
            await self.record_metric('network_bytes_sent', network.bytes_sent, 'bytes')
            await self.record_metric('network_bytes_recv', network.bytes_recv, 'bytes')
            
            # 进程信息
            process = psutil.Process()
            await self.record_metric('process_cpu_percent', process.cpu_percent(), 'percent')
            await self.record_metric('process_memory_percent', process.memory_percent(), 'percent')
            await self.record_metric('process_num_threads', process.num_threads(), 'count')
            
        except Exception as e:
            logging.error(f"收集系统指标时发生错误: {e}")
    
    async def record_metric(self, name: str, value: float, unit: str, 
                           tags: Optional[Dict[str, str]] = None) -> None:
        """记录性能指标
        
        Args:
            name: 指标名称
            value: 指标值
            unit: 单位
            tags: 标签
        """
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now(),
            tags=tags or {},
            node_id=self.node_id,
            service_name=self.service_name
        )
        
        self.metrics.append(metric)
    
    def record_request(self, endpoint: str, method: str, status_code: int, 
                      response_time: float) -> None:
        """记录请求信息
        
        Args:
            endpoint: 端点
            method: HTTP方法
            status_code: 状态码
            response_time: 响应时间
        """
        key = f"{method}:{endpoint}"
        
        self.request_counts[key] += 1
        self.response_times[key].append(response_time)
        
        if status_code >= 400:
            self.error_counts[key] += 1
        
        # 记录指标
        asyncio.create_task(self.record_metric(
            'request_response_time', response_time, 'ms',
            {'endpoint': endpoint, 'method': method, 'status_code': str(status_code)}
        ))
    
    def get_metrics_summary(self, time_window: int = 300) -> Dict[str, Any]:
        """获取指标摘要
        
        Args:
            time_window: 时间窗口（秒）
            
        Returns:
            指标摘要
        """
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=time_window)
        
        # 过滤时间窗口内的指标
        recent_metrics = [
            metric for metric in self.metrics 
            if metric.timestamp >= cutoff_time
        ]
        
        # 按指标名称分组
        metrics_by_name = defaultdict(list)
        for metric in recent_metrics:
            metrics_by_name[metric.name].append(metric.value)
        
        # 计算统计信息
        summary = {}
        for name, values in metrics_by_name.items():
            if values:
                summary[name] = {
                    'count': len(values),
                    'avg': np.mean(values),
                    'min': np.min(values),
                    'max': np.max(values),
                    'std': np.std(values),
                    'p50': np.percentile(values, 50),
                    'p95': np.percentile(values, 95),
                    'p99': np.percentile(values, 99)
                }
        
        # 请求统计
        request_summary = {}
        for endpoint, count in self.request_counts.items():
            response_times = self.response_times[endpoint]
            error_count = self.error_counts[endpoint]
            
            if response_times:
                request_summary[endpoint] = {
                    'total_requests': count,
                    'error_count': error_count,
                    'error_rate': error_count / count,
                    'avg_response_time': np.mean(response_times),
                    'p95_response_time': np.percentile(response_times, 95),
                    'p99_response_time': np.percentile(response_times, 99)
                }
        
        return {
            'metrics': summary,
            'requests': request_summary,
            'system': {
                'cpu_avg': np.mean(list(self.cpu_history)) if self.cpu_history else 0,
                'memory_avg': np.mean(list(self.memory_history)) if self.memory_history else 0,
                'disk_avg': np.mean(list(self.disk_history)) if self.disk_history else 0
            },
            'collection_info': {
                'total_metrics': len(self.metrics),
                'time_window': time_window,
                'node_id': self.node_id,
                'service_name': self.service_name
            }
        }


class DistributedTracer:
    """分布式链路追踪器"""
    
    def __init__(self, node_id: str, service_name: str):
        self.node_id = node_id
        self.service_name = service_name
        self.context = TraceContext()
        self.spans = {}
        self.completed_spans = deque(maxlen=10000)
        self.logger = logging.getLogger(__name__)
    
    def start_span(self, operation_name: str, parent_span: Optional[TraceSpan] = None,
                   tags: Optional[Dict[str, Any]] = None) -> TraceSpan:
        """开始一个新的跨度
        
        Args:
            operation_name: 操作名称
            parent_span: 父跨度
            tags: 标签
            
        Returns:
            新的跨度
        """
        if parent_span is None:
            parent_span = self.context.get_current_span()
        
        trace_id = parent_span.trace_id if parent_span else str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        parent_span_id = parent_span.span_id if parent_span else None
        
        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.time(),
            end_time=None,
            duration=None,
            tags=tags or {},
            logs=[],
            status='active',
            node_id=self.node_id,
            service_name=self.service_name
        )
        
        self.spans[span_id] = span
        return span
    
    def finish_span(self, span: TraceSpan, status: str = 'ok') -> None:
        """结束跨度
        
        Args:
            span: 要结束的跨度
            status: 状态
        """
        span.finish(status)
        
        # 移动到已完成跨度
        if span.span_id in self.spans:
            del self.spans[span.span_id]
        
        self.completed_spans.append(span)
        
        self.logger.debug(
            f"跨度完成: {span.operation_name} (耗时: {span.duration:.3f}s)"
        )
    
    @contextmanager
    def trace(self, operation_name: str, tags: Optional[Dict[str, Any]] = None):
        """同步链路追踪上下文管理器
        
        Args:
            operation_name: 操作名称
            tags: 标签
        """
        span = self.start_span(operation_name, tags=tags)
        old_span = self.context.get_current_span()
        self.context.set_current_span(span)
        
        try:
            yield span
            self.finish_span(span, 'ok')
        except Exception as e:
            span.add_log(f"错误: {str(e)}", 'error')
            self.finish_span(span, 'error')
            raise
        finally:
            self.context.set_current_span(old_span)
    
    @asynccontextmanager
    async def trace_async(self, operation_name: str, tags: Optional[Dict[str, Any]] = None):
        """异步链路追踪上下文管理器
        
        Args:
            operation_name: 操作名称
            tags: 标签
        """
        span = self.start_span(operation_name, tags=tags)
        old_span = self.context.get_current_span()
        self.context.set_current_span(span)
        
        try:
            yield span
            self.finish_span(span, 'ok')
        except Exception as e:
            span.add_log(f"错误: {str(e)}", 'error')
            self.finish_span(span, 'error')
            raise
        finally:
            self.context.set_current_span(old_span)
    
    def get_trace(self, trace_id: str) -> List[TraceSpan]:
        """获取完整的追踪链路
        
        Args:
            trace_id: 追踪ID
            
        Returns:
            追踪链路中的所有跨度
        """
        # 从活跃跨度中查找
        active_spans = [span for span in self.spans.values() if span.trace_id == trace_id]
        
        # 从已完成跨度中查找
        completed_spans = [span for span in self.completed_spans if span.trace_id == trace_id]
        
        all_spans = active_spans + completed_spans
        
        # 按开始时间排序
        return sorted(all_spans, key=lambda x: x.start_time)
    
    def get_trace_statistics(self, time_window: int = 3600) -> Dict[str, Any]:
        """获取追踪统计信息
        
        Args:
            time_window: 时间窗口（秒）
            
        Returns:
            统计信息
        """
        now = time.time()
        cutoff_time = now - time_window
        
        # 过滤时间窗口内的跨度
        recent_spans = [
            span for span in self.completed_spans 
            if span.start_time >= cutoff_time and span.duration is not None
        ]
        
        if not recent_spans:
            return {'message': '没有可用的追踪数据'}
        
        # 按操作名称分组
        spans_by_operation = defaultdict(list)
        for span in recent_spans:
            spans_by_operation[span.operation_name].append(span)
        
        # 计算统计信息
        operation_stats = {}
        for operation, spans in spans_by_operation.items():
            durations = [span.duration for span in spans]
            error_count = sum(1 for span in spans if span.status == 'error')
            
            operation_stats[operation] = {
                'count': len(spans),
                'error_count': error_count,
                'error_rate': error_count / len(spans),
                'avg_duration': np.mean(durations),
                'min_duration': np.min(durations),
                'max_duration': np.max(durations),
                'p50_duration': np.percentile(durations, 50),
                'p95_duration': np.percentile(durations, 95),
                'p99_duration': np.percentile(durations, 99)
            }
        
        # 整体统计
        all_durations = [span.duration for span in recent_spans]
        total_errors = sum(1 for span in recent_spans if span.status == 'error')
        
        return {
            'overall': {
                'total_spans': len(recent_spans),
                'total_errors': total_errors,
                'error_rate': total_errors / len(recent_spans),
                'avg_duration': np.mean(all_durations),
                'p95_duration': np.percentile(all_durations, 95),
                'p99_duration': np.percentile(all_durations, 99)
            },
            'by_operation': operation_stats,
            'time_window': time_window,
            'node_id': self.node_id,
            'service_name': self.service_name
        }


def trace_function(operation_name: Optional[str] = None, tags: Optional[Dict[str, Any]] = None):
    """函数追踪装饰器
    
    Args:
        operation_name: 操作名称（默认使用函数名）
        tags: 标签
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = getattr(wrapper, '_tracer', None)
            if not tracer:
                return func(*args, **kwargs)
            
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            with tracer.trace(op_name, tags=tags) as span:
                span.add_tag('function.name', func.__name__)
                span.add_tag('function.module', func.__module__)
                
                try:
                    result = func(*args, **kwargs)
                    span.add_tag('function.result_type', type(result).__name__)
                    return result
                except Exception as e:
                    span.add_tag('error.type', type(e).__name__)
                    span.add_tag('error.message', str(e))
                    raise
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = getattr(async_wrapper, '_tracer', None)
            if not tracer:
                return await func(*args, **kwargs)
            
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            async with tracer.trace_async(op_name, tags=tags) as span:
                span.add_tag('function.name', func.__name__)
                span.add_tag('function.module', func.__module__)
                
                try:
                    result = await func(*args, **kwargs)
                    span.add_tag('function.result_type', type(result).__name__)
                    return result
                except Exception as e:
                    span.add_tag('error.type', type(e).__name__)
                    span.add_tag('error.message', str(e))
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator


class PerformanceMonitor:
    """性能监控主类"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.node_id = config.get('node_id', 'unknown')
        self.service_name = config.get('service_name', 'fail2ban')
        
        # 初始化组件
        self.collector = PerformanceCollector(self.node_id, self.service_name)
        self.tracer = DistributedTracer(self.node_id, self.service_name)
        
        # 性能阈值
        self.thresholds = config.get('performance_thresholds', {
            'response_time_p95': 1000,  # ms
            'error_rate': 0.05,  # 5%
            'cpu_usage': 80,  # %
            'memory_usage': 85,  # %
        })
        
        # 告警回调
        self.alert_callbacks: List[Callable] = []
        
        self.logger = logging.getLogger(__name__)
    
    async def start(self) -> None:
        """启动性能监控"""
        await self.collector.start_collection()
        self.logger.info("性能监控已启动")
    
    async def stop(self) -> None:
        """停止性能监控"""
        await self.collector.stop_collection()
        self.logger.info("性能监控已停止")
    
    def add_alert_callback(self, callback: Callable) -> None:
        """添加告警回调
        
        Args:
            callback: 告警回调函数
        """
        self.alert_callbacks.append(callback)
    
    async def check_performance_alerts(self) -> List[Dict[str, Any]]:
        """检查性能告警
        
        Returns:
            告警列表
        """
        alerts = []
        
        # 获取性能摘要
        summary = self.collector.get_metrics_summary()
        
        # 检查响应时间
        for endpoint, stats in summary.get('requests', {}).items():
            p95_time = stats.get('p95_response_time', 0)
            if p95_time > self.thresholds['response_time_p95']:
                alerts.append({
                    'type': 'performance_degradation',
                    'severity': 'high',
                    'message': f'端点 {endpoint} P95响应时间过高: {p95_time:.2f}ms',
                    'metric': 'response_time_p95',
                    'value': p95_time,
                    'threshold': self.thresholds['response_time_p95']
                })
            
            # 检查错误率
            error_rate = stats.get('error_rate', 0)
            if error_rate > self.thresholds['error_rate']:
                alerts.append({
                    'type': 'high_error_rate',
                    'severity': 'high',
                    'message': f'端点 {endpoint} 错误率过高: {error_rate:.2%}',
                    'metric': 'error_rate',
                    'value': error_rate,
                    'threshold': self.thresholds['error_rate']
                })
        
        # 检查系统资源
        system_stats = summary.get('system', {})
        
        cpu_avg = system_stats.get('cpu_avg', 0)
        if cpu_avg > self.thresholds['cpu_usage']:
            alerts.append({
                'type': 'high_cpu_usage',
                'severity': 'medium',
                'message': f'CPU使用率过高: {cpu_avg:.1f}%',
                'metric': 'cpu_usage',
                'value': cpu_avg,
                'threshold': self.thresholds['cpu_usage']
            })
        
        memory_avg = system_stats.get('memory_avg', 0)
        if memory_avg > self.thresholds['memory_usage']:
            alerts.append({
                'type': 'high_memory_usage',
                'severity': 'medium',
                'message': f'内存使用率过高: {memory_avg:.1f}%',
                'metric': 'memory_usage',
                'value': memory_avg,
                'threshold': self.thresholds['memory_usage']
            })
        
        # 触发告警回调
        for alert in alerts:
            for callback in self.alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    self.logger.error(f"执行告警回调时发生错误: {e}")
        
        return alerts
    
    def get_performance_dashboard(self) -> Dict[str, Any]:
        """获取性能仪表板数据
        
        Returns:
            仪表板数据
        """
        return {
            'metrics_summary': self.collector.get_metrics_summary(),
            'trace_statistics': self.tracer.get_trace_statistics(),
            'thresholds': self.thresholds,
            'node_info': {
                'node_id': self.node_id,
                'service_name': self.service_name
            }
        }
    
    def export_performance_data(self, start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None) -> Dict[str, Any]:
        """导出性能数据
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            性能数据
        """
        # 过滤指标数据
        metrics = list(self.collector.metrics)
        if start_time:
            metrics = [m for m in metrics if m.timestamp >= start_time]
        if end_time:
            metrics = [m for m in metrics if m.timestamp <= end_time]
        
        # 过滤追踪数据
        spans = list(self.tracer.completed_spans)
        if start_time or end_time:
            start_ts = start_time.timestamp() if start_time else 0
            end_ts = end_time.timestamp() if end_time else float('inf')
            spans = [s for s in spans if start_ts <= s.start_time <= end_ts]
        
        return {
            'metrics': [asdict(m) for m in metrics],
            'spans': [asdict(s) for s in spans],
            'export_info': {
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': end_time.isoformat() if end_time else None,
                'metrics_count': len(metrics),
                'spans_count': len(spans),
                'node_id': self.node_id,
                'service_name': self.service_name
            }
        }


# 全局性能监控实例
_performance_monitor: Optional[PerformanceMonitor] = None


def initialize_performance_monitor(config: Dict[str, Any]) -> PerformanceMonitor:
    """初始化全局性能监控实例
    
    Args:
        config: 配置
        
    Returns:
        性能监控实例
    """
    global _performance_monitor
    _performance_monitor = PerformanceMonitor(config)
    return _performance_monitor


def get_performance_monitor() -> Optional[PerformanceMonitor]:
    """获取全局性能监控实例
    
    Returns:
        性能监控实例
    """
    return _performance_monitor


def get_tracer() -> Optional[DistributedTracer]:
    """获取全局追踪器实例
    
    Returns:
        追踪器实例
    """
    return _performance_monitor.tracer if _performance_monitor else None


def get_collector() -> Optional[PerformanceCollector]:
    """获取全局收集器实例
    
    Returns:
        收集器实例
    """
    return _performance_monitor.collector if _performance_monitor else None