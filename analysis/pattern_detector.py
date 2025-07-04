#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 攻击模式检测器
"""

import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set


class PatternDetector:
    """攻击模式检测器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.analysis_config = config.get('analysis', {})
        self.attack_patterns = self.analysis_config.get('attack_patterns', {})
        
        # 编译正则表达式模式
        self.compiled_patterns = self._compile_patterns()
        
        # 请求历史记录（用于频率分析）
        self.request_history = defaultdict(lambda: deque(maxlen=1000))
        
        # 攻击检测缓存
        self.detection_cache = {}
        self.cache_ttl = 300  # 5分钟缓存
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """编译攻击模式正则表达式
        
        Returns:
            编译后的模式字典
        """
        compiled = {}
        
        for attack_type, config in self.attack_patterns.items():
            if not config.get('enabled', True):
                continue
            
            patterns = config.get('patterns', [])
            compiled_patterns = []
            
            for pattern in patterns:
                try:
                    compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    print(f"编译模式失败 {attack_type}/{pattern}: {e}")
            
            if compiled_patterns:
                compiled[attack_type] = compiled_patterns
        
        return compiled
    
    async def detect(self, log_entry: Dict) -> Optional[str]:
        """检测攻击模式
        
        Args:
            log_entry: 日志条目
        
        Returns:
            检测到的攻击类型，如果没有检测到返回None
        """
        try:
            # 提取关键字段
            ip = log_entry.get('remote_addr', '')
            uri = log_entry.get('request_uri', '')
            user_agent = log_entry.get('http_user_agent', '')
            referer = log_entry.get('http_referer', '')
            method = log_entry.get('request_method', '')
            status = log_entry.get('status', 200)
            
            # 创建检测上下文
            context = {
                'ip': ip,
                'uri': uri,
                'user_agent': user_agent,
                'referer': referer,
                'method': method,
                'status': status,
                'timestamp': datetime.now()
            }
            
            # 记录请求历史
            self._record_request(ip, context)
            
            # 检查缓存
            cache_key = self._get_cache_key(context)
            if cache_key in self.detection_cache:
                cache_entry = self.detection_cache[cache_key]
                if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                    return cache_entry['result']
            
            # 执行模式检测
            detected_attack = await self._detect_patterns(context)
            
            # 如果没有检测到模式攻击，检查频率攻击
            if not detected_attack:
                detected_attack = await self._detect_frequency_attacks(ip, context)
            
            # 缓存结果
            self.detection_cache[cache_key] = {
                'result': detected_attack,
                'timestamp': time.time()
            }
            
            return detected_attack
        
        except Exception as e:
            print(f"攻击检测异常: {e}")
            return None
    
    def _get_cache_key(self, context: Dict) -> str:
        """生成缓存键
        
        Args:
            context: 检测上下文
        
        Returns:
            缓存键
        """
        import hashlib
        
        key_data = f"{context['uri']}:{context['user_agent']}:{context['method']}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _record_request(self, ip: str, context: Dict):
        """记录请求历史
        
        Args:
            ip: IP地址
            context: 请求上下文
        """
        self.request_history[ip].append({
            'timestamp': context['timestamp'],
            'uri': context['uri'],
            'method': context['method'],
            'status': context['status'],
            'user_agent': context['user_agent']
        })
    
    async def _detect_patterns(self, context: Dict) -> Optional[str]:
        """检测模式攻击
        
        Args:
            context: 检测上下文
        
        Returns:
            攻击类型
        """
        # 要检测的字段
        fields_to_check = [
            context['uri'],
            context['user_agent'],
            context['referer'] or ''
        ]
        
        # 检查每种攻击模式
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                for field in fields_to_check:
                    if pattern.search(field):
                        return f"{attack_type}:{pattern.pattern}"
        
        return None
    
    async def _detect_frequency_attacks(self, ip: str, context: Dict) -> Optional[str]:
        """检测频率攻击
        
        Args:
            ip: IP地址
            context: 请求上下文
        
        Returns:
            攻击类型
        """
        if ip not in self.request_history:
            return None
        
        history = self.request_history[ip]
        now = context['timestamp']
        
        # 检查404频率
        attack = self._check_404_frequency(history, now)
        if attack:
            return attack
        
        # 检查请求频率
        attack = self._check_request_frequency(history, now)
        if attack:
            return attack
        
        # 检查扫描行为
        attack = self._check_scanning_behavior(history, now)
        if attack:
            return attack
        
        return None
    
    def _check_404_frequency(self, history: deque, now: datetime) -> Optional[str]:
        """检查404错误频率
        
        Args:
            history: 请求历史
            now: 当前时间
        
        Returns:
            攻击类型
        """
        ban_rules = self.analysis_config.get('ban_rules', {})
        threshold = ban_rules.get('not_found_threshold', 20)
        time_window = ban_rules.get('time_window', 10)  # 分钟
        
        cutoff_time = now - timedelta(minutes=time_window)
        
        # 统计时间窗口内的404错误
        error_404_count = 0
        for request in history:
            if request['timestamp'] >= cutoff_time:
                if request['status'] == 404:
                    error_404_count += 1
        
        if error_404_count >= threshold:
            return f"high_404_frequency:{error_404_count}_in_{time_window}min"
        
        return None
    
    def _check_request_frequency(self, history: deque, now: datetime) -> Optional[str]:
        """检查请求频率
        
        Args:
            history: 请求历史
            now: 当前时间
        
        Returns:
            攻击类型
        """
        # 检查1分钟内的请求数
        cutoff_time = now - timedelta(minutes=1)
        recent_requests = sum(1 for req in history if req['timestamp'] >= cutoff_time)
        
        if recent_requests > 60:  # 每分钟超过60个请求
            return f"high_request_frequency:{recent_requests}_per_minute"
        
        # 检查5分钟内的请求数
        cutoff_time = now - timedelta(minutes=5)
        recent_requests = sum(1 for req in history if req['timestamp'] >= cutoff_time)
        
        if recent_requests > 200:  # 5分钟超过200个请求
            return f"sustained_high_frequency:{recent_requests}_in_5min"
        
        return None
    
    def _check_scanning_behavior(self, history: deque, now: datetime) -> Optional[str]:
        """检查扫描行为
        
        Args:
            history: 请求历史
            now: 当前时间
        
        Returns:
            攻击类型
        """
        cutoff_time = now - timedelta(minutes=10)
        
        # 收集最近10分钟的URI
        recent_uris = set()
        for request in history:
            if request['timestamp'] >= cutoff_time:
                recent_uris.add(request['uri'])
        
        # 如果访问了大量不同的URI，可能是扫描
        if len(recent_uris) > 50:
            return f"directory_scanning:{len(recent_uris)}_unique_paths"
        
        # 检查是否访问了常见的敏感路径
        sensitive_paths = {
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/config', '/backup', '/test', '/dev', '/api',
            '/.env', '/.git', '/robots.txt', '/sitemap.xml'
        }
        
        accessed_sensitive = 0
        for uri in recent_uris:
            for sensitive in sensitive_paths:
                if sensitive in uri.lower():
                    accessed_sensitive += 1
                    break
        
        if accessed_sensitive > 5:
            return f"sensitive_path_scanning:{accessed_sensitive}_sensitive_paths"
        
        return None
    
    def get_ip_statistics(self, ip: str) -> Dict:
        """获取IP统计信息
        
        Args:
            ip: IP地址
        
        Returns:
            统计信息
        """
        if ip not in self.request_history:
            return {'total_requests': 0}
        
        history = self.request_history[ip]
        now = datetime.now()
        
        # 统计信息
        stats = {
            'total_requests': len(history),
            'last_request': max(req['timestamp'] for req in history) if history else None,
            'unique_paths': len(set(req['uri'] for req in history)),
            'status_codes': defaultdict(int),
            'methods': defaultdict(int),
            'user_agents': set()
        }
        
        # 详细统计
        for request in history:
            stats['status_codes'][request['status']] += 1
            stats['methods'][request['method']] += 1
            stats['user_agents'].add(request['user_agent'])
        
        # 转换为普通字典
        stats['status_codes'] = dict(stats['status_codes'])
        stats['methods'] = dict(stats['methods'])
        stats['unique_user_agents'] = len(stats['user_agents'])
        del stats['user_agents']  # 移除集合，避免序列化问题
        
        # 时间窗口统计
        for window_minutes in [1, 5, 10, 60]:
            cutoff_time = now - timedelta(minutes=window_minutes)
            recent_count = sum(1 for req in history if req['timestamp'] >= cutoff_time)
            stats[f'requests_last_{window_minutes}min'] = recent_count
        
        return stats
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """清理旧数据
        
        Args:
            max_age_hours: 最大保留时间（小时）
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        # 清理请求历史
        for ip in list(self.request_history.keys()):
            history = self.request_history[ip]
            
            # 移除过期请求
            while history and history[0]['timestamp'] < cutoff_time:
                history.popleft()
            
            # 如果历史为空，删除IP记录
            if not history:
                del self.request_history[ip]
        
        # 清理检测缓存
        current_time = time.time()
        expired_keys = [
            key for key, value in self.detection_cache.items()
            if current_time - value['timestamp'] > self.cache_ttl
        ]
        
        for key in expired_keys:
            del self.detection_cache[key]
    
    def get_detection_statistics(self) -> Dict:
        """获取检测统计信息
        
        Returns:
            统计信息
        """
        return {
            'monitored_ips': len(self.request_history),
            'total_requests': sum(len(history) for history in self.request_history.values()),
            'cache_entries': len(self.detection_cache),
            'enabled_patterns': len(self.compiled_patterns),
            'pattern_details': {
                attack_type: len(patterns)
                for attack_type, patterns in self.compiled_patterns.items()
            }
        }


class AdvancedPatternDetector(PatternDetector):
    """高级模式检测器"""
    
    def __init__(self, config: dict):
        super().__init__(config)
        
        # 机器学习相关（如果需要）
        self.ml_enabled = False
        
        # 地理位置检测
        self.geo_enabled = False
        
        # 协同检测
        self.collaborative_detection = True
    
    async def detect_advanced_patterns(self, log_entry: Dict) -> Optional[Dict]:
        """高级模式检测
        
        Args:
            log_entry: 日志条目
        
        Returns:
            检测结果详情
        """
        result = {
            'basic_detection': await self.detect(log_entry),
            'advanced_features': {}
        }
        
        # 用户代理分析
        ua_analysis = self._analyze_user_agent(log_entry.get('http_user_agent', ''))
        if ua_analysis['suspicious']:
            result['advanced_features']['suspicious_user_agent'] = ua_analysis
        
        # 请求时序分析
        timing_analysis = self._analyze_request_timing(log_entry.get('remote_addr', ''))
        if timing_analysis['suspicious']:
            result['advanced_features']['suspicious_timing'] = timing_analysis
        
        # 负载分析
        payload_analysis = self._analyze_payload(log_entry)
        if payload_analysis['suspicious']:
            result['advanced_features']['suspicious_payload'] = payload_analysis
        
        return result if result['basic_detection'] or result['advanced_features'] else None
    
    def _analyze_user_agent(self, user_agent: str) -> Dict:
        """分析User-Agent
        
        Args:
            user_agent: User-Agent字符串
        
        Returns:
            分析结果
        """
        suspicious_indicators = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap',
            'burp', 'w3af', 'acunetix', 'nessus',
            'python-requests', 'curl', 'wget', 'libwww'
        ]
        
        result = {
            'suspicious': False,
            'indicators': [],
            'score': 0
        }
        
        ua_lower = user_agent.lower()
        
        for indicator in suspicious_indicators:
            if indicator in ua_lower:
                result['suspicious'] = True
                result['indicators'].append(indicator)
                result['score'] += 10
        
        # 检查是否为空或过短
        if not user_agent or len(user_agent) < 10:
            result['suspicious'] = True
            result['indicators'].append('empty_or_short')
            result['score'] += 5
        
        # 检查是否包含异常字符
        if any(char in user_agent for char in ['<', '>', '"', "'", ';']):
            result['suspicious'] = True
            result['indicators'].append('special_characters')
            result['score'] += 8
        
        return result
    
    def _analyze_request_timing(self, ip: str) -> Dict:
        """分析请求时序
        
        Args:
            ip: IP地址
        
        Returns:
            分析结果
        """
        result = {
            'suspicious': False,
            'patterns': [],
            'score': 0
        }
        
        if ip not in self.request_history:
            return result
        
        history = self.request_history[ip]
        if len(history) < 5:
            return result
        
        # 分析请求间隔
        intervals = []
        for i in range(1, len(history)):
            interval = (history[i]['timestamp'] - history[i-1]['timestamp']).total_seconds()
            intervals.append(interval)
        
        # 检查是否有规律的间隔（可能是自动化工具）
        if len(intervals) >= 5:
            # 计算间隔的标准差
            import statistics
            try:
                std_dev = statistics.stdev(intervals)
                mean_interval = statistics.mean(intervals)
                
                # 如果标准差很小且平均间隔很短，可能是自动化攻击
                if std_dev < 1.0 and mean_interval < 5.0:
                    result['suspicious'] = True
                    result['patterns'].append('regular_intervals')
                    result['score'] += 15
            except statistics.StatisticsError:
                pass
        
        return result
    
    def _analyze_payload(self, log_entry: Dict) -> Dict:
        """分析请求负载
        
        Args:
            log_entry: 日志条目
        
        Returns:
            分析结果
        """
        result = {
            'suspicious': False,
            'features': [],
            'score': 0
        }
        
        uri = log_entry.get('request_uri', '')
        
        # 检查URI长度
        if len(uri) > 1000:
            result['suspicious'] = True
            result['features'].append('long_uri')
            result['score'] += 10
        
        # 检查编码字符
        encoded_chars = uri.count('%')
        if encoded_chars > 10:
            result['suspicious'] = True
            result['features'].append('excessive_encoding')
            result['score'] += encoded_chars
        
        # 检查特殊字符密度
        special_chars = sum(1 for char in uri if char in '&=?#<>"\'\'()[]{}|;')
        if special_chars > len(uri) * 0.3:  # 超过30%是特殊字符
            result['suspicious'] = True
            result['features'].append('high_special_char_density')
            result['score'] += 12
        
        return result


if __name__ == '__main__':
    # 测试模式检测器
    config = {
        'analysis': {
            'attack_patterns': {
                'sql_injection': {
                    'enabled': True,
                    'patterns': [
                        'union.*select',
                        'drop.*table',
                        'insert.*into'
                    ]
                },
                'xss': {
                    'enabled': True,
                    'patterns': [
                        '<script',
                        'javascript:',
                        'onerror='
                    ]
                }
            },
            'ban_rules': {
                'not_found_threshold': 10,
                'time_window': 5
            }
        }
    }
    
    async def test_detector():
        detector = PatternDetector(config)
        
        # 测试日志条目
        test_logs = [
            {
                'remote_addr': '192.168.1.100',
                'request_uri': '/index.php?id=1 union select * from users',
                'http_user_agent': 'Mozilla/5.0',
                'status': 200
            },
            {
                'remote_addr': '10.0.0.1',
                'request_uri': '/search?q=<script>alert(1)</script>',
                'http_user_agent': 'sqlmap/1.0',
                'status': 404
            },
            {
                'remote_addr': '172.16.0.1',
                'request_uri': '/normal-page.html',
                'http_user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'status': 200
            }
        ]
        
        print("=== 模式检测测试 ===")
        
        for i, log_entry in enumerate(test_logs):
            print(f"\n测试 {i+1}: {log_entry['request_uri']}")
            
            result = await detector.detect(log_entry)
            if result:
                print(f"🚨 检测到攻击: {result}")
            else:
                print("✅ 未检测到攻击")
        
        # 测试频率攻击
        print("\n=== 频率攻击测试 ===")
        
        # 模拟大量404请求
        for i in range(15):
            log_entry = {
                'remote_addr': '192.168.1.200',
                'request_uri': f'/nonexistent-{i}.php',
                'http_user_agent': 'Mozilla/5.0',
                'status': 404
            }
            
            result = await detector.detect(log_entry)
            if result:
                print(f"🚨 频率攻击检测: {result}")
                break
        
        # 获取统计信息
        print("\n=== 统计信息 ===")
        stats = detector.get_detection_statistics()
        for key, value in stats.items():
            print(f"{key}: {value}")
        
        # IP统计
        ip_stats = detector.get_ip_statistics('192.168.1.200')
        print(f"\nIP 192.168.1.200 统计: {ip_stats}")
    
    import asyncio
    asyncio.run(test_detector())
    print("\n模式检测器测试完成")