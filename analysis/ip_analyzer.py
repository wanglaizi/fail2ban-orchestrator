#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - IP分析器
"""

import asyncio
import ipaddress
import json
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple


class IPAnalyzer:
    """IP行为分析器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.analysis_config = config.get('analysis', {})
        self.ban_rules = self.analysis_config.get('ban_rules', {})
        
        # IP行为数据
        self.ip_behaviors = defaultdict(lambda: {
            'first_seen': None,
            'last_seen': None,
            'request_count': 0,
            'attack_count': 0,
            'status_codes': defaultdict(int),
            'user_agents': set(),
            'paths': set(),
            'countries': set(),
            'risk_score': 0,
            'ban_history': [],
            'recent_attacks': deque(maxlen=100)
        })
        
        # IP地理位置缓存
        self.geo_cache = {}
        self.geo_cache_ttl = 3600  # 1小时
        
        # 风险评分权重
        self.risk_weights = {
            'attack_frequency': 0.3,
            'status_4xx_rate': 0.2,
            'unique_paths': 0.15,
            'user_agent_diversity': 0.1,
            'geo_risk': 0.1,
            'ban_history': 0.15
        }
        
        # 已知恶意IP集合
        self.known_malicious = set()
        self.whitelist = set()
        
        # 加载IP列表
        self._load_ip_lists()
    
    def _load_ip_lists(self):
        """加载IP白名单和黑名单"""
        whitelist_config = self.config.get('whitelist', {})
        
        # 加载白名单IP
        for ip in whitelist_config.get('ips', []):
            try:
                self.whitelist.add(ipaddress.ip_address(ip))
            except ValueError:
                print(f"无效的白名单IP: {ip}")
        
        # 加载白名单网络
        for network in whitelist_config.get('networks', []):
            try:
                self.whitelist.add(ipaddress.ip_network(network, strict=False))
            except ValueError:
                print(f"无效的白名单网络: {network}")
    
    def is_whitelisted(self, ip: str) -> bool:
        """检查IP是否在白名单中
        
        Args:
            ip: IP地址
        
        Returns:
            是否在白名单中
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for whitelist_item in self.whitelist:
                if isinstance(whitelist_item, ipaddress.IPv4Address) or isinstance(whitelist_item, ipaddress.IPv6Address):
                    if ip_obj == whitelist_item:
                        return True
                elif isinstance(whitelist_item, ipaddress.IPv4Network) or isinstance(whitelist_item, ipaddress.IPv6Network):
                    if ip_obj in whitelist_item:
                        return True
            
            return False
        
        except ValueError:
            return False
    
    async def analyze_ip(self, ip: str, log_entry: Dict, attack_type: Optional[str] = None) -> Dict:
        """分析IP行为
        
        Args:
            ip: IP地址
            log_entry: 日志条目
            attack_type: 攻击类型（如果有）
        
        Returns:
            分析结果
        """
        # 检查白名单
        if self.is_whitelisted(ip):
            return {
                'ip': ip,
                'whitelisted': True,
                'risk_score': 0,
                'should_ban': False,
                'reason': 'IP在白名单中'
            }
        
        # 更新IP行为数据
        behavior = self.ip_behaviors[ip]
        now = datetime.now()
        
        # 更新基本信息
        if behavior['first_seen'] is None:
            behavior['first_seen'] = now
        behavior['last_seen'] = now
        behavior['request_count'] += 1
        
        # 更新状态码统计
        status = log_entry.get('status', 200)
        behavior['status_codes'][status] += 1
        
        # 更新User-Agent
        user_agent = log_entry.get('http_user_agent', '')
        if user_agent:
            behavior['user_agents'].add(user_agent)
        
        # 更新访问路径
        path = log_entry.get('request_uri', '')
        if path:
            behavior['paths'].add(path)
        
        # 记录攻击
        if attack_type:
            behavior['attack_count'] += 1
            behavior['recent_attacks'].append({
                'timestamp': now,
                'type': attack_type,
                'path': path,
                'status': status
            })
        
        # 获取地理位置信息
        geo_info = await self._get_geo_info(ip)
        if geo_info and geo_info.get('country'):
            behavior['countries'].add(geo_info['country'])
        
        # 计算风险评分
        risk_score = await self._calculate_risk_score(ip, behavior, geo_info)
        behavior['risk_score'] = risk_score
        
        # 判断是否应该封禁
        should_ban, ban_reason = self._should_ban_ip(ip, behavior, attack_type)
        
        return {
            'ip': ip,
            'whitelisted': False,
            'risk_score': risk_score,
            'should_ban': should_ban,
            'reason': ban_reason,
            'behavior_summary': self._get_behavior_summary(behavior),
            'geo_info': geo_info
        }
    
    async def _get_geo_info(self, ip: str) -> Optional[Dict]:
        """获取IP地理位置信息
        
        Args:
            ip: IP地址
        
        Returns:
            地理位置信息
        """
        # 检查缓存
        if ip in self.geo_cache:
            cache_entry = self.geo_cache[ip]
            if time.time() - cache_entry['timestamp'] < self.geo_cache_ttl:
                return cache_entry['data']
        
        # 检查是否为私有IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                geo_info = {
                    'country': 'Private',
                    'city': 'Private Network',
                    'isp': 'Private',
                    'risk_level': 'low'
                }
                
                self.geo_cache[ip] = {
                    'data': geo_info,
                    'timestamp': time.time()
                }
                
                return geo_info
        
        except ValueError:
            return None
        
        # 这里可以集成真实的地理位置API
        # 例如：MaxMind GeoIP2, IP2Location等
        # 为了演示，我们使用模拟数据
        
        geo_info = await self._mock_geo_lookup(ip)
        
        # 缓存结果
        self.geo_cache[ip] = {
            'data': geo_info,
            'timestamp': time.time()
        }
        
        return geo_info
    
    async def _mock_geo_lookup(self, ip: str) -> Dict:
        """模拟地理位置查询
        
        Args:
            ip: IP地址
        
        Returns:
            模拟的地理位置信息
        """
        # 模拟延迟
        await asyncio.sleep(0.1)
        
        # 根据IP段模拟不同地区
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            first_octet = int(ip_parts[0])
            
            if first_octet in [10, 172, 192]:  # 私有IP
                return {
                    'country': 'Private',
                    'city': 'Private Network',
                    'isp': 'Private',
                    'risk_level': 'low'
                }
            elif first_octet < 50:
                return {
                    'country': 'US',
                    'city': 'New York',
                    'isp': 'Example ISP',
                    'risk_level': 'medium'
                }
            elif first_octet < 100:
                return {
                    'country': 'CN',
                    'city': 'Beijing',
                    'isp': 'China Telecom',
                    'risk_level': 'low'
                }
            elif first_octet < 150:
                return {
                    'country': 'RU',
                    'city': 'Moscow',
                    'isp': 'Russian ISP',
                    'risk_level': 'high'
                }
            else:
                return {
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'isp': 'Unknown',
                    'risk_level': 'medium'
                }
        
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'risk_level': 'medium'
        }
    
    async def _calculate_risk_score(self, ip: str, behavior: Dict, geo_info: Optional[Dict]) -> float:
        """计算IP风险评分
        
        Args:
            ip: IP地址
            behavior: 行为数据
            geo_info: 地理位置信息
        
        Returns:
            风险评分 (0-100)
        """
        score = 0.0
        
        # 攻击频率评分
        if behavior['request_count'] > 0:
            attack_rate = behavior['attack_count'] / behavior['request_count']
            attack_score = min(attack_rate * 100, 50)  # 最高50分
            score += attack_score * self.risk_weights['attack_frequency']
        
        # 4xx状态码比率
        total_requests = sum(behavior['status_codes'].values())
        if total_requests > 0:
            error_4xx = sum(count for status, count in behavior['status_codes'].items() if 400 <= status < 500)
            error_rate = error_4xx / total_requests
            error_score = min(error_rate * 100, 30)  # 最高30分
            score += error_score * self.risk_weights['status_4xx_rate']
        
        # 访问路径多样性（可能表示扫描行为）
        unique_paths = len(behavior['paths'])
        if unique_paths > 10:
            path_score = min((unique_paths - 10) * 2, 25)  # 最高25分
            score += path_score * self.risk_weights['unique_paths']
        
        # User-Agent多样性（可能表示伪装）
        unique_agents = len(behavior['user_agents'])
        if unique_agents > 5:
            agent_score = min((unique_agents - 5) * 3, 20)  # 最高20分
            score += agent_score * self.risk_weights['user_agent_diversity']
        
        # 地理位置风险
        if geo_info:
            geo_risk_level = geo_info.get('risk_level', 'medium')
            geo_score = {
                'low': 0,
                'medium': 10,
                'high': 25
            }.get(geo_risk_level, 10)
            score += geo_score * self.risk_weights['geo_risk']
        
        # 封禁历史
        ban_count = len(behavior['ban_history'])
        if ban_count > 0:
            ban_score = min(ban_count * 15, 30)  # 最高30分
            score += ban_score * self.risk_weights['ban_history']
        
        return min(score, 100.0)  # 确保不超过100分
    
    def _should_ban_ip(self, ip: str, behavior: Dict, attack_type: Optional[str]) -> Tuple[bool, str]:
        """判断是否应该封禁IP
        
        Args:
            ip: IP地址
            behavior: 行为数据
            attack_type: 攻击类型
        
        Returns:
            (是否封禁, 封禁原因)
        """
        # 检查是否已知恶意IP
        if ip in self.known_malicious:
            return True, "已知恶意IP"
        
        # 检查风险评分
        risk_threshold = self.ban_rules.get('risk_threshold', 70)
        if behavior['risk_score'] >= risk_threshold:
            return True, f"风险评分过高: {behavior['risk_score']:.1f}"
        
        # 检查攻击次数
        attack_threshold = self.ban_rules.get('attack_threshold', 5)
        if behavior['attack_count'] >= attack_threshold:
            return True, f"攻击次数过多: {behavior['attack_count']}"
        
        # 检查短时间内的攻击频率
        if attack_type and len(behavior['recent_attacks']) >= 3:
            recent_attacks = list(behavior['recent_attacks'])[-3:]
            time_span = (recent_attacks[-1]['timestamp'] - recent_attacks[0]['timestamp']).total_seconds()
            
            if time_span < 60:  # 1分钟内3次攻击
                return True, "短时间内频繁攻击"
        
        # 检查404错误频率
        not_found_threshold = self.ban_rules.get('not_found_threshold', 20)
        not_found_count = behavior['status_codes'].get(404, 0)
        if not_found_count >= not_found_threshold:
            return True, f"404错误过多: {not_found_count}"
        
        # 检查请求频率
        if behavior['last_seen'] and behavior['first_seen']:
            time_span = (behavior['last_seen'] - behavior['first_seen']).total_seconds()
            if time_span > 0:
                request_rate = behavior['request_count'] / time_span * 60  # 每分钟请求数
                
                rate_threshold = self.ban_rules.get('request_rate_threshold', 30)
                if request_rate > rate_threshold:
                    return True, f"请求频率过高: {request_rate:.1f}/min"
        
        return False, "未达到封禁条件"
    
    def _get_behavior_summary(self, behavior: Dict) -> Dict:
        """获取行为摘要
        
        Args:
            behavior: 行为数据
        
        Returns:
            行为摘要
        """
        total_requests = sum(behavior['status_codes'].values())
        
        summary = {
            'total_requests': behavior['request_count'],
            'attack_count': behavior['attack_count'],
            'unique_paths': len(behavior['paths']),
            'unique_user_agents': len(behavior['user_agents']),
            'countries_visited': list(behavior['countries']),
            'first_seen': behavior['first_seen'].isoformat() if behavior['first_seen'] else None,
            'last_seen': behavior['last_seen'].isoformat() if behavior['last_seen'] else None,
            'ban_count': len(behavior['ban_history'])
        }
        
        # 状态码分布
        if total_requests > 0:
            summary['status_distribution'] = {
                '2xx': sum(count for status, count in behavior['status_codes'].items() if 200 <= status < 300) / total_requests,
                '3xx': sum(count for status, count in behavior['status_codes'].items() if 300 <= status < 400) / total_requests,
                '4xx': sum(count for status, count in behavior['status_codes'].items() if 400 <= status < 500) / total_requests,
                '5xx': sum(count for status, count in behavior['status_codes'].items() if 500 <= status < 600) / total_requests
            }
        
        # 最近攻击
        if behavior['recent_attacks']:
            summary['recent_attacks'] = [
                {
                    'timestamp': attack['timestamp'].isoformat(),
                    'type': attack['type'],
                    'path': attack['path']
                }
                for attack in list(behavior['recent_attacks'])[-5:]  # 最近5次攻击
            ]
        
        return summary
    
    def record_ban(self, ip: str, reason: str, duration: int):
        """记录IP封禁
        
        Args:
            ip: IP地址
            reason: 封禁原因
            duration: 封禁时长（秒）
        """
        behavior = self.ip_behaviors[ip]
        behavior['ban_history'].append({
            'timestamp': datetime.now(),
            'reason': reason,
            'duration': duration
        })
    
    def get_ip_report(self, ip: str) -> Optional[Dict]:
        """获取IP详细报告
        
        Args:
            ip: IP地址
        
        Returns:
            IP报告
        """
        if ip not in self.ip_behaviors:
            return None
        
        behavior = self.ip_behaviors[ip]
        
        report = {
            'ip': ip,
            'whitelisted': self.is_whitelisted(ip),
            'risk_score': behavior['risk_score'],
            'behavior_summary': self._get_behavior_summary(behavior),
            'detailed_stats': {
                'status_codes': dict(behavior['status_codes']),
                'user_agents': list(behavior['user_agents'])[:10],  # 最多显示10个
                'top_paths': list(behavior['paths'])[:20],  # 最多显示20个路径
                'ban_history': [
                    {
                        'timestamp': ban['timestamp'].isoformat(),
                        'reason': ban['reason'],
                        'duration': ban['duration']
                    }
                    for ban in behavior['ban_history']
                ]
            }
        }
        
        return report
    
    def get_top_risky_ips(self, limit: int = 10) -> List[Dict]:
        """获取风险最高的IP列表
        
        Args:
            limit: 返回数量限制
        
        Returns:
            风险IP列表
        """
        risky_ips = []
        
        for ip, behavior in self.ip_behaviors.items():
            if not self.is_whitelisted(ip) and behavior['risk_score'] > 0:
                risky_ips.append({
                    'ip': ip,
                    'risk_score': behavior['risk_score'],
                    'attack_count': behavior['attack_count'],
                    'request_count': behavior['request_count'],
                    'last_seen': behavior['last_seen'].isoformat() if behavior['last_seen'] else None
                })
        
        # 按风险评分排序
        risky_ips.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return risky_ips[:limit]
    
    def get_statistics(self) -> Dict:
        """获取分析器统计信息
        
        Returns:
            统计信息
        """
        total_ips = len(self.ip_behaviors)
        whitelisted_count = sum(1 for ip in self.ip_behaviors.keys() if self.is_whitelisted(ip))
        
        risk_distribution = {'low': 0, 'medium': 0, 'high': 0}
        total_attacks = 0
        total_requests = 0
        
        for behavior in self.ip_behaviors.values():
            total_attacks += behavior['attack_count']
            total_requests += behavior['request_count']
            
            risk_score = behavior['risk_score']
            if risk_score < 30:
                risk_distribution['low'] += 1
            elif risk_score < 70:
                risk_distribution['medium'] += 1
            else:
                risk_distribution['high'] += 1
        
        return {
            'total_ips': total_ips,
            'whitelisted_ips': whitelisted_count,
            'monitored_ips': total_ips - whitelisted_count,
            'total_requests': total_requests,
            'total_attacks': total_attacks,
            'attack_rate': total_attacks / total_requests if total_requests > 0 else 0,
            'risk_distribution': risk_distribution,
            'geo_cache_size': len(self.geo_cache)
        }
    
    def cleanup_old_data(self, max_age_days: int = 7):
        """清理旧数据
        
        Args:
            max_age_days: 最大保留天数
        """
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        
        # 清理IP行为数据
        expired_ips = []
        for ip, behavior in self.ip_behaviors.items():
            if behavior['last_seen'] and behavior['last_seen'] < cutoff_time:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            del self.ip_behaviors[ip]
        
        # 清理地理位置缓存
        current_time = time.time()
        expired_geo_keys = [
            ip for ip, cache_entry in self.geo_cache.items()
            if current_time - cache_entry['timestamp'] > self.geo_cache_ttl
        ]
        
        for ip in expired_geo_keys:
            del self.geo_cache[ip]
        
        print(f"清理完成: 删除了 {len(expired_ips)} 个过期IP记录和 {len(expired_geo_keys)} 个过期地理位置缓存")
    
    def export_data(self, filepath: str):
        """导出分析数据
        
        Args:
            filepath: 导出文件路径
        """
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'top_risky_ips': self.get_top_risky_ips(50),
            'ip_behaviors': {}
        }
        
        # 导出IP行为数据（序列化处理）
        for ip, behavior in self.ip_behaviors.items():
            export_data['ip_behaviors'][ip] = {
                'first_seen': behavior['first_seen'].isoformat() if behavior['first_seen'] else None,
                'last_seen': behavior['last_seen'].isoformat() if behavior['last_seen'] else None,
                'request_count': behavior['request_count'],
                'attack_count': behavior['attack_count'],
                'risk_score': behavior['risk_score'],
                'status_codes': dict(behavior['status_codes']),
                'unique_user_agents': len(behavior['user_agents']),
                'unique_paths': len(behavior['paths']),
                'countries': list(behavior['countries']),
                'ban_count': len(behavior['ban_history'])
            }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"数据已导出到: {filepath}")


if __name__ == '__main__':
    # 测试IP分析器
    config = {
        'analysis': {
            'ban_rules': {
                'risk_threshold': 70,
                'attack_threshold': 5,
                'not_found_threshold': 10,
                'request_rate_threshold': 30
            }
        },
        'whitelist': {
            'ips': ['127.0.0.1', '::1'],
            'networks': ['192.168.0.0/16', '10.0.0.0/8']
        }
    }
    
    async def test_analyzer():
        analyzer = IPAnalyzer(config)
        
        print("=== IP分析器测试 ===")
        
        # 测试正常请求
        normal_log = {
            'remote_addr': '203.0.113.1',
            'request_uri': '/index.html',
            'http_user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'status': 200
        }
        
        result = await analyzer.analyze_ip('203.0.113.1', normal_log)
        print(f"\n正常请求分析: {result['ip']} - 风险评分: {result['risk_score']:.1f}")
        
        # 模拟攻击请求
        attack_logs = [
            {
                'remote_addr': '198.51.100.1',
                'request_uri': '/admin/login.php',
                'http_user_agent': 'sqlmap/1.0',
                'status': 404
            },
            {
                'remote_addr': '198.51.100.1',
                'request_uri': '/wp-admin/',
                'http_user_agent': 'Nikto/2.1.6',
                'status': 404
            },
            {
                'remote_addr': '198.51.100.1',
                'request_uri': '/phpmyadmin/',
                'http_user_agent': 'dirb/2.22',
                'status': 404
            }
        ]
        
        print("\n=== 攻击行为模拟 ===")
        
        for i, log in enumerate(attack_logs):
            result = await analyzer.analyze_ip('198.51.100.1', log, f'scanning_attack_{i}')
            print(f"攻击 {i+1}: 风险评分 {result['risk_score']:.1f}, 应封禁: {result['should_ban']}")
            
            if result['should_ban']:
                analyzer.record_ban('198.51.100.1', result['reason'], 3600)
                print(f"  封禁原因: {result['reason']}")
        
        # 测试白名单
        print("\n=== 白名单测试 ===")
        
        whitelist_log = {
            'remote_addr': '192.168.1.100',
            'request_uri': '/admin/test',
            'http_user_agent': 'test-agent',
            'status': 200
        }
        
        result = await analyzer.analyze_ip('192.168.1.100', whitelist_log, 'test_attack')
        print(f"白名单IP测试: {result['ip']} - 白名单: {result['whitelisted']}")
        
        # 获取统计信息
        print("\n=== 统计信息 ===")
        stats = analyzer.get_statistics()
        for key, value in stats.items():
            print(f"{key}: {value}")
        
        # 获取风险IP列表
        print("\n=== 高风险IP ===")
        risky_ips = analyzer.get_top_risky_ips(5)
        for ip_info in risky_ips:
            print(f"IP: {ip_info['ip']}, 风险评分: {ip_info['risk_score']:.1f}, 攻击次数: {ip_info['attack_count']}")
        
        # 获取详细报告
        print("\n=== IP详细报告 ===")
        report = analyzer.get_ip_report('198.51.100.1')
        if report:
            print(f"IP: {report['ip']}")
            print(f"风险评分: {report['risk_score']:.1f}")
            print(f"总请求数: {report['behavior_summary']['total_requests']}")
            print(f"攻击次数: {report['behavior_summary']['attack_count']}")
            print(f"封禁次数: {report['behavior_summary']['ban_count']}")
    
    asyncio.run(test_analyzer())
    print("\nIP分析器测试完成")