#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - Nginx日志解析器
"""

import re
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Pattern


class NginxLogParser:
    """Nginx日志解析器"""
    
    # 预定义的日志格式
    LOG_FORMATS = {
        'combined': (
            r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) '
            r'\[(?P<time_local>[^\]]+)\] '
            r'"(?P<request>[^"]+)" '
            r'(?P<status>\d+) (?P<body_bytes_sent>\d+) '
            r'"(?P<http_referer>[^"]+)" '
            r'"(?P<http_user_agent>[^"]+)"'
        ),
        'common': (
            r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) '
            r'\[(?P<time_local>[^\]]+)\] '
            r'"(?P<request>[^"]+)" '
            r'(?P<status>\d+) (?P<body_bytes_sent>\d+)'
        ),
        'custom': (
            r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) '
            r'\[(?P<time_local>[^\]]+)\] '
            r'"(?P<request>[^"]+)" '
            r'(?P<status>\d+) (?P<body_bytes_sent>\d+) '
            r'"(?P<http_referer>[^"]+)" '
            r'"(?P<http_user_agent>[^"]+)" '
            r'(?P<request_time>\S+) (?P<upstream_response_time>\S+)'
        )
    }
    
    def __init__(self, log_format: str = 'combined'):
        self.log_format = log_format
        self.pattern: Optional[Pattern] = None
        self._compile_pattern()
    
    def _compile_pattern(self):
        """编译正则表达式模式"""
        if self.log_format in self.LOG_FORMATS:
            pattern_str = self.LOG_FORMATS[self.log_format]
        else:
            # 自定义格式
            pattern_str = self.log_format
        
        try:
            self.pattern = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"无效的日志格式正则表达式: {e}")
    
    def parse(self, log_line: str) -> Optional[Dict]:
        """解析单行日志
        
        Args:
            log_line: 日志行
        
        Returns:
            解析后的字典，如果解析失败返回None
        """
        if not self.pattern:
            return None
        
        match = self.pattern.match(log_line.strip())
        if not match:
            return None
        
        result = match.groupdict()
        
        # 后处理
        result = self._post_process(result)
        
        return result
    
    def _post_process(self, data: Dict) -> Dict:
        """后处理解析结果"""
        # 解析时间
        if 'time_local' in data:
            data['timestamp'] = self._parse_timestamp(data['time_local'])
        
        # 解析请求
        if 'request' in data:
            request_parts = self._parse_request(data['request'])
            data.update(request_parts)
        
        # 转换数值类型
        for field in ['status', 'body_bytes_sent']:
            if field in data and data[field].isdigit():
                data[field] = int(data[field])
        
        # 转换浮点数类型
        for field in ['request_time', 'upstream_response_time']:
            if field in data:
                try:
                    if data[field] != '-':
                        data[field] = float(data[field])
                    else:
                        data[field] = None
                except ValueError:
                    data[field] = None
        
        # 处理特殊字段
        for field in ['remote_user', 'http_referer']:
            if field in data and data[field] == '-':
                data[field] = None
        
        return data
    
    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """解析时间戳
        
        Args:
            timestamp_str: 时间戳字符串
        
        Returns:
            datetime对象
        """
        try:
            # Nginx默认时间格式: 27/Aug/2023:10:30:45 +0800
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            try:
                # 尝试其他格式
                return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
            except ValueError:
                return None
    
    def _parse_request(self, request_str: str) -> Dict:
        """解析请求字符串
        
        Args:
            request_str: 请求字符串，如 "GET /path HTTP/1.1"
        
        Returns:
            包含method, uri, protocol的字典
        """
        parts = request_str.split(' ', 2)
        
        result = {
            'request_method': parts[0] if len(parts) > 0 else '',
            'request_uri': parts[1] if len(parts) > 1 else '',
            'request_protocol': parts[2] if len(parts) > 2 else ''
        }
        
        # 解析URI
        if result['request_uri']:
            parsed_uri = urllib.parse.urlparse(result['request_uri'])
            result['request_path'] = parsed_uri.path
            result['request_query'] = parsed_uri.query
            result['request_fragment'] = parsed_uri.fragment
        
        return result


class LogAnalyzer:
    """日志分析器"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'sql_injection': [
                re.compile(r'union.*select', re.IGNORECASE),
                re.compile(r'drop.*table', re.IGNORECASE),
                re.compile(r'insert.*into', re.IGNORECASE),
                re.compile(r'delete.*from', re.IGNORECASE),
                re.compile(r'update.*set', re.IGNORECASE),
                re.compile(r'exec.*xp_', re.IGNORECASE),
            ],
            'xss': [
                re.compile(r'<script', re.IGNORECASE),
                re.compile(r'javascript:', re.IGNORECASE),
                re.compile(r'onerror=', re.IGNORECASE),
                re.compile(r'onload=', re.IGNORECASE),
                re.compile(r'onclick=', re.IGNORECASE),
            ],
            'path_traversal': [
                re.compile(r'\.\./'),
                re.compile(r'\\.\\.\\'),
                re.compile(r'%2e%2e%2f', re.IGNORECASE),
                re.compile(r'%2e%2e/'),
                re.compile(r'..%2f'),
            ],
            'command_injection': [
                re.compile(r';\s*(cat|ls|pwd|id|whoami)', re.IGNORECASE),
                re.compile(r'\|\s*(cat|ls|pwd|id|whoami)', re.IGNORECASE),
                re.compile(r'`.*`'),
                re.compile(r'\$\(.*\)'),
            ],
            'file_inclusion': [
                re.compile(r'\.\./', re.IGNORECASE),
                re.compile(r'/etc/passwd', re.IGNORECASE),
                re.compile(r'/etc/shadow', re.IGNORECASE),
                re.compile(r'php://filter', re.IGNORECASE),
                re.compile(r'data://', re.IGNORECASE),
            ]
        }
    
    def analyze_request(self, log_entry: Dict) -> Dict:
        """分析请求是否可疑
        
        Args:
            log_entry: 解析后的日志条目
        
        Returns:
            分析结果
        """
        result = {
            'is_suspicious': False,
            'attack_types': [],
            'risk_score': 0,
            'details': {}
        }
        
        # 获取要分析的字段
        uri = log_entry.get('request_uri', '')
        user_agent = log_entry.get('http_user_agent', '')
        referer = log_entry.get('http_referer', '')
        
        # 分析各种攻击模式
        for attack_type, patterns in self.suspicious_patterns.items():
            matches = []
            
            for pattern in patterns:
                # 检查URI
                if pattern.search(uri):
                    matches.append(f"URI: {pattern.pattern}")
                
                # 检查User-Agent
                if pattern.search(user_agent):
                    matches.append(f"User-Agent: {pattern.pattern}")
                
                # 检查Referer
                if referer and pattern.search(referer):
                    matches.append(f"Referer: {pattern.pattern}")
            
            if matches:
                result['is_suspicious'] = True
                result['attack_types'].append(attack_type)
                result['details'][attack_type] = matches
                result['risk_score'] += len(matches) * 10
        
        # 检查状态码异常
        status = log_entry.get('status', 200)
        if status >= 400:
            result['risk_score'] += 5
            if status == 404:
                result['details']['status_404'] = True
            elif status >= 500:
                result['details']['server_error'] = True
        
        # 检查请求大小异常
        body_bytes = log_entry.get('body_bytes_sent', 0)
        if body_bytes > 10 * 1024 * 1024:  # 大于10MB
            result['risk_score'] += 15
            result['details']['large_response'] = body_bytes
        
        # 检查请求时间异常
        request_time = log_entry.get('request_time')
        if request_time and request_time > 30:  # 超过30秒
            result['risk_score'] += 10
            result['details']['slow_request'] = request_time
        
        return result
    
    def is_bot_request(self, log_entry: Dict) -> bool:
        """判断是否为机器人请求
        
        Args:
            log_entry: 日志条目
        
        Returns:
            是否为机器人请求
        """
        user_agent = log_entry.get('http_user_agent', '').lower()
        
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'googlebot', 'bingbot', 'slurp', 'duckduckbot',
            'baiduspider', 'yandexbot', 'facebookexternalhit'
        ]
        
        return any(pattern in user_agent for pattern in bot_patterns)
    
    def extract_ip_info(self, log_entry: Dict) -> Dict:
        """提取IP相关信息
        
        Args:
            log_entry: 日志条目
        
        Returns:
            IP信息
        """
        ip = log_entry.get('remote_addr', '')
        
        result = {
            'ip': ip,
            'is_private': self._is_private_ip(ip),
            'is_localhost': ip in ['127.0.0.1', '::1'],
            'ip_type': 'unknown'
        }
        
        if result['is_localhost']:
            result['ip_type'] = 'localhost'
        elif result['is_private']:
            result['ip_type'] = 'private'
        else:
            result['ip_type'] = 'public'
        
        return result
    
    def _is_private_ip(self, ip: str) -> bool:
        """判断是否为私有IP
        
        Args:
            ip: IP地址
        
        Returns:
            是否为私有IP
        """
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False


class LogStatistics:
    """日志统计器"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """重置统计信息"""
        self.total_requests = 0
        self.status_codes = {}
        self.methods = {}
        self.ips = {}
        self.user_agents = {}
        self.suspicious_requests = 0
        self.bot_requests = 0
    
    def update(self, log_entry: Dict, analysis_result: Dict = None):
        """更新统计信息
        
        Args:
            log_entry: 日志条目
            analysis_result: 分析结果
        """
        self.total_requests += 1
        
        # 统计状态码
        status = log_entry.get('status', 0)
        self.status_codes[status] = self.status_codes.get(status, 0) + 1
        
        # 统计请求方法
        method = log_entry.get('request_method', 'UNKNOWN')
        self.methods[method] = self.methods.get(method, 0) + 1
        
        # 统计IP
        ip = log_entry.get('remote_addr', 'unknown')
        self.ips[ip] = self.ips.get(ip, 0) + 1
        
        # 统计User-Agent
        user_agent = log_entry.get('http_user_agent', 'unknown')
        self.user_agents[user_agent] = self.user_agents.get(user_agent, 0) + 1
        
        # 统计可疑请求
        if analysis_result and analysis_result.get('is_suspicious'):
            self.suspicious_requests += 1
    
    def get_top_ips(self, limit: int = 10) -> List[tuple]:
        """获取访问量最高的IP
        
        Args:
            limit: 返回数量限制
        
        Returns:
            IP和访问次数的元组列表
        """
        return sorted(self.ips.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_top_user_agents(self, limit: int = 10) -> List[tuple]:
        """获取最常见的User-Agent
        
        Args:
            limit: 返回数量限制
        
        Returns:
            User-Agent和出现次数的元组列表
        """
        return sorted(self.user_agents.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def get_summary(self) -> Dict:
        """获取统计摘要
        
        Returns:
            统计摘要
        """
        return {
            'total_requests': self.total_requests,
            'unique_ips': len(self.ips),
            'suspicious_requests': self.suspicious_requests,
            'bot_requests': self.bot_requests,
            'status_codes': dict(sorted(self.status_codes.items())),
            'methods': dict(sorted(self.methods.items(), key=lambda x: x[1], reverse=True)),
            'suspicious_rate': self.suspicious_requests / max(self.total_requests, 1) * 100
        }


if __name__ == '__main__':
    # 测试日志解析器
    parser = NginxLogParser('combined')
    analyzer = LogAnalyzer()
    stats = LogStatistics()
    
    # 测试日志行
    test_logs = [
        '192.168.1.100 - - [27/Aug/2023:10:30:45 +0800] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '10.0.0.1 - - [27/Aug/2023:10:31:00 +0800] "POST /login.php HTTP/1.1" 200 567 "http://example.com" "curl/7.68.0"',
        '192.168.1.200 - - [27/Aug/2023:10:31:15 +0800] "GET /admin.php?id=1 union select * from users HTTP/1.1" 404 0 "-" "sqlmap/1.0"',
        '172.16.0.50 - - [27/Aug/2023:10:31:30 +0800] "GET /../../../etc/passwd HTTP/1.1" 403 0 "-" "Nikto/2.1.6"'
    ]
    
    print("=== Nginx日志解析测试 ===")
    
    for log_line in test_logs:
        print(f"\n原始日志: {log_line}")
        
        # 解析日志
        parsed = parser.parse(log_line)
        if parsed:
            print(f"解析结果: {parsed['remote_addr']} {parsed['request_method']} {parsed['request_uri']} {parsed['status']}")
            
            # 分析请求
            analysis = analyzer.analyze_request(parsed)
            if analysis['is_suspicious']:
                print(f"⚠️  可疑请求检测到: {analysis['attack_types']}, 风险评分: {analysis['risk_score']}")
                print(f"详情: {analysis['details']}")
            
            # 更新统计
            stats.update(parsed, analysis)
        else:
            print("❌ 解析失败")
    
    print("\n=== 统计摘要 ===")
    summary = stats.get_summary()
    for key, value in summary.items():
        print(f"{key}: {value}")
    
    print("\n=== Top IPs ===")
    for ip, count in stats.get_top_ips(5):
        print(f"{ip}: {count} 次访问")
    
    print("\n日志解析器测试完成")