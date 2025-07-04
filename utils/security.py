#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分布式Fail2ban系统 - 安全验证工具
"""

import hashlib
import hmac
import secrets
import time
from typing import Optional


def verify_api_key(provided_key: Optional[str], expected_key: str) -> bool:
    """验证API密钥
    
    Args:
        provided_key: 提供的API密钥
        expected_key: 期望的API密钥
    
    Returns:
        验证结果
    """
    if not provided_key or not expected_key:
        return False
    
    # 使用常量时间比较防止时序攻击
    return hmac.compare_digest(provided_key, expected_key)


def hash_ip(ip: str, salt: str = "fail2ban_distributed") -> str:
    """对IP地址进行哈希处理
    
    Args:
        ip: IP地址
        salt: 盐值
    
    Returns:
        哈希后的IP
    """
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]


def generate_api_key(length: int = 32) -> str:
    """生成安全的API密钥
    
    Args:
        length: 密钥长度
    
    Returns:
        生成的API密钥
    """
    return secrets.token_urlsafe(length)


def create_signature(data: str, secret: str) -> str:
    """创建数据签名
    
    Args:
        data: 要签名的数据
        secret: 签名密钥
    
    Returns:
        签名
    """
    return hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_signature(data: str, signature: str, secret: str) -> bool:
    """验证数据签名
    
    Args:
        data: 原始数据
        signature: 提供的签名
        secret: 签名密钥
    
    Returns:
        验证结果
    """
    expected_signature = create_signature(data, secret)
    return hmac.compare_digest(signature, expected_signature)


def create_timestamped_token(data: str, secret: str, ttl: int = 3600) -> str:
    """创建带时间戳的令牌
    
    Args:
        data: 数据
        secret: 密钥
        ttl: 生存时间（秒）
    
    Returns:
        令牌
    """
    timestamp = int(time.time())
    payload = f"{data}:{timestamp}:{ttl}"
    signature = create_signature(payload, secret)
    return f"{payload}:{signature}"


def verify_timestamped_token(token: str, secret: str) -> tuple[bool, Optional[str]]:
    """验证带时间戳的令牌
    
    Args:
        token: 令牌
        secret: 密钥
    
    Returns:
        (验证结果, 数据)
    """
    try:
        parts = token.split(':')
        if len(parts) != 4:
            return False, None
        
        data, timestamp_str, ttl_str, signature = parts
        timestamp = int(timestamp_str)
        ttl = int(ttl_str)
        
        # 检查时间戳
        current_time = int(time.time())
        if current_time > timestamp + ttl:
            return False, None
        
        # 验证签名
        payload = f"{data}:{timestamp}:{ttl}"
        if verify_signature(payload, signature, secret):
            return True, data
        
        return False, None
    
    except Exception:
        return False, None


class RateLimiter:
    """速率限制器"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # {client_id: [timestamps]}
    
    def is_allowed(self, client_id: str) -> bool:
        """检查是否允许请求
        
        Args:
            client_id: 客户端标识
        
        Returns:
            是否允许
        """
        current_time = time.time()
        
        # 获取客户端请求历史
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        client_requests = self.requests[client_id]
        
        # 清理过期请求
        cutoff_time = current_time - self.window_seconds
        client_requests[:] = [t for t in client_requests if t > cutoff_time]
        
        # 检查是否超过限制
        if len(client_requests) >= self.max_requests:
            return False
        
        # 记录当前请求
        client_requests.append(current_time)
        return True
    
    def get_remaining_requests(self, client_id: str) -> int:
        """获取剩余请求数
        
        Args:
            client_id: 客户端标识
        
        Returns:
            剩余请求数
        """
        if client_id not in self.requests:
            return self.max_requests
        
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        # 清理过期请求
        client_requests = self.requests[client_id]
        valid_requests = [t for t in client_requests if t > cutoff_time]
        
        return max(0, self.max_requests - len(valid_requests))
    
    def reset_client(self, client_id: str):
        """重置客户端限制
        
        Args:
            client_id: 客户端标识
        """
        if client_id in self.requests:
            del self.requests[client_id]


class IPWhitelist:
    """IP白名单管理器"""
    
    def __init__(self, whitelist_config: dict):
        self.ips = set(whitelist_config.get('ips', []))
        self.networks = whitelist_config.get('networks', [])
        self._compiled_networks = None
        self._compile_networks()
    
    def _compile_networks(self):
        """编译网络地址"""
        import ipaddress
        
        self._compiled_networks = []
        for network in self.networks:
            try:
                self._compiled_networks.append(ipaddress.ip_network(network))
            except ValueError as e:
                print(f"无效的网络地址: {network}, 错误: {e}")
    
    def is_whitelisted(self, ip: str) -> bool:
        """检查IP是否在白名单中
        
        Args:
            ip: IP地址
        
        Returns:
            是否在白名单中
        """
        # 检查IP白名单
        if ip in self.ips:
            return True
        
        # 检查网络白名单
        if self._compiled_networks:
            import ipaddress
            try:
                ip_obj = ipaddress.ip_address(ip)
                for network in self._compiled_networks:
                    if ip_obj in network:
                        return True
            except ValueError:
                pass
        
        return False
    
    def add_ip(self, ip: str):
        """添加IP到白名单
        
        Args:
            ip: IP地址
        """
        self.ips.add(ip)
    
    def remove_ip(self, ip: str):
        """从白名单移除IP
        
        Args:
            ip: IP地址
        """
        self.ips.discard(ip)
    
    def add_network(self, network: str):
        """添加网络到白名单
        
        Args:
            network: 网络地址
        """
        import ipaddress
        try:
            network_obj = ipaddress.ip_network(network)
            self.networks.append(network)
            self._compiled_networks.append(network_obj)
        except ValueError as e:
            raise ValueError(f"无效的网络地址: {network}, 错误: {e}")
    
    def get_whitelist(self) -> dict:
        """获取白名单配置
        
        Returns:
            白名单配置
        """
        return {
            'ips': list(self.ips),
            'networks': self.networks
        }


if __name__ == '__main__':
    # 测试安全工具
    
    # 测试API密钥验证
    api_key = generate_api_key()
    print(f"生成的API密钥: {api_key}")
    print(f"密钥验证: {verify_api_key(api_key, api_key)}")
    
    # 测试IP哈希
    ip = "192.168.1.100"
    hashed_ip = hash_ip(ip)
    print(f"IP {ip} 哈希: {hashed_ip}")
    
    # 测试签名
    data = "test data"
    secret = "test secret"
    signature = create_signature(data, secret)
    print(f"数据签名: {signature}")
    print(f"签名验证: {verify_signature(data, signature, secret)}")
    
    # 测试时间戳令牌
    token = create_timestamped_token("user123", secret, 60)
    print(f"时间戳令牌: {token}")
    valid, extracted_data = verify_timestamped_token(token, secret)
    print(f"令牌验证: {valid}, 数据: {extracted_data}")
    
    # 测试速率限制
    rate_limiter = RateLimiter(5, 10)
    client = "client1"
    
    for i in range(7):
        allowed = rate_limiter.is_allowed(client)
        remaining = rate_limiter.get_remaining_requests(client)
        print(f"请求 {i+1}: 允许={allowed}, 剩余={remaining}")
    
    # 测试IP白名单
    whitelist_config = {
        'ips': ['127.0.0.1', '::1'],
        'networks': ['192.168.0.0/16', '10.0.0.0/8']
    }
    
    whitelist = IPWhitelist(whitelist_config)
    test_ips = ['127.0.0.1', '192.168.1.100', '8.8.8.8', '10.0.0.1']
    
    for test_ip in test_ips:
        is_whitelisted = whitelist.is_whitelisted(test_ip)
        print(f"IP {test_ip} 白名单状态: {is_whitelisted}")
    
    print("安全工具测试完成")