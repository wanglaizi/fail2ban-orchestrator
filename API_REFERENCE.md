# API 参考文档

本文档提供 Fail2ban 增强系统的完整 API 参考。

## 目录

- [认证 API](#认证-api)
- [租户管理 API](#租户管理-api)
- [用户管理 API](#用户管理-api)
- [IP 管理 API](#ip-管理-api)
- [告警管理 API](#告警管理-api)
- [监控 API](#监控-api)
- [配置管理 API](#配置管理-api)
- [系统 API](#系统-api)
- [错误代码](#错误代码)
- [SDK 示例](#sdk-示例)

## 基础信息

### 基础 URL

```
http://localhost:8080/api/v1
```

### 认证方式

所有 API 请求需要在 Header 中包含认证信息：

```http
Authorization: Bearer <token>
Content-Type: application/json
```

### 响应格式

所有 API 响应都遵循统一格式：

```json
{
  "code": 200,
  "message": "success",
  "data": {},
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 认证 API

### 登录

获取访问令牌。

**请求**

```http
POST /auth/login
```

**请求体**

```json
{
  "username": "admin",
  "password": "password",
  "tenant_id": "default"
}
```

**响应**

```json
{
  "code": 200,
  "message": "登录成功",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "user_info": {
      "id": "user_001",
      "username": "admin",
      "role": "admin",
      "tenant_id": "default"
    }
  }
}
```

### 登出

注销当前会话。

**请求**

```http
POST /auth/logout
```

**响应**

```json
{
  "code": 200,
  "message": "登出成功"
}
```

### 刷新令牌

刷新访问令牌。

**请求**

```http
POST /auth/refresh
```

**请求体**

```json
{
  "refresh_token": "refresh_token_here"
}
```

## 租户管理 API

### 获取租户列表

**请求**

```http
GET /tenants?page=1&size=10&search=keyword
```

**响应**

```json
{
  "code": 200,
  "data": {
    "items": [
      {
        "id": "tenant_001",
        "name": "默认租户",
        "description": "系统默认租户",
        "status": "active",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "size": 10
  }
}
```

### 创建租户

**请求**

```http
POST /tenants
```

**请求体**

```json
{
  "name": "新租户",
  "description": "租户描述",
  "config": {
    "max_users": 100,
    "max_ips": 1000
  }
}
```

### 获取租户详情

**请求**

```http
GET /tenants/{tenant_id}
```

### 更新租户

**请求**

```http
PUT /tenants/{tenant_id}
```

### 删除租户

**请求**

```http
DELETE /tenants/{tenant_id}
```

## 用户管理 API

### 获取用户列表

**请求**

```http
GET /users?tenant_id=default&page=1&size=10
```

**响应**

```json
{
  "code": 200,
  "data": {
    "items": [
      {
        "id": "user_001",
        "username": "admin",
        "email": "admin@example.com",
        "role": "admin",
        "status": "active",
        "tenant_id": "default",
        "last_login": "2024-01-01T00:00:00Z",
        "created_at": "2024-01-01T00:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "size": 10
  }
}
```

### 创建用户

**请求**

```http
POST /users
```

**请求体**

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "password123",
  "role": "user",
  "tenant_id": "default"
}
```

## IP 管理 API

### 获取被封禁 IP 列表

**请求**

```http
GET /ips/banned?tenant_id=default&page=1&size=10
```

**响应**

```json
{
  "code": 200,
  "data": {
    "items": [
      {
        "ip": "192.168.1.100",
        "reason": "多次登录失败",
        "banned_at": "2024-01-01T00:00:00Z",
        "expires_at": "2024-01-01T01:00:00Z",
        "jail": "ssh",
        "tenant_id": "default"
      }
    ],
    "total": 1,
    "page": 1,
    "size": 10
  }
}
```

### 封禁 IP

**请求**

```http
POST /ips/ban
```

**请求体**

```json
{
  "ip": "192.168.1.100",
  "jail": "ssh",
  "duration": 3600,
  "reason": "手动封禁",
  "tenant_id": "default"
}
```

### 解封 IP

**请求**

```http
POST /ips/unban
```

**请求体**

```json
{
  "ip": "192.168.1.100",
  "jail": "ssh",
  "tenant_id": "default"
}
```

## 告警管理 API

### 获取告警列表

**请求**

```http
GET /alerts?status=active&severity=high&page=1&size=10
```

**响应**

```json
{
  "code": 200,
  "data": {
    "items": [
      {
        "id": "alert_001",
        "title": "异常登录尝试",
        "description": "检测到来自 192.168.1.100 的异常登录尝试",
        "severity": "high",
        "status": "active",
        "source": "ssh",
        "tenant_id": "default",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-01T00:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "size": 10
  }
}
```

### 确认告警

**请求**

```http
POST /alerts/{alert_id}/acknowledge
```

**请求体**

```json
{
  "comment": "已处理"
}
```

## 监控 API

### 获取系统指标

**请求**

```http
GET /monitoring/metrics?start_time=2024-01-01T00:00:00Z&end_time=2024-01-01T23:59:59Z
```

**响应**

```json
{
  "code": 200,
  "data": {
    "cpu_usage": 45.2,
    "memory_usage": 68.5,
    "disk_usage": 32.1,
    "network_io": {
      "bytes_sent": 1024000,
      "bytes_recv": 2048000
    },
    "fail2ban_stats": {
      "total_bans": 150,
      "active_bans": 25,
      "total_jails": 5
    }
  }
}
```

### 获取健康状态

**请求**

```http
GET /monitoring/health
```

**响应**

```json
{
  "code": 200,
  "data": {
    "status": "healthy",
    "services": {
      "database": "healthy",
      "redis": "healthy",
      "fail2ban": "healthy"
    },
    "uptime": 86400,
    "version": "1.0.0"
  }
}
```

## 配置管理 API

### 获取配置

**请求**

```http
GET /config?tenant_id=default
```

### 更新配置

**请求**

```http
PUT /config
```

**请求体**

```json
{
  "tenant_id": "default",
  "config": {
    "ban_time": 3600,
    "find_time": 600,
    "max_retry": 5
  }
}
```

### 验证配置

**请求**

```http
POST /config/validate
```

### 导出配置

**请求**

```http
GET /config/export?tenant_id=default&format=yaml
```

### 导入配置

**请求**

```http
POST /config/import
```

## 系统 API

### 获取系统信息

**请求**

```http
GET /system/info
```

**响应**

```json
{
  "code": 200,
  "data": {
    "version": "1.0.0",
    "build_time": "2024-01-01T00:00:00Z",
    "python_version": "3.9.0",
    "platform": "Linux",
    "features": {
      "multi_tenancy": true,
      "ml_detection": true,
      "web_interface": true
    }
  }
}
```

## 错误代码

| 代码 | 说明 | 描述 |
|------|------|------|
| 200 | 成功 | 请求成功 |
| 400 | 请求错误 | 请求参数错误 |
| 401 | 未授权 | 认证失败或令牌无效 |
| 403 | 禁止访问 | 权限不足 |
| 404 | 未找到 | 资源不存在 |
| 409 | 冲突 | 资源已存在 |
| 422 | 参数错误 | 请求参数验证失败 |
| 500 | 服务器错误 | 内部服务器错误 |
| 503 | 服务不可用 | 服务暂时不可用 |

## SDK 示例

### Python SDK

```python
import requests

class Fail2banAPI:
    def __init__(self, base_url, token=None):
        self.base_url = base_url
        self.token = token
        self.session = requests.Session()
        if token:
            self.session.headers.update({
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            })
    
    def login(self, username, password, tenant_id='default'):
        """用户登录"""
        response = self.session.post(f'{self.base_url}/auth/login', json={
            'username': username,
            'password': password,
            'tenant_id': tenant_id
        })
        if response.status_code == 200:
            data = response.json()
            self.token = data['data']['token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}'
            })
        return response.json()
    
    def get_banned_ips(self, tenant_id='default', page=1, size=10):
        """获取被封禁的IP列表"""
        response = self.session.get(f'{self.base_url}/ips/banned', params={
            'tenant_id': tenant_id,
            'page': page,
            'size': size
        })
        return response.json()
    
    def ban_ip(self, ip, jail='ssh', duration=3600, reason='API ban', tenant_id='default'):
        """封禁IP"""
        response = self.session.post(f'{self.base_url}/ips/ban', json={
            'ip': ip,
            'jail': jail,
            'duration': duration,
            'reason': reason,
            'tenant_id': tenant_id
        })
        return response.json()
    
    def unban_ip(self, ip, jail='ssh', tenant_id='default'):
        """解封IP"""
        response = self.session.post(f'{self.base_url}/ips/unban', json={
            'ip': ip,
            'jail': jail,
            'tenant_id': tenant_id
        })
        return response.json()

# 使用示例
api = Fail2banAPI('http://localhost:8080/api/v1')

# 登录
result = api.login('admin', 'password')
print(f"登录结果: {result}")

# 获取被封禁的IP
banned_ips = api.get_banned_ips()
print(f"被封禁的IP: {banned_ips}")

# 封禁IP
ban_result = api.ban_ip('192.168.1.100', reason='测试封禁')
print(f"封禁结果: {ban_result}")
```

### JavaScript SDK

```javascript
class Fail2banAPI {
    constructor(baseUrl, token = null) {
        this.baseUrl = baseUrl;
        this.token = token;
    }
    
    async request(method, endpoint, data = null) {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        const config = {
            method,
            headers
        };
        
        if (data) {
            config.body = JSON.stringify(data);
        }
        
        const response = await fetch(`${this.baseUrl}${endpoint}`, config);
        return await response.json();
    }
    
    async login(username, password, tenantId = 'default') {
        const result = await this.request('POST', '/auth/login', {
            username,
            password,
            tenant_id: tenantId
        });
        
        if (result.code === 200) {
            this.token = result.data.token;
        }
        
        return result;
    }
    
    async getBannedIps(tenantId = 'default', page = 1, size = 10) {
        return await this.request('GET', 
            `/ips/banned?tenant_id=${tenantId}&page=${page}&size=${size}`);
    }
    
    async banIp(ip, jail = 'ssh', duration = 3600, reason = 'API ban', tenantId = 'default') {
        return await this.request('POST', '/ips/ban', {
            ip,
            jail,
            duration,
            reason,
            tenant_id: tenantId
        });
    }
}

// 使用示例
const api = new Fail2banAPI('http://localhost:8080/api/v1');

// 登录
api.login('admin', 'password').then(result => {
    console.log('登录结果:', result);
    
    // 获取被封禁的IP
    return api.getBannedIps();
}).then(bannedIps => {
    console.log('被封禁的IP:', bannedIps);
});
```

---

**注意**: 本文档基于 API v1 版本。更多详细信息和最新更新请参考项目文档。