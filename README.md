#### 关于
这里是专门收集各大监控摄像头和路由器漏洞的POC仓库


#### 怎么使用

```
# 运行全部的脚本
nmap --script vuln-detect 0.0.0.0/24


# 运行海康摄像头漏洞检测脚本
nmap --script hkvision 0.0.0.0/24


# 运行锐捷摄像头漏洞检测脚本
nmap --script ruijie 0.0.0.0/24


# 运行LG摄像头漏洞检测脚本
nmap --script LG 0.0.0.24
```

---
that's all
