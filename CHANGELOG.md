# 更新记录✨

## V1.2 - 2024-11-17

- 修复已知问题
  - 多Session会话共存
  - 文件上传bug修复
- 新增漏洞模块：验证码安全(图形验证码、短信验证码)

## V1.1 - 2024-11-10

- 修复已知问题
- 平台页面UI：简化对应缺陷/安全代码、优化DashBoard页面
- 新增漏洞模块：IDOR(水平/垂直越权)、拒绝服务、XPATH注入

## V1.0 - 2024-10
- 初始功能实现：跨站脚本（XSS）、SQL 注入、任意文件上传、SSRF、XXE、CSRF、CORS、JSONP、RCE、URL 重定向、XFF 伪造、敏感信息泄漏、SPEL 注入、SSTI 注入、反序列化、组件漏洞等。

## 系统设计 - 2024-05

- 完成系统技术选型、架构设计、相关靶场项目调研……
- 技术栈：**SpringBoot+Spring Security+MyBatis+Thymeleaf+Layui**
- 这里暂时只做了简单认证实现、权限分级/人员管理等复杂鉴权功能后续待实现……
- 架构设计：前后端不分离，在通用后端管理框架基础上，添加一个个漏洞模块……
- 参考项目：[Hello-Java-Sec](https://github.com/j3ers3/Hello-Java-Sec) [JavaSec](https://github.com/j3ers3/Hello-Java-Sec)

## 灵感来源 - 2024-03
- 一个想法💡
