# 搭建PHP Web环境

## 搭建WAMP环境

### [phpStudy](https://www.xp.cn/)

phpStudy 是国内一款免费的 PHP 调试环境的程序集成包，集成了`Apache2`、`Nginx`、`MySQL`和`PHP`等等软件，最重要的是支持切换软件的不同版本。

![phpStudy](https://www.xp.cn/static/images/mac.png)

2019 年，phpStudy 后门供应链攻击。

### [WampServer](https://www.wampserver.com/en/)

## 搭建LAMP环境

LAMP 是`Linux+Apache+MySQL+PHP`的简称。

Linux 作为操作系统，Linux 提供了稳定、可靠的基础。建议选择`Ubuntu 22.04`。

Apache 是一个流行的 Web 服务器，用于处理 HTTP 请求。它支持动态内容、静态文件和虚拟主机。

MySQL 是一个开源的关系型数据库管理系统（RDBMS）。它用于存储和检索数据。

PHP 是用于编写服务器端脚本的编程语言。它们与 Apache 和 MySQL 一起工作，用于创建动态 Web 页面。

### 安装Apache

```bash
sudo apt install apache2 -y
```

### 安装PHP

PHP 与 Apache 协同工作，PHP 有两种安装模式，第一个是 PHP 嵌入到服务器端软件（如 Apache）作为一个模块安装。

第二个是以 CGI（Common Gateway Interface，公共网关接口）的模式安装，CGI 是外部扩展应用程序与 Web 服务器交互的一个标准接口。

```bash
sudo apt install php libapache2-mod-php php-mysql -y
```

### 安装Maridb

### 运行测试
