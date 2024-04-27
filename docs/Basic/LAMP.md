# 搭建LAMP环境

LAMP是`Linux+Apache+MySQL+PHP`的简称。

Linux作为操作系统，Linux提供了稳定、可靠的基础。建议选择`Ubuntu 22.04`。

Apache是一个流行的Web服务器，用于处理HTTP请求。它支持动态内容、静态文件和虚拟主机。

MySQL是一个开源的关系型数据库管理系统（RDBMS）。它用于存储和检索数据。

PHP是用于编写服务器端脚本的编程语言。它们与Apache和MySQL一起工作，用于创建动态Web页面。

## 安装Apache

```bash
sudo apt install apache2 -y
```

## 安装PHP

```bash
sudo apt install php libapache2-mod-php php-mysql -y
```

## 安装Maridb


## 运行测试