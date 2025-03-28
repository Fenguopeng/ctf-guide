# 网站工作原理

## 术语

### IP 地址

`127.0.0.1` 是环回地址（loopback address），指代本机，用于同一台计算机的内部网络通信。

`0.0.0.0` 是通配地址，设置为 `0.0.0.0` 监听表示接受分配给机器的任何 IP 地址上的连接。

### 端口

计算机的端口范围是 `0-65535`，由于端口号大小为 4 字节（32 位），因此最小端口号为 0，最大端口号$2^{32}-1=65535$。虽然理论上可以使用整个范围，但常用的可用端口号从 1 开始。

这些端口可分为三大类：

| 类别名称                                                                      | 端口范围      | 说明                                                                         | 例子                                                                                        |
| ----------------------------------------------------------------------------- | ------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| 系统端口（System Ports），也称为知名端口（well-known ports）                  | `0-1023`      | 由互联网号码分配机构（IANA）分配                                             | SSH 使用 22 端口，HTTP 使用 80 端口                                                         |
| 用户端口（User Ports），也称为注册端口（Registered Ports）                    | `1024-49151`  | 由互联网号码分配机构（IANA）分配。用于特定协议或应用程序的网络端口。         | Microsoft SQL Server 使用 1433 端口，MySQL 数据库使用 3306 端口，Redis 数据库使用 6379 端口 |
| 动态端口（Dynamic Ports），也称为私有或临时端口（Private or Ephemeral Ports） | `49152-65535` | 当进程或应用程序需要进行网络通信时，临时分配的端口，通常不固定分配给某种服务 |                                                                                             |

可以使用`netstat -an`命令查看当前网络连接情况。

参考资料

- [IANA - Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

### 域名

用户与互联网上的主机通信时，必须知道对方的 IP 地址，但是记住 IP 地址较难，因此出现了域名，以便于使用各种网络应用。

域名的结构通常包括顶级域名（TLD）、二级域名和可能的子域名。基本概念如下：

顶级域名（TLD）：域名最右侧部分，如 `.com`、`.org`、`.net` 等。
二级域名：顶级域名左侧部分，通常是组织或公司的名称，如 `google` 在 google.com。
子域名：二级域名左侧部分，可用于指向组织内部的不同服务或部门，如 mail 在 mail.google.com。

域名系统（Domain Name System，DNS）负责将这些易于记忆的域名转换为机器可读的 IP 地址，例如将 google.com 转换为 192.168.1.1。这个转换过程是由互联网上的 DNS 服务器自动完成。

域名解析的过程如下：

1. 查找本地的`hosts`文件，Windows 系统位于 `C:\Windows\System32\drivers\etc\hosts`，Linux 系统位于`/etc/hosts`
2. DNS解析，依据本地设置的 DNS 服务器地址进行解析。

## 访问网站
