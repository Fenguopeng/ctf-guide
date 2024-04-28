# 网站工作原理

## 术语

### IP地址

`127.0.0.1`为环回地址（loopback address），指代本机，用于同一台计算机内部网络通信。 

`0.0.0.0`为通配地址，在服务器配置中，设置为`0.0.0.0`上监听，意味着它接受分配给机器的任何IP地址上的连接。

### 端口

计算机的端口范围是`0-65535`，由于端口号大小为4字节，也就是32比特，所以最小端口号为0，最大端口号$2^{32}-1=65535$。这些端口可分为三大类：


|类别名称|端口范围|说明|例子|
|--|--|--|--|
|系统端口（System Ports），也称为知名端口（well-known ports）|`0-1023`|由互联网号码分配机构（IANA）分配|SSH使用22端口，HTTP使用80端口|
|用户端口（User Ports），也称为注册端口（Registered Ports）|`1024-49151`|由互联网号码分配机构（IANA）分配。用于特定协议或应用程序的网络端口。|Microsoft SQL Server使用1433端口，MySQL数据库使用3306端口，Redis数据库使用6379端口|
|动态端口（Dynamic Ports），也称为私有或临时端口（Private or Ephemeral Ports）|`49152-65535`|当进程或应用程序需要进行网络通信时，临时分配的端口，通常不固定分配给某种服务||

可以使用`netstat -an`命令查看当前的网络连接情况。

参考资料

- [IANA - Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

### 域名

用户与互联网上某台主机通信时，必须知道对方的IP地址。然后IP地址很难被记住，为了用户方便记忆各种网络应用，就有了域名。

域名的结构通常包括顶级域名（TLD）、二级域名和可能的子域名。以下是域名的一些基本概念：

顶级域名（TLD）：域名的最右边部分，如 .com、.org、.net 等。
二级域名：顶级域名左边的部分，通常是组织或公司的名称，如 google 在 google.com。
子域名：二级域名左边的部分，可以用来指向组织内部的不同服务或部门，如 mail 在 mail.google.com。

域名系统（DNS）负责将这些易于记忆的域名转换为机器可读的IP地址，如将 google.com 转换为 192.168.1.1。这个转换过程是通过互联网上的DNS服务器自动完成的。

域名解析的过程：

1. 查找本地的`hosts`文件，Windows系统`C:\Windows\System32\drivers\etc\hosts`  Linux系统`/etc/hosts`
2. DNS（Domain Name System，域名系统）解析，根据本地设置的DNS服务器地址，进行DNS解析。


## 访问网站