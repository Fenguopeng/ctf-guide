# PHP文件包含

把可重复使用的函数写入到单个文件中，在使用该函数时，直接调用此文件，无需再次编写函数。这一过程被称为包含。

`include()`
`include_once()`
`require()`
`require_once()`

在通过 PHP 函数引入文件时，如果传入的文件名没有经过合理的校验，从而操作了预想之外的文件，就可能导致意外的文件泄露甚至恶意的代码注入。

文件包含漏洞分为两个类型，分别本地文件包含（Local File Inclusion，LFI）和远程文件包含（Remote File Inclusion，RFI）

> 文件包含的文件无须是`php`后缀，只要文件内容符合PHP语法规范，任何扩展名都可以执行

```php
<?php
$file = $_GET['file'];
include($file);
```

## PHP 封装伪协议

PHP 带有很多内置 URL 风格的封装协议，可用于类似 fopen()、 copy()、 file_exists() 和 filesize() 的文件系统函数，[了解更多](https://www.php.net/manual/zh/wrappers.php)

`file`

### php://filter

```
php://filter/read=convert.base64-enccode/resource=
```

### data://

```url
?file=data://text/plain,<?php phpinfo();?>
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
//data:text/plain
```

### input://

### phar://

### zip://

```
?file=zip://./foo.zip#bar.txt
?file=phar://my.phar/somefile.php
```

> `phar://`读取phar文件时，会反序列化meta-data储存的信息

### convert.iconv:// and dechunk://

## 文件包含漏洞利用

- 包含上传的含有PHP代码的任意类型文件，比如图片木马
- 包含session文件

> 默认存放路径`/var/`
> phpinfo信息中，php.ini，PHP代码
session.save_path

- 包含服务器日志
- 读取服务器敏感文件

#### 泄露文件内容

#### PHP FILTER CHAINS: FILE READ FROM ERROR-BASED ORACLE

<https://github.com/synacktiv/php_filter_chains_oracle_exploit/>

## LFI2RCE

### session 文件包含

## 练习题

- ACTF2020新生赛 Include
- [羊城杯 2020]Easyphp2

## 参考资料
