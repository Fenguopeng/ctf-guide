# PHP语法基础

PHP作为“世界上最好的语言”，是目前CTF Web题目中的考查热点。

当前主流版本有`5.[56].x`、`7.[01234].x`和`8.[0123].x`。

在命令行模式下运行PHP代码的方法如下：

```bash
# 交互模式
php -a

# 执行代码，不包括标记
php -r <code>

# 执行指定文件
php -f scriptname.php
```

此外，强烈推荐[PHP在线平台](https://onlinephp.io/)，支持多种PHP版本。


## 基本语法
### 标记

开始标记、结束标记

- 普通标记`<?php ?>`
- 短标记`<? ?>`
  - 短标记是被默认开启的，但是也可以通过设置`short_open_tag`来禁用
- `<?=`
  - `<?php echo`的简写形式，不受`short_open_tag` 控制
- ASP风格标记 `<% %>` 、`<%=`
  - 自PHP 7.0.0起 ，被移除
  - 默认关闭，须将`asp_tags`设置为On
- 脚本标记 `<script language="php"`
  - 自PHP 7.0.0起，被移除
  - eg. `<script language="php">system("id"); </script>`

### 指令分隔符

PHP需要在每个语句后用`分号`结束指令，一段 PHP 代码中的结束标记隐含表示了一个分号；在一个 PHP 代码段中的最后一行可以不用分号结束。

文件末尾的 PHP 代码段结束标记可以不要，有些情况下当使用 include 或者 require 时省略掉会更好些，这样不期望的空白符就不会出现在文件末尾，之后仍然可以输出响应标头。

## 类型

常用类型如下：

- [NULL](https://www.php.net/manual/zh/language.types.null.php)
  - 仅有一个值`null`，未定义和`unset()`的变量都将解析为值`null`。
- [Boolean布尔类型](https://www.php.net/manual/zh/language.types.boolean.php)
- [Integer整型](https://www.php.net/manual/zh/language.types.integer.php)
  - 可以使用十进制，**十六进制**，八进制或二进制表示。
- [Float浮点型](https://www.php.net/manual/zh/language.types.float.php)
  - **科学计数法**
- [String字符串](https://www.php.net/manual/zh/language.types.string.php)
  - 单引号，双引号字符串支持变量解析
  - [数字字符串](https://www.php.net/manual/zh/language.types.numeric-strings.php)，如果一个 PHP string 可以被解释为`int`或 `float`类型，则它被视为`数字字符串`。
  - `前导数字字符串`，其开头类似于数字字符串，后跟任何字符，如`123a`。
  - `前导数字字符串`不是数字字符串，`is_numeric('123a')`返回`false`。
- [Array数组](https://www.php.net/manual/zh/language.types.array.php)
  - 从PHP 7.1.O 起，支持`[]`数组解包，`[$foo, $bar, $baz] = $source_array;`

### 双引号字符串中含有`RTLO`等格式字符

[格式字符介绍](https://www.w3.org/International/questions/qa-bidi-unicode-controls#basedirection)

RTLO字符，全称为Right-to-Left Override，是一个Unicode控制字符，编码为U+202E。它的作用是改变文本的显示方向，使其从右向左显示，这对于支持阿拉伯语、希伯来语等从右向左书写的语言非常有用。

```php
echo "\u{202E}abc"; // cba
```

PHP的代码高亮函数，其颜色显示是根据`php.ini`定义显示，注释、默认、HTML、关键词和字符串显示不同颜色。

![](http://oss.dropsec.xyz/book/phpinfo-highlight.png)


假设我们需要遇到这样一道题目，浏览器显示源码如图所示。

![](http://oss.dropsec.xyz/book/RTLO1.png)

图中有三个注释，其中第三个`//sha2`显示的颜色与前两个不同。原因在于真正的`$_GET`参数不是所谓看见的`sha2`，而是包含有控制字符的字符串，导致浏览器渲染显示时产生位置偏移，我们需要从十六进制层面获取真正的参数名称。可通过`burp`或`wireshark`抓包，也可以直接复制粘贴代码，获取参数值。由于是不可打印字符，发送时需要URL编码。

在做题中，可以通过颜色判断或者鼠标双击选择变量，来发现是否设置了考点。

- Hack.lu CTF 2018 Baby PHP
- ISCC 2023 小周的密码锁

## [变量](https://www.php.net/manual/zh/language.variables.basics.php)

PHP 中的变量用一个美元符号后面跟变量名来表示。变量名是**区分大小写**的。

变量名与 PHP 中其它的标签一样遵循相同的规则。一个有效的变量名由字母或者下划线开头，后面跟上任意数量的字母，数字，或者下划线。正则表达式为`^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$`。

!> 在此所说的字母是 a-z，A-Z，以及 ASCII 字符从 128 到 255（0x80-0xff）。通过正则发现，变量名支持unicode、中文，如`$你好`


### [超全局变量](https://www.php.net/manual/zh/language.variables.superglobals.php)


超全局变量是指在全部作用域中始终可用的内置变量。

#### [$_GET](https://www.php.net/manual/zh/reserved.variables.get.php)、[$_POST](https://www.php.net/manual/zh/reserved.variables.post.php)

`$_GET`通过 URL 参数（又叫 query string）传递给当前脚本的变量的**数组**。

- `$_GET`、 `$_POST`是通过 **urldecode()** 传递的，`urldecode($_POST['id'])`，可通过双重URL编码绕过。
  - URL解码[urldecode()](https://www.php.net/manual/zh/function.urldecode.php) 加号（'+'）被解码成一个空格字符。
- 若URL中的查询字符串`?arg=a`，则`$_GET['arg']`为字符串类型；若URL中的查询字符串`?arg[a]=a`，则`$_GET['arg']`为数组类型。
  - `?arg[]=a&arg[]=b`，不指定key，自动索引递增
  - `?arg[name]=a&arg[name2]=b`，指定数组key，**不需要加引号**
- `$_GET`，该数组不仅仅对 method 为 GET 的请求生效，而是会针对**所有带 query string 的请求**。

## 常量

可以使用 const 关键字或 define() 函数两种方法来定义一个常量。一个常量一旦被定义，就不能再改变或者取消定义。常量前面没有美元符号（$）；

```php
<?php
// 简单的标量值
const CONSTANT = 'Hello World';

echo CONSTANT;
```

在 PHP 8.0.0 之前，调用未定义的常量会被解释为一个该常量的字符串，即（CONSTANT 对应 "CONSTANT" ）。 此方法已在 PHP 7.2.0 中被废弃，会抛出一个 E_WARNING 级错误。
参见手册中为什么 $foo[bar] 是错误的（除非 bar 是一个常量）。

### [预定义常量](https://www.php.net/manual/zh/reserved.constants.php)

内核预定义常量在 PHP 的内核中定义。它包含 PHP、Zend 引擎和 SAPI 模块。

### [魔术常量](https://www.php.net/manual/zh/language.constants.magic.php)

有九个魔术常量它们的值随着它们在代码中的位置改变而改变。例如 `__LINE__` 的值就依赖于它在脚本中所处的行来决定。

## 表达式

## 函数

可变函数

## 类与对象

### 匿名类

PHP7现在支持通过 new class 来实例化匿名类，这可以用来替代一些“用后即焚”的完整类定义。匿名类很有用，可以创建一次性的简单对象。匿名类的名称是通过引擎赋予的。匿名类的名称在不同版本存在差异。

```php
<?php
echo get_class(new class() {} );
// PHP 7.4 
// class@anonymous%00/var/www/html/index.php:2$1

// PHP 7.[0123]
// class@anonymous%00/var/www/html/index.php0x7fb985e59023
```

在PHP 7.4中，匿名类的名称与之前版本有所不同，`class@anonymous%00/var/www/html/index.php:2$1`，包含有脚本名称、匿名类所在的行号`:2`、序号`$1`。在实际测试中发现，每次会话其序号从`$0`递增。

我们可以用过引用匿名类的名称实例化。

```php
<?php
$a = new class {
    function getflag() {
        echo "flag{}";
    }
};

$b = $_GET['b'];
$c = new $b();
$c->getflag();

// ?b=class@anonymous%00/var/www/html/1.php:2$0
```
