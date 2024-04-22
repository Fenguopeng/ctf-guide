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
  - [数字字符串](https://www.php.net/manual/zh/language.types.numeric-strings.php)，如果一个 PHP string 可以被解释为`int`或 `float`类型，则它被视为`数字字符串`。
- [Array数组](https://www.php.net/manual/zh/language.types.array.php)

### 类型转换

PHP是**动态类型**语言，存在自动类型转换

变量类型转换分为`自动类型转换`和`强制类型转换`。
- `强制类型转换`是通过显式调用进行转换，有两种方法
  - 通过在值前面的括号中写入类型来将值转换指定的类型，如`$bar = (bool) $foo`。
  - 使用`settype()`函数。
- [类型转换的判别](https://www.php.net/manual/zh/language.types.type-juggling.php)

[转换为string](https://www.php.net/manual/zh/language.types.string.php#language.types.string.casting)

- 布尔值`true`转换为"1"
- 布尔值`false`转换为""（空字符串）
- 数组`array`总是转换成字符串"Array"
  - `echo`和`print`无法显示该数组的内容
- 整数、浮点数转换为数字的字面样式的字符串
- 必须使用魔术方法 `__toString` 才能将 `object` 转换为 `string`
- `null`总是被转变成空字符串
  
```php
// 布尔值`true`转换为"1"
var_dump(strval(true)); //string(1) "1"
var_dump(strval(false)); //string(0) ""
var_dump(strval([])); //string(5) "Array"
var_dump(strval(123)); //string(3) 
var_dump(strval(123.5)); //"123"string(5) "123.5"
var_dump(strval(1e2)); //string(3) "100"
var_dump(strval(null)); // string(0) ""
```

[转换为布尔值]()

以下值被认为是`false`
<div grid="~ cols-2 gap-4">
<div>

- 布尔值`false`本身
- 整型值`0`（零）
- 浮点型值 `0.0`
- 空字符串 ""，以及字符串 "0"
- 不包括任何元素的数组
- 原子类型 NULL（包括尚未赋值的变量）
- 内部对象的强制转换行为重载为 bool。例如：由不带属性的空元素创建的 SimpleXML 对象。

```php
<?php
// bool(false)
var_dump((bool)false);
var_dump((bool)0);
var_dump((bool)0.0);
var_dump((bool)"");
var_dump((bool)"0");
var_dump((bool)[]);
var_dump((bool)null);
```

所有其它值都被认为是 true（包括 资源 和 NAN）。

### 类型比较

不同类型的变量在进行比较时会进行`自动类型转换`，[比较运算符](https://www.php.net/manual/zh/language.operators.comparison.php)

- [PHP类型比较表](https://www.php.net/manual/zh/types.comparisons.php)
- 当两个操作对象都是`数字字符串`，或一个是数字另一个是`数字字符串`，就会**自动按照数值**进行比较。
- 松散比较，先进行类型转换，然后**比较值**
- 严格比较，**比较类型、值**
- PHP 8.0.0 之前，如果`string`与数字或者数字字符串进行比较，则在比较前会将`string`转化为数字。

## [变量](https://www.php.net/manual/zh/language.variables.basics.php)

PHP 中的变量用一个美元符号后面跟变量名来表示。变量名是**区分大小写**的。

变量名与 PHP 中其它的标签一样遵循相同的规则。一个有效的变量名由字母或者下划线开头，后面跟上任意数量的字母，数字，或者下划线。

!> 在此所说的字母是 a-z，A-Z，以及 ASCII 字符从 128 到 255（0x80-0xff）

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

## 类与对象

### 匿名类

```php

```