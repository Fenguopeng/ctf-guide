# 文件上传

## 客户端校验

## 文件后缀绕过

- 大小写绕过
- 罕见后缀
  - ^\.ph(p[3457]?|t|tml|ps)$
- 解析特性
  - 1.php.666
  - /1.jpg/1.php

## 文件类型绕过（MIME绕过）

- 白名单
  - 直接修改`content-type`
- [getimagesize](https://www.php.net/manual/zh/function.getimagesize.php)
  - 在脚本文件开头补充图片对应的头部值，或在图片后写入脚本代码

## 文件截断绕过
CVE-2006-7243

```
**PHP before 5.3.4 **accepts the \0 character in a pathname, which might allow context-dependent attackers to bypass intended access restrictions by placing a safe file extension after this character, as demonstrated by .php\0.jpg at the end of the argument to the file_exists function.
```

## 文件内容绕过

- 文件头检测
- [PHP语言标记](/Web/PHP?id=标记)检测

## 条件竞争

先保存文件，再检测文件内容。利用时间差，访问文件。

## php-gd渲染绕过
## 练习题

- upload labs
- SUCTF 2019 Checkin
- GXYCTF2019BabyUpload
- HarekazeCTF2019 Avatar Uploader 

## 经典赛题分析