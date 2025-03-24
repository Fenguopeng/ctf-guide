# Burp Suite Pro的安装与激活

[Burp Suite](https://portswigger.net/burp)是英国PortSwigger公司开发的最广泛使用的Web应用安全测试软件，现有专业版、社区版和企业版，业内常称其为`burp`或`bp`。

!> Burp Suite 的发音为 `/bɜːrp swiːt/`，其中"Suite"的发音类似于"sweet"，中文翻译为`套件`。

- Bilibili video
- aid=1053570015&bvid=BV1bH4y1A7SG&cid=1522261095&p=1

## 安装Java

运行Java程序只需要安装Java运行环境（Java Runtime Environment，**JRE**），它包括所需的Java虚拟机和类库；若要开发和编译Java程序则需要Java开发工具包（Java Development Kit，**JDK**）,JDK包括JRE、编译器`javac`及其他开发工具。

**建议安装JDK**。因Burp的不同版本对JDK版本有不同要求，需根据Burp的官方说明安装相应版本的JDK，具体参阅[官方说明](https://portswigger.net/burp/documentation/desktop/troubleshooting/launch-from-command-line)。

!> 到2024年4月，Burp的最低JDK版本要求为21，[JDK下载地址](https://www.oracle.com/cn/java/technologies/downloads/archive/)。

安装完成后，通过命令行输入`java -version`验证安装是否成功。

```shell
> java -version
java version "21.0.2" 2024-01-16 LTS
Java(TM) SE Runtime Environment (build 21.0.2+13-LTS-58)
Java HotSpot(TM) 64-Bit Server VM (build 21.0.2+13-LTS-58, mixed mode, sharing)
```

## 下载Burp的JAR程序

在[官方网站](https://portswigger.net/burp/releases)下载专业版的`JAR`文件。

!>官方虽然提供了支持各种操作系统的安装包，但为了便于许可激活，我们选择下载`JAR`文件。

## 下载BurpLoaderKeygen

[BurpLoaderKeygen](https://github.com/h3110w0r1d-y/BurpLoaderKeygen)是Burp的注册机。请将`BurpLoaderKeygen`与`burpsuite_pro_v20**.*.jar`放在同一目录中。

## 设置双击启动

启动`JAR`文件可以通过命令行手动运行或双击直接运行。

- 命令行手动运行

```shell
java -jar 文件名.jar
```

- 双击直接运行

在Windows中，双击运行指定后缀的文件前需设置关联程序，这涉及修改注册表。

?> **强烈推荐**使用[JarFix工具](https://johann.loefflmann.net/en/software/jarfix/index.html)，它能自动配置双击运行`JAR`文件。

若需手动修改注册表：

1. 按下`Win + R`，输入`regedit`并回车打开注册表编辑器。
2. 导航到`HKEY_CLASSES_ROOT\.jar`，确保`Default`的值为`jarfile`。
3. 然后导航到`HKEY_CLASSES_ROOT\jarfile\shell\open\command`，确保`Default`的值为`"C:\Program Files\Java\jdk-21\bin\javaw.exe" -jar "%1" %*`。

也可以使用以下命令：

```powershell
// 将文件扩展名 .jar 关联到文件类型 jarfile
assoc .jar=jarfile

// 指定使用 javaw.exe 程序来运行 JAR 文件。"%1" 表示传递给命令的第一个参数（即要打开的 JAR 文件），%* 表示传递所有附加参数。
ftype jarfile=javaw.exe -jar "%1" %*
```

此外，在Windows下也可以利用`.bat`批处理文件实现双击运行。

## 许可激活

<!-- tabs:start -->

#### **第一步**

![](http://oss.dropsec.xyz/book/BurpLoaderKeygen.png)

运行`BurpLoaderKeygen.jar`，点击`Run`以启动Burp。

#### **第二步**

![](http://oss.dropsec.xyz/book/burp-activation-1.PNG)

复制粘贴`BurpLoaderKeygen`中的`License`。

#### **第三步**
![](http://oss.dropsec.xyz/book/burp-activation-2.PNG)

选择`Manual activation`（人工激活）。

#### **第四步**

![](http://oss.dropsec.xyz/book/burp-activation-3.PNG)

点击`Copy request`（复制请求），并粘贴到`BurpLoaderKeygen`中`Activation Request`位置，然后将`BurpLoaderKeygen`中`Activation Response`复制粘贴过来。

最后激活成功。

<!-- tabs:end -->

## 创建桌面快捷方式

为了方便日常使用，我们选择创建桌面快捷方式。步骤如下：

1. 打开`BurpLoaderKeygen`并勾选`Auto run`以开启自启动。
2. 右键点击`BurpLoaderKeygen`，选择“发送到桌面快捷方式“。
3. 右键点击生成`桌面快捷方式`，更改[图标](../../../assets/img/burp-suite-pro.ico)。

## 参考资料

- [Burp Suite documentation](https://portswigger.net/burp/documentation)