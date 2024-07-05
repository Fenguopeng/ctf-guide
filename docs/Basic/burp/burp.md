# Burp Suite Pro的安装与激活

[Burp Suite](https://portswigger.net/burp)是一款由英国PortSwigger公司开发，使用最广泛的Web应用安全测试软件。目前发行版本有专业版、社区版和企业版。圈内人士常将其简称为`burp`、`bp`。

?>Burp Suite 的发音为 `/bɜːrp swiːt/`，"Suite"的发音类似于"sweet"，中文翻译为`套件`。

- Bilibili video
- aid=1053570015&bvid=BV1bH4y1A7SG&cid=1522261095&p=1

## 安装Java

如果只想运行Java程序，只需要安装Java运行环境（Java Runtime Environment，**JRE**），JRE包括所需的Java虚拟机和类库；如果打算开发和编译Java程序，则需要Java开发工具包（Java Development Kit，**JDK**）,JDK包括了JRE及编译器javac和其他开发工具。

**建议安装JDK**，由于不同时期的burp版本对JDK版本要求不同，需要根据burp的要求安装相应版本JDK，具体阅读[官方说明](https://portswigger.net/burp/documentation/desktop/troubleshooting/launch-from-command-line)。2024年4月，burp要求最低版本为21，[JDK下载地址](https://www.oracle.com/cn/java/technologies/downloads/archive/)。

通过在命令行输入`java -version`，验证是否安装成功。

```shell
>java -version
java version "21.0.2" 2024-01-16 LTS
Java(TM) SE Runtime Environment (build 21.0.2+13-LTS-58)
Java HotSpot(TM) 64-Bit Server VM (build 21.0.2+13-LTS-58, mixed mode, sharing)
```

## 下载burp的JAR程序

在[官方网站](https://portswigger.net/burp/releases)下载专业版`JAR`文件。

?>官方虽然提供了支持各种操作系统的安装包，但是由于不便于我们进行许可激活，所以我们选择下载`JAR`文件。

## 下载BurpLoaderKeygen

[BurpLoaderKeygen](https://github.com/h3110w0r1d-y/BurpLoaderKeygen)是burp的注册机。需要将`BurpLoaderKeygen`和`burpsuite_pro_v20**.*.jar`放在同一目录。

## 设置双击启动

通过运行[JarFix工具](https://johann.loefflmann.net/en/software/jarfix/index.html)（**强烈推荐**），自动实现双击运行`JAR`文件的配置。

此外，补充其他运行`JAR`文件的方法。

- 使用命令行

```shell
java -jar 文件名.jar
```

- Windows下通过批处理文件`.bat`，文件内容同命令行

```shell
java -jar 文件名.jar 
```

- 手动进行文件关联配置，实现**双击运行**
  - 通过命令行
  
```powershell
assoc .jar=jarfile
ftype jarfile=javaw.exe -jar "%1" %*
```

  - 通过注册表编辑器
    - 按下`Win + R`，输入`regedit`并按回车键打开注册表编辑器。
    - 导航到`HKEY_CLASSES_ROOT\.jar`
    - 确保Default的值为jarfile
    - 导航到`HKEY_CLASSES_ROOT\jarfile\shell\open\command`
    - 确保Default的值为`"C:\Program Files\Java\jdk-21\bin\javaw.exe" -jar "%1" %*`

## 许可激活

<!-- tabs:start -->

#### **第一步**

![](http://oss.dropsec.xyz/book/BurpLoaderKeygen.png)

双击运行`BurpLoaderKeygen.jar`，然后点击`Run`，启动burp。

#### **第二步**

![](http://oss.dropsec.xyz/book/burp-activation-1.PNG)

复制`BurpLoaderKeygen`中的`License`

#### **第三步**
![](http://oss.dropsec.xyz/book/burp-activation-2.PNG)

选择`Manual activation`，人工激活。

#### **第四步**

![](http://oss.dropsec.xyz/book/burp-activation-3.PNG)

点击`Copy request`，复制请求并粘贴到`BurpLoaderKeygen`中`Activation Request`位置，然后将`BurpLoaderKeygen`中`Activation Response`复制粘贴过来。

最后激活成功。

<!-- tabs:end -->

## 创建桌面快捷方式

1. 打开`BurpLoaderKeygen`，勾选`Auto run`
2. 单击右键`BurpLoaderKeygen`，发送到桌面快捷方式
3. 修改快捷方式的[图标](../../../assets/img/burp-suite-pro.ico)。

## 参考资料
- [Burp Suite documentation](https://portswigger.net/burp/documentation)