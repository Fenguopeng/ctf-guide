# 信息泄露

在CTF比赛中，信息泄露往往是出题人**故意设置**的，泄露的可能是提示、源代码等信息，以达到降低题目难度或者代码审计的目的。

主要途径有：

- 网页源代码（注释）、响应头
- `robots.txt`
- `*.phps`
- 网站备份文件，如`www.zip`、`index.php.bak`等
- 版本控制软件，如`.git`、`.svn`
- 开发环境遗留
  - vi、vim、gedit等编辑器的临时文件
  - .DS_store文件
  - .idea文件夹
- 文件读取（包含）漏洞

## 目录扫描

通过扫描工具进行暴力目录探测

[dirsearch](https://github.com/maurosoria/dirsearch)是一款命令行风格的网站目录扫描工具

```shell
python3 dirsearch.py -e php -u http://example.com
```

## `.git`目录

Git一个免费的开源分布式版本控制系统，[了解更多](https://www.liaoxuefeng.com/wiki/896043488029600)

如果存在`.git`目录，可以还原构建工程源代码

1. [GitHacker](https://github.com/WangYihang/GitHacker)
2. [GitHack](https://github.com/lijiejie/GitHack)

```shell
// 查看提交记录
git reflog 

// 版本回滚
git reset --hard [log hash]
```

此外，`.gitignore`文件保存git忽略的文件或目录，也可能有敏感信息

扩展阅读，[别想偷我源码：通用的针对源码泄露利用程序的反制（常见工具集体沦陷）](https://drivertom.blogspot.com/2021/08/git.html)

> [Git Cola](https://git-cola.github.io/)一款免费的git图形工具

例题
1. [Lab: Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history)

## `.idea`目录

JetBrains公司出品的IDE，如PyCharm、IntelliJ IDEA、PhpStorm等，会在项目根目录下创建`.idea`文件夹，用于保存项目的特定配置文件，包含文件变更、版本控制、调试信息等。

重点关注`workspace.xml`文件，可能会暴露文件名称

- FileEditorManager
- ChangeListManager
- editorHistoryManager

## 编辑器的临时文件

`vi`和`gedit`是Linux系统上的文本编辑器。

- `SWAP`文件是`vi`文本编辑器或其变体创建的交换文件，如`vim编辑器`。存储了正在编辑文件的恢复版本。编辑器在会话开始时，在当前目录创建临时文件，如`.index.php.swp`，当编辑器意外退出时，文件将会保留下来，我们可以通过命令进行恢复。[^1]

```shell
vim -r index.php
```

> 如果`.swp`文件已经存在，将会创建`.swo`、`.swn`等后缀的文件

- gedit编辑器保存后，会创建一个`~`后缀的文件作为保存前的副本，，如`index.php~`

## `.DS_Store`文件

.DS_Store (英文全称 Desktop Services Store) 是一种由苹果公司的Mac OS X操作系统所创造的隐藏文件，目的在于存贮目录的自定义属性，例如文件们的图标位置或者是背景色的选择。该文件由Finder创建并维护，类似于Microsoft Windows中的desktop.ini文件。[^1]

通过分析`.DS_Store`文件可以还原目录结构。

1. [Python-dsstore](https://github.com/gehaxelt/Python-dsstore) - Python .DS_Store parser
2. [ds_store_exp](https://github.com/lijiejie/ds_store_exp) - 这是一个 .DS_Store 文件泄漏利用脚本，它解析.DS_Store文件并递归地下载文件到本地