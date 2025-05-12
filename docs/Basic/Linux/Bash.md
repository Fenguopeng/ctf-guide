# Bash

`Shell`意为“外壳”，对应`kernel`（内核），是用户与内核交互的命令行界面。Linux 常见 Shell 有：

- Bourne Shell (`/usr/bin/sh` or `/bin/sh`)，简称`sh`
- Bourne Again Shell (`/bin/bash`)，简称`bash`
- C Shell（`/usr/bin/csh`），简称`csh`
- Korn Shell (`/usr/bin/ksh`)，简称`ksh`
- Z Shell（`/usr/bin/zsh` or `/bin/zsh`）简称`zsh`

绝大多数 Linux 发行版默认使用 `bash`。

![](https://media.geeksforgeeks.org/wp-content/uploads/18834419_1198504446945937_35839918_n-300x291.png)

## 命令提示符

```bash
user@hostname:~$
```

其字段含义为`用户名@主机名:当前目录$`，示例中的`~`被扩展为家目录，`$`代表普通用户，根用户（root）提示符以`#`结尾。

## 命令格式

```bash
command [ arg1 ... [ argN ]]
```

`command`是具体的命令或者一个可执行文件，`arg1 ... argN`是传递给命令的参数，它们是可选的。

Bash 单个命令一般都是一行，用户按下回车键，就开始执行。有些命令比较长，写成多行会有利于阅读和编辑，这时可以在每一行的结尾加上反斜杠，Bash 就会将下一行跟当前行放在一起解释。

命令分为内置命令和外部命令（程序），使用`type`命令来判断命令的来源。

```bash
$ type echo
echo is a shell builtin
$ type whoami
whoami is /usr/bin/whoami
```

## 变量

Bash 变量分成环境变量和自定义变量两类。

### 环境变量

`env`命令或`printenv`命令，可以显示所有环境变量。

### 自定义变量

自定义变量是用户在当前 Shell 里面自己定义的变量，仅在当前 Shell 可用。一旦退出当前 Shell，该变量就不存在了。

`set`命令可以显示所有变量（包括环境变量和自定义变量），以及所有的 Bash 函数。

如果变量不存在，Bash 不会报错，而会输出空字符。

变量名也可以使用花括号`{}`包围，比如`$a`也可以写成`${a}`。这种写法可以用于变量名与其他字符连用的情况。

## 参考资料

- [Bash 脚本教程 - 阮一峰](https://wangdoc.com/bash/intro)
- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/bash.html)
