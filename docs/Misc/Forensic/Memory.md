# 内存取证

[Volatility 3](https://volatility3.readthedocs.io/en/latest/)是一款强大的内存取证工具，用于分析计算机内存转储（RAM dump）。

- `Kali Linux 2024.4`

```bash
$ sudo apt install pipx
$ pipx install volatility3
  installed package volatility3 2.26.0, installed using Python 3.13.2
  These apps are now globally available
    - vol
    - volshell
done! ✨ 🌟 ✨
```

查看可用的插件：

```bash
volatility --info
```

使用 `-f` 选项指定内存转储文件。

```bash
volatility -f memory_dump.raw --profile=WinXPSP2x86 pslist
```
