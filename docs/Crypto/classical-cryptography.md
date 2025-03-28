# 古典密码学

相比与现代密码，古典密码是密码学的一个类型，大部分加密方式是**代换**和**置换**。

## 字母频率分析

字母频率是字母表中的字母在书面语言中出现的平均次数。Herbert S. Jim 在他的经典密码入门书《Codes and Secret Writing》中提到，最常见字母频率排列顺序是`ETAON RISHD LFCMU GYPWB VKJXZQ`，最常见的字母对是`TH HE AN RE ER IN ON AT ND ST ES EN OF TE ED OR TI HI AS TO`，最常见的双字母是`LL EE SS OO TT FF RR NN PP CC`。其按照大小排序后英文字母频率如下图。需要注意的是，不同的计数方法可能会导致排序略有不同，也是说不同的来源结果略有不同。

![](../../../assets/img/English_letter_frequency.png)

在古典密码中，如果密文并没有改变字母的出现频率，如凯撒密码，我们可以通过字母频率分析进行破解。如果在CTF解题中，可以使用在线工具 https://quipqiup.com/ 辅助解题。

```
garyxqhqlxfwhswjxhzsrhxdwrxcwhxvrwlrqsfwbvxnqbwvcgawgxvfhpdrcgarfwgcwjrjyrbqsgaxcswjxhzxcwhcqfwhhrdwsrhxdgarfawbwfgrbxcgxfsrwgpbrcqsfwgcawnrrnqhnrdgqcpttqbgwfwbvxnqbqpchxsrcgzhruxgawdwtgwgxqvcsqbwjypcaqbcgwhkxvlwvdcaqbgtpbcpxgapvgxvlgarzawnrlbwfxhrwvdjpcfphwbyqdxrccgbqvlshroxyhrsqbrhxjycwvdbrgbwfgwyhrfhwucsqbaqhdxvltbrzdrvgwhwvdfbwvxwhwdwtgwgxqvcsqbwcgbqvlyxgrwvdqsgrvawnrfawbwfgrbxcgxfcgbxtrdqbctqggrdfqwgtwggrbvcsqbfwjqpshwlrfwgcwbrqyhxlwgrfwbvxnqbrcjrwvxvlgarzwbrdrtrvdrvgqvvpgbxrvgcxvwvxjwhshrcasqbcpbnxnwhwvdyrfwpcrqsgarhwblrtbqtqbgxqvqsjrwgxvgarxbdxrgwbrcqjrgxjrcbrsrbbrdgqwcaztrbfwbvxnqbrcqsgargrbbrcgbxwhswjxhxrcxvgarqbdrbfwbvxnqbwgarzwbrgarcgbxfgrcgfwbvxnqbrchxnxvlfwgcyrhqvlgqguqcpyswjxhxrcgartwvgarbxvwrwvdsrhxvwrgarsqbjrbfqjtbxcrcgaryxlfwgcgargxlrbhxqviwlpwbhrqtwbdcvquhrqtwbdfhqpdrdhrqtwbdwvdcpvdwfhqpdrdhrqtwbdsrhxvwrfqjtbxcrcwhhgarvqvtwvgarbxvrfwgcuaxfabwvlrxvcxersbqjgarcjwhhbpcgzctqggrdfwggqgaryxlfwgcxerdtpjwwvdxvfhpdrccpfadxnrbcrsqbjcwcgarhzvoqfrhqgcrbnwhwvdfarrgwawcurhhwcgardqjrcgxffwggarwvcurbxciwlpwbpvdx
```

```
the biological family felidae is a lineage of carnivorans that includes the cats a member of this family is also called a felid the characteristic features of cats have evolved to support a carnivorous lifestyle with adaptations for ambush or stalking and short pursuit hunting they have gracile and muscular bodies strong flexible for elimbs and retractable claws for holding prey dental and cranial adaptations for a strong bite and often have characteristic striped or spotted coat patterns for camouflage cats are obligate carnivores meaning they are dependent on nutrients in animal flesh for survival and because of the large proportion of meat in their diet are sometimes referred to as hyper carnivores of the terrestrial families in the order carnivora they are the strictest carnivores living cats belong to two subfamilies the pantherinae and felinae the former comprises the big cats the tiger lion jaguar leopard snow leopard clouded leopard and sunda clouded leopard felinae comprises all the nonpantherine cats which range in size from the small rusty spotted cat to the big cat sized puma and includes such diverse forms as the lynx ocelot serval and cheetah as well as the domestic cat the answer is jaguarundi
```

## 代换（替换）密码（Substitution Cipher）

代换密码是将明文中的字符替换成其他字符，即替代转换。若加密过程中，每个字符采用同一张表替代，则为**单表代换密码**；若整个加密过程中每个字符采用不同的表替代，则为**多表代换密码**。

破解代换加密的基本方法是用统计手段，即统计语言中的一些字或字母出现频率的规律。

### 单表代换

单表代换密码是在明文和密文之间建立一一映射关系，也就是说明文与密文一一对应。所以有以下两种方式来进行破解：

1. 在密钥空间较小的情况下，采用暴力破解方式
2. 在密文长度足够长的情况下，采用词频分析方式

当密钥空间足够大，且密文长度足够短的情况下，破解较为困难。

#### 移位密码（凯撒密码）

移位密码（Shift Cipher）是一种单字母替换密码，将明文中每个字母在字母表中向后（或向前）移动固定长度后得到密文。例如，当偏移量是3时，所有的字母A将被替换成D，B变成E，以此类推。

![](../../../assets/img/CaesarCipher-1.png)

移位密码也被称为凯撒密码（Caesar Cipher），凯撒密码是以罗马共和时期凯撒的名字命名的，据称当年凯撒曾用此方法与其将军们进行联系。
移位密码的密钥是0到25之间的整数，因此可以通过穷举法进行破解。
根据偏移量不同，还存在若干特定的移位密码名称：

- 偏移量为10：
- 偏移量为13：ROT-13
- 偏移量为-5：
- 偏移量为-6：

ROT系列

#### 埃特巴什码

埃特巴什码（Atbash Cipher）是一种单字母替换密码，使用字母表中的最后一个字母代表第一个字母，倒数第二个字母代表第二个字母。

```
明文：ABCDEFGHIJKLMNOPQRSTUVWXYZ
密文：ZYXWVUTSRQPONMLKJIHGFEDCBA
```

例如，`MIRROR`加密为`NRIILI`。埃特巴什码也称为`镜像密码`。

<!-- #### rabbit -->

#### 仿射密码（Affine Cipher）

仿射加密（Affine cipher）是一种基于线性变换的加密方法。

加密过程：
$$
E(x)=(ax+b) \mod m
$$

解密解密：
$$
D(x)=a^{-1}(x-b) \mod m
$$

`x`为字符在字母表中的位置，从`0`开始。`m`为字母表的长度，例如对于英文字母为26。

假设我们要加密字符串 "HELLO"，使用以下参数：

- a=5
- b=8
- 字母表长度 m=26

`H → 7`

`E(7)=(5⋅7+8) mod 26 = (35+8) mod 26 = 17`,17对应的字母为R。
因此，字符串 "HELLO" 的加密结果是 "RCLLA"。

#### 培根密码（Bacon Cipher）

培根密码（Bacon Cipher），又叫倍康尼密码，是由法兰西斯·培根发明的一种替换密码。加密时，明文中的每个字母都会替换成一组五个英文字母。其转换依靠下表：

![](../../../assets/img/BaconCipher-2.png)

转换表有两个版本。一是`i` 和`j`、`u`和`v`使用相同的编码。二是所有字母使用不同的编码。
例如，对明文`hello world`进行加密。步骤如下：
第一步，将`H`替换为`aabbb`，`E`替换为`aabaa`等等

![](../../../assets/img/BaconCipher-helloworld-1.png)

第二步，隐藏信息。常规字体表示`a`，粗体表示`b`

![](../../../assets/img/BaconCipher-helloworld-2.png)

也可以使用大小写来隐藏信息。

```
sSsSSsSSssSSsSsSsSssSSSSSSSssS{SSSsSsSSSsSsSSSsSSsSSssssssSSSSSSSsSSSSSSSSsSSsssSSssSsSSSsSSsSSSSssssSSsssSSsSSsSSSs}
```

```
UTFLAG{CRISPYBACONCIPHER}
```

培根密码本质上是将二进制信息通过样式的区别，加在了正常书写之上，样式包括大小写、斜体和加粗等。培根密码所包含的信息可以和用于承载其的文章完全无关。

<!-- #### 希尔密码（Hill Cipher）希尔密码（Hill Cipher） -->

### 多表代换

多表代换密码与单表代换密码不同，不是代换单个字符，而是代换整个字符组。多表代换密码在加密后，明文字符的频率会被改变，无法通过词频分析破解。

#### 棋盘密码

#### 维吉尼亚密码（Vigenère Cipher）

维吉尼亚密码是将明文字符和密钥作为索引值。如果密钥字符比明文字符短，那么密钥会通过重复使用的方式扩展至明文的长度。

#### 普莱费尔密码

普莱费尔密码（Playfair Cipher）是第一个二字母替换密码，1854 年由英国人查尔斯 · 惠斯通（Charles Wheatstone）发明，基本算法如下：

例如，选取密钥为`playfair`，去除重复字母后，得到`playfir`，将字母按顺序填入$5 \times 5$的矩阵中，余下的位置用字母表中剩下的字母填充，其中`i`和`j`作为同一个字母。

> 注意，由于矩阵大小只有25个，而字母有26个，可以将`i`和`j`视作同一字母，或者将`q`去除。

$$
\begin{array}{ccccc}
P & L & A & Y & F \\
I & R & B & C & D \\
E & G & H & K & M \\
N & O & Q & S & T \\
U & V & W & X & Z \\
\end{array}
$$

加密过程如下：

- 将明文去掉空格后，每两个字母一组，如果一组中的字母相同，则在中间插入一个填充字母（通常为`X`），然后重新分组。必要的话，在最后一组末尾加字母`X`。例如明文为`HELLO`，分组结果为`HE LX LO`。
- 对每一组字母，按照以下规则进行加密
  - 如果两个字母在同一行，则用它们右边的字母替换（如果在最右边，则循环到最左边）。例如`HE`->`KG`。
  - 如果两个字母在同一列，则用它们下边的字母替换（如果在最下边，则循环到最上边）。例如`LO`->`RV`。
  - 如果两个字母不在同一行也不在同一列，则用它们所在矩阵的对角线上字母替换。例如`LX`->`YV`。

完整的密文是`KGYVRV`。解密时，将这一过程倒过来。

<!-- 例题： [picoCTF 2021 Play nice](https://ctftime.org/task/15292)
https://github.com/Dvd848/CTFs/blob/master/2021_picoCTF/Play_Nice.md -->

### 图形代换

#### [猪圈密码](https://www.dcode.fr/pigpen-cipher)（Pigpen Cipher）

猪圈密码是一种以格子为基础的图形代换密码。

![](../../../assets/img/PigpenCipher-1.png)

例如，明文`X marks the spot`的密文如下

![](../../../assets/img/PigpenCipher-2.jpg)

在线网站: https://www.dcode.fr/pigpen-cipher

<!-- #### 键盘密码 -->

#### 跳舞小人密码

![](https://p9-tt-ipv6.byteimg.com/large/pgc-image/85c18be4a7824119a16b443f047341c6)

#### 键盘密码

所谓键盘密码，就是采用手机键盘或者电脑键盘进行加密。

- 手机键盘密码

手机键盘加密方式，是每个数字键上有 3-4 个字母，用两位数字来表示字母，例如：ru 用手机键盘表示就是：7382，那么这里就可以知道了，手机键盘加密方式不可能用 1 开头，第二位数字不可能超过 4，解密的时候参考此。

![](https://ctf-wiki.org/crypto/classical/figure/mobile.jpg)

关于手机键盘加密还有另一种方式，就是「音的」式（这一点可能根据手机的不同会有所不同），具体参照手机键盘来打，例如：「数字」表示出来就是：748 94。在手机键盘上面按下这几个数，就会出：「数字」的拼音。

- 电脑键盘棋盘

电脑键盘棋盘加密，利用了电脑的棋盘方阵。

![](https://ctf-wiki.org/crypto/classical/figure/computer-chess.jpg)

- 电脑键盘坐标

电脑键盘坐标加密，利用键盘上面的字母行和数字行来加密，例：bye 用电脑键盘 XY 表示就是：351613

![](https://ctf-wiki.org/crypto/classical/figure/computer-x-y.jpg)

- 电脑键盘 QWE
电脑键盘 QWE 加密法，就是用字母表替换键盘上面的排列顺序。

![](https://ctf-wiki.org/crypto/classical/figure/computer-qwe.jpg)

例题分析：[SWPUCTF 2021 新生赛]我的银行卡密码

<!-- https://blog.csdn.net/2301_76328911/article/details/136545008 -->

## 置换密码

置换密码（Transposition Cipher）又称为转置密码或换位密码，是指通过改变明文中各字符位置得到密文，其字符不变，但位置改变，即**位置转换**。典型的有栅栏密码、曲路密码等。

### 栅栏密码

栅栏密码（Rail Fence Cipher）是把明文分成N个一组，取每组的第一个字符连起来得到密文1，取每组的第二个字符连起来得到密文2，依次类推，最后将密文1、密文2....连接形成密文。栅栏密码根据分为传统型（W型）和N型
例如

明文：

```
THISISCIPHER
```

https://www.geocachingtoolbox.com/index.php?page=railFenceCipher

<!-- ### 曲路密码 -->

## 总结

- 如果给定的密文长度较长，考虑字母频率分析

## 参考资料