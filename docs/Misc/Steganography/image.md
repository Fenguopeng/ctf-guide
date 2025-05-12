# 图片隐写

## BMP（位图）

[BMP](https://zh.wikipedia.org/wiki/BMP)是一种独立于显示器的位图数字图像文件格式，**通常不压缩**，体积大，不适合在因特网上传输。

![](https://upload.wikimedia.org/wikipedia/commons/7/75/BMPfileFormat.svg)

## PNG

PNG 文件包括以下主要部分：

文件头（Signature）：每个 PNG 文件以字节序列 `89 50 4E 47 0D 0A 1A 0A` 开头。
块（Chunks）：PNG 文件由多个不同类型的块组成，每个块包含特定的信息和数据。主要块包括：
IHDR：图像头，包含图像宽度、高度、颜色类型等信息。
PLTE：调色板块（可选），定义用于图像的颜色调色板。
IDAT：图像数据块，存储图像的实际像素数据。
IEND：图像结束块，指示文件的结尾。

### 修改高度

### IDAT

## JPG

jphide

## GIF

## LSB隐写

## 数字水印

<https://medium.com/@PLZENTERTEXT/wargames-my-2024-forensics-misc-writeup-74375de25de5>
<https://ctftime.org/writeup/34120>

### 盲水印

## Exif

[Exif](https://zh.wikipedia.org/wiki/Exif)（Exchangeable image file format，可交换图像文件格式）是专门为数码相机的照片设定的文件格式，可以记录数码照片的属性信息和拍摄数据。

## 隐写检测工具

[zsteg](https://github.com/zed-0xff/zsteg) detect stegano-hidden data in PNG & BMP

[stegdetect](https://web.archive.org/web/20150415213536/http://www.outguess.org/detection.php)是一个用来检测`JPEG`图片是否存在隐藏信息的自动化工具。可检测`jsteg`、`jphide`、`outguess`、`F5`、``、``

WbStego

jphide

<https://github.com/DominicBreuker/stego-toolkit>

<https://www.anquanke.com/post/id/189154#h2-7>
