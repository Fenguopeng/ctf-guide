# VMware Workstation Pro的安装与使用技巧

?> VMware 于 2024 年 5 月 14 日宣布其 Workstation Pro 和 Fusion 产品对个人用户完全免费使用。

## 下载与安装

?> 博通收购 VMware 后，下载 VMware Workstation 需前往博通官网并注册账号。

下载[官方安装包](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)，并按默认设置安装即可。

## 创建虚拟机

点击菜单栏中的`文件>新建虚拟机`，将弹出`新建虚拟机向导`窗口。

<!-- tabs:start -->

#### **第一步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC1%E6%AD%A5.png)

通常选择“典型”设置即可。

#### **第二步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC2%E6%AD%A5.png)

当选择第二项`安装程序光盘映像文件`时，如果VMware识别出操作系统类型，将执行简易安装。但由于简易安装缺少个性化设置，建议选择第三项`稍后安装操作系统`。这就相当于组装一台拥有空白硬盘的计算机，随后可通过光盘手动安装操作系统，与物理机安装系统方法类似。

#### **第三步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC3%E6%AD%A5.png)

根据实际情况选择操作系统类型和版本。

#### **第四步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC4%E6%AD%A5.png)

建议将虚拟机位置选择为数据盘（如D盘），以避免系统盘（如C盘）。应建立专门存放虚拟机的文件夹（如`D:\Virtual Machines`），避免路径复杂或出现中文字符，并可通过`编辑>首选项`更改默认位置。

#### **第五步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC5%E6%AD%A5.png)

为了提高磁盘性能，建议选择`将虚拟磁盘存储为单个文件`。

#### **第六步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC6%E6%AD%A5.png)

根据物理机的性能情况决定是否修改虚拟机的默认硬件配置。若物理机的性能较强（如`16G`内存以上），建议调整硬件配置。

#### **第七步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC7%E6%AD%A5.png)

建议将虚拟机配置为`4核4G`。
根据[官方手册](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-9745D560-9243-4262-A585-D709D52B1349.html)，处理器配置建议为`处理器数量`为`1`，`每个处理器的内核数量`为4。也就是说，1路CPU（或1个插槽），每颗CPU有4个核心。避免使用`处理器数量`为4，`每个处理器的内核数量`为1，否则可能会降低性能。

?> 请勿追求过高的性能配置，以免影响物理机性能，导致系统响应缓慢。

根据需要选择是否勾选`虚拟化Intel VT-x/EPT或AMD-V/RVI(V)`选项，开启虚拟机的CPU虚拟化功能可实现嵌套虚拟化，例如安装Docker、安卓模拟器等。

!> CPU虚拟化选项与`Hyper-V`冲突。

<!-- tabs:end -->

### 创建Windows虚拟机

1. 通过临时禁用网络，注册本地账号。
2. 安装VMware Tools。
3. 更新系统后，关机，制作快照。

### 创建Kali Linux虚拟机

## 常用功能

### VMware Tools

VMware Tools 是一套提升虚拟机性能和用户体验的工具，支持鼠标集成、动态分辨率调整、主机与虚拟机之间的共享文件夹和时间同步等功能。安装后，可以通过`复制粘贴`或`拖放`传输文件。

### 拍摄快照

拍摄快照可以保存虚拟机当前的完整状态，以便随时恢复。

拍摄快照的方法是选择虚拟机，`右键`或通过菜单栏中的`虚拟机`选项，选择`快照>拍摄快照`，`快照管理器`可以用于查看和管理虚拟机的快照。

!> 如果不需要保存虚拟机的内存信息（即实时状态），可以在**虚拟机关机时**拍摄快照，以减少快照对物理机硬盘空间的占用。

在重要节点（如`虚拟机安装完成`或`重要软件安装前后`）拍摄快照，可避免因操作问题导致重新安装操作系统，从而提高效率。

### 克隆虚拟机

通过`克隆虚拟机`功能，可以快速创建多个相同的虚拟机，避免重复安装的麻烦。

<!-- tabs:start -->
#### **第一步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA1.png)

#### **第二步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA2.png)

#### **第三步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA3.png)

如果是`链接克隆`，原始虚拟机不能删除；如果是`完整克隆`，则相当于完整复制得到一个独立的虚拟机。

#### **第四步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA4.png)

<!-- tabs:end -->


### 删除虚拟机

右键选择`移除`将不会从磁盘中删除虚拟机，如下图所示。

![](http://oss.dropsec.xyz/book/%E7%A7%BB%E9%99%A4%E8%99%9A%E6%8B%9F%E6%9C%BA.png)

正确的做法是，选择虚拟机，然后选择`虚拟机 > 管理 > 从磁盘中删除`，或直接删除虚拟机目录文件。

### 网络编辑器

通过菜单的`编辑-虚拟网络编辑器`进行网络连接设置。

<!-- tabs:start -->
#### **桥接（Bridge）模式**

![桥接（Bridge）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-8AB8E6E2-E16F-4E60-8421-669C96E6BF38-high.png)

如同网络中的物理机。

#### **网络地址转换（NAT）模式**

![网络地址转换（NAT）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-4C1FE8E1-9C52-4A43-9C36-97AEC38C737B-high.png)

与虚拟机**共享主机的IP地址**。

#### **仅主机（host-only）模式**

![仅主机（host-only）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-B8B0D851-3DF2-4999-AE86-9059AE017A9C-high.png)

- 独立的虚拟网络。
- 仅主机模式下的虚拟机无法连接到Internet。
<!-- tabs:end -->

!> 为保护虚拟机安全，若无特殊必要，请尽量**避免选择桥接模式**。

## 虚拟机文件

[虚拟机文件](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-A968EF50-BA25-450A-9D1F-F8A9DEE640E7.html)类型介绍

## Q&A

1. 如何给他人拷贝虚拟机？
  
  - 直接拷贝虚拟机目录，但可能存在多余的快照信息导致文件过大。可先进行`完整克隆`后再拷贝。
  - 导出OVF文件。

2. 移动或复制虚拟机的提示

![](http://oss.dropsec.xyz/book/%E7%A7%BB%E5%8A%A8%E6%88%96%E5%A4%8D%E5%88%B6%E8%99%9A%E6%8B%9F%E6%9C%BA%E6%8F%90%E7%A4%BA.png)

`移动虚拟机`是指改变了虚拟机的存放位置，网络中仍仅有一台相同的虚拟机，因此虚拟机的网络配置不变；`复制虚拟机`是指复制了一份虚拟机，网络中可能出现两台相同的虚拟机，会自动更改虚拟机的MAC地址以避免网络冲突。

