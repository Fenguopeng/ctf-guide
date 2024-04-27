# VMware Workstation Pro的安装与使用方法

## 下载与安装

[官网下载安装包](https://www.vmware.com/products/workstation-pro/workstation-pro-evaluation.html)

## 创建虚拟机

点击菜单栏`文件>新建虚拟机`，弹出`新建虚拟机向导`窗口。

<!-- tabs:start -->

#### **第一步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC1%E6%AD%A5.png)

通常选择“典型”即可。

#### **第二步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC2%E6%AD%A5.png)

当选择第二项`安装程序光盘映像文件`时，如果VMware识别出操作系统类型，则会进行简易安装。

由于简易安装，缺少个性化设置选项，所以建议选择第三项`稍后安装操作系统`。相当于组装了一台具有空白磁盘的计算机，后续通过光盘手动安装操作系统，此步骤与物理机安装一致。

#### **第三步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC3%E6%AD%A5.png)

根据实际情况选择操作系统类型和版本。

#### **第四步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC4%E6%AD%A5.png)

虚拟机位置建议：
- 应选择数据盘，如D盘；避免系统盘，如C盘。
- 应建立专门存放虚拟机的文件夹，如`D:\Virtual Machines`，避免路径复杂、中文等，并在`编辑>首选项`中更改默认位置。

#### **第五步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC5%E6%AD%A5.png)

为了提高磁盘性能，建议选择`将虚拟磁盘存储为单个文件`。

#### **第六步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC6%E6%AD%A5.png)

根据自身物理机的性能情况，选择是否修改默认的虚拟机硬件配置。假设物理机的性能较强，`16G`内存及以上，建议提升硬件配置。

#### **第七步**

![](http://oss.dropsec.xyz/book/%E6%96%B0%E5%BB%BA%E8%99%9A%E6%8B%9F%E6%9C%BA%E5%90%91%E5%AF%BC%E7%AC%AC7%E6%AD%A5.png)

建议将虚拟机配置为`4核4G`。
根据[官方手册](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-9745D560-9243-4262-A585-D709D52B1349.html)建议处理器配置为`处理器数量`为`1`，`每个处理器的内核数量`为4。也就是说，1路CPU（或1个插槽），每颗CPU有4个核心。避免使用`处理器数量`为4，`每个处理器的内核数量`为1，否则可能会降低性能。

?> 请勿追求过高的性能配置，否则可能会影响物理机性能，导致整体系统反应迟钝。

勾选`虚拟化Intel VT-x/EPT或AMD-V/RVI(V)`选项为开启虚拟机的CPU虚拟化功能，可以执行嵌套虚拟化功能，比如安装Docker、安卓模拟器等。

!> CPU虚拟化选项与`Hyper-V`冲突。

<!-- tabs:end -->

### 安装Windows

1. 通过临时禁用网络，注册本地账号
2. 安装VMware Tools
3. 更新系统后，关机，制作快照

[filename](1.mp4 ':include :type=video width=800px')

### 安装Kali Linux


### 安装VMware Tools

### 虚拟机文件

[虚拟机文件](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-A968EF50-BA25-450A-9D1F-F8A9DEE640E7.html)类型介绍

## 常用功能

### 拍摄快照

为虚拟机拍摄快照可以保存虚拟机的当前状态，使您能够重复返回到同一状态。拍摄快照时，Workstation Pro 会捕捉虚拟机的完整状态。您可以使用快照管理器来查看和操作活动虚拟机的快照。

我们在进行重要操作时，比如`刚安装好虚拟机`、`重要软件部署前后`，通过拍摄快照，我们可以快速回到指定的虚拟机状态，不必重新安装操作系统。

选择虚拟机，`右键`或点击菜单栏`虚拟机`选项，选择`快照>拍摄快照`。

!> 如果不必要保存虚拟机的内存信息，即实时状态信息，可以在**虚拟机处于关机状态下进行拍摄快照**，这样可减少快照占用物理机的硬盘空间。

### 克隆虚拟机

通过`克隆虚拟机`功能，可以快速创建若干一样的虚拟机，减少重复安装的麻烦。

<!-- tabs:start -->
#### **第一步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA1.png)

#### **第二步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA2.png)

#### **第三步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA3.png)

如果是`链接克隆`，原始虚拟机不能删除。

如果是`完整克隆`，相当于完整复制得到一个独立的虚拟机。

#### **第四步**

![](http://oss.dropsec.xyz/book/%E5%85%8B%E9%9A%86%E8%99%9A%E6%8B%9F%E6%9C%BA4.png)

<!-- tabs:end -->


### 删除虚拟机

右键`移除`，不会从磁盘中删除虚拟机，如下图所示。

![](http://oss.dropsec.xyz/book/%E7%A7%BB%E9%99%A4%E8%99%9A%E6%8B%9F%E6%9C%BA.png)

正确的做法是，选择虚拟机，然后选择`虚拟机 > 管理 > 从磁盘中删除`。或者，直接删除虚拟机目录文件。


### 网络编辑器

通过菜单的`编辑-虚拟网络编辑器`进行网络连接设置。

<!-- tabs:start -->
#### **桥接（Bridge）模式**

![桥接（Bridge）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-8AB8E6E2-E16F-4E60-8421-669C96E6BF38-high.png)

就像是网络中的物理机

#### **网络地址转换（NAT）模式**

![网络地址转换（NAT）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-4C1FE8E1-9C52-4A43-9C36-97AEC38C737B-high.png)

与虚拟机**共享主机的IP地址**

#### **仅主机（host-only）模式**

![仅主机（host-only）模式](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/images/GUID-B8B0D851-3DF2-4999-AE86-9059AE017A9C-high.png)

- 独立的虚拟网络
- 在默认配置中，仅主机模式网络中的虚拟机无法连接到Internet
<!-- tabs:end -->

!> 从保护虚拟机安全角度出发，若无特殊必要，尽可能**不选择桥接模式**

### [与物理机传输文件](https://docs.vmware.com/cn/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-6F26D7EF-8D29-46E9-A48E-0BCBB138D333.html)

- 安装VMware Tools后，可以`复制粘贴`或`拖放`传输文件
- 安装VMware Tools后，使用共享文件夹

## Q&A

1. 如何给他人拷贝虚拟机？
  
  - 直接拷贝虚拟机目录，但是由于虚拟机目录可能存在不需要的快照信息，导致虚拟机目录文件过大。可以先进行`完整克隆`然后拷贝文件。
  - 导出OVF文件

2. 移动或复制虚拟机的提示

![](http://oss.dropsec.xyz/book/%E7%A7%BB%E5%8A%A8%E6%88%96%E5%A4%8D%E5%88%B6%E8%99%9A%E6%8B%9F%E6%9C%BA%E6%8F%90%E7%A4%BA.png)

`移动虚拟机`是指将移动虚拟机文件的位置，重新启动后，不更改MAC地址。

`复制虚拟机`是指复制了一份虚拟机文件，重新启动后，为避免网络冲突，会更改MAC地址。