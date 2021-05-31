# encrypt

File Encrypt &amp; Decrypt-Project of BUAA 'Computer Network Security' Course

## Installation

1. 安装GMP大数库，安装过程可以参考博客:
   	https://blog.csdn.net/win_in_action/article/details/46956245
2. Tkinter为python自带，如果在linux上无法跑通，可以参考如下博客:
   	https://blog.csdn.net/toby54king/article/details/86498294
3. 安装opensssl，方法同课程组提供的资料

## Usage

1. 切换到receiver目录下，执行python3 ui.py，打开GUI；输入当前IP地址和要监听的端口号，点击监听(一定要先监听)
2. 切换到sender目录下，执行python3 ui.py，打开GUI;输入目的IP和端口号；输入并添加要传输的文件(可以添加多个)；点击发送进行发送
3. 此时，可以在receiver的GUI中看到接收到的文件(自动检测.txt结尾的数据文件)
4. 接收方与发送方均可以使用打开按钮来查看文件内容;接收方点击删除按钮会删除所选中的文件；发送方点击删除按钮是删除发送列表中的文件