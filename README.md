# IP-Crawl
本项目，从头至尾都是用openAI 生成，包括本readme大部分。
旨在监控游戏进程的TCP/UDP连接，做成相应的Clash Rule Provider。

`ipcrawl.py` 的最低的 Python 版本需求为 Python 3.6 或更高版本。此外，它依赖于以下 Python 标准库：

- `psutil`：用于获取系统和进程信息。
- `time`：用于进行延时操作。
- `sys`：用于从命令行接收参数。
- `ipaddress`：用于解析 IP 地址和子网。
- `socket`：用于获取协议名称。

在运行 `ipcrawl.py` 之前，请确保您的环境满足这些要求并已安装所需的运行库。

以下是一个简单的运行须知的 README 示例：

```
IPCrawl 是一个用于监视指定进程的网络连接并记录访问的 Python 脚本。

## 运行要求

- Python 3.6 或更高版本
- 必需的库：psutil

## 安装依赖

运行以下命令安装所需的依赖库：

```
pip install psutil
```

## 使用方法

运行 `ipcrawl.py` 脚本需要传入被监视程序的名称作为参数。例如：

```
python ipcrawl.py your_program_name
```

脚本将监视指定名称的进程的网络连接，并将连接的远程C段地址记录在 access_log.txt 文件中。

要停止运行 `ipcrawl.py`，按下 `Ctrl + C` 组合键。

请注意，在被监视的程序退出并重新启动后，`ipcrawl.py` 会自动开始监视新的进程实例。

```