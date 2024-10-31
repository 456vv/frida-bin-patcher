# Frida Patcher
Frida Patcher 是专为 Frida 二进制文件设计的修补程序系统，以避免基于工件的检测。
该工具通过修补二进制工件来帮助绕过检测。

# 特征
- 补丁后程序可能卡到黑屏/无反应/死机。
- 过滤关键字需要在filter.json文件中设置。filter.jso中的值是【空】表示生成随机符，否则自定义。
- 你还可以使用patch方式：https://github.com/456vv/Florida

# 先决条件
- Python version 3.x
- Frida binary (Gadget, Server or Inject).

# 安装
1. 克隆存储库:
```bash
git clone https://github.com/456vv/frida-bin-patcher.git
cd frida-bin-patcher
```

2. 安装依赖项
```bash
pip install -r requirements.txt -t src
```

# 如何使用
使用以下命令修补现有的 frida 二进制文件。
```bash
python main.py --input bin/stock/frida-server --output bin/patched/frida-server
```
如果要使用导出验证系统，请使用以下命令。
```bash
python main.py --input bin/stock/frida-server --output bin/patched/frida-server --verify
```
