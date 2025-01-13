# Frida Patcher
Frida Patcher 是专为 Frida 二进制文件设计的修补程序系统，以避免基于工件的检测。
该工具通过修补二进制工件来帮助绕过检测。

# 说明
- 补丁后程序可能卡到黑屏/无反应/死机。
- 过滤关键字需要在filter_xxx.json文件中设置。filter_xxx.json中的值是【空】表示生成随机符，否则自定义。其中#R5表示生成5个随机字符。
- 需要替换 frida:rpc 字符在这个路径：Python/Lib/site-packages/frida
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
使用以下命令修补现有的 frida 二进制文件。1661 是版本号16.6.1
```bash
python main.py --input bin/frida-server --output bin/patched/frida-server --filter filter_elf.json --seed 1661
python main.py --input /Python/Lib/site-packages/frida  --filter filter_py.json --seed 1661
```
```bash
hexreplace.exe -input bin/frida-server -output bin/patched/frida-server -filter filter-elf.json -seed 1661
```
如果要使用导出验证系统，请使用以下命令。
```bash
python main.py --input bin/stock/frida-server --output bin/patched/frida-server --verify
```
