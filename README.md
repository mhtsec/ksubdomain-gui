# KSubdomain-GUI 
本项目基于KSubdomain 本项目基于KSubdomain是一款基于无状态技术的子域名爆破工具，带来前所未有的扫描速度和极低的内存占用。 告别传统工具的效率瓶颈，体验闪电般的 DNS 查询，同时拥有可靠的状态表重发机制，确保结果的完整性。 KSubdomain 支持 Windows、Linux 和 macOS，是进行大规模DNS资产探测的理想选择。
原项目：[https://github.com/boy-hack/ksubdomain/](https://github.com/boy-hack/ksubdomain/)

注意！mac使用需要在命令行使用sudo执行，否则识别不到网卡
## 预览
![image](https://github.com/user-attachments/assets/c5ca0088-851d-4b9d-aebe-9332c37e75b0)

#  编译指南

## 如何自行编译

要自行编译KSubdomain-GUI，请按照以下步骤操作：

1. 将本项目下载后放在原项目（KSubdomain）的cmd文件夹中
2. 编译即可

## 目录结构

放置在原项目的cmd目录后，目录结构应如下：

```
cmd/
├── ksubdomain/         # 原项目的命令行工具目录
└── ksubdomain-gui/     # 本GUI项目目录
    ├── main.go         # GUI主程序
    ├── go.mod          # 依赖管理文件
    ├── go.sum          # 依赖校验文件
    ├── icon.ico        # 图标文件
    ├── main.rc         # 资源配置文件
    └── icon.syso       # 编译后的资源文件
```

## 编译命令

在KSubdomain项目根目录下执行：

```bash
go build -ldflags="-s -w" -o ksubdomain-gui cmd/ksubdomain-gui/main.go
```

编译完成后将在项目根目录生成可执行文件`ksubdomain-gui`。

## 注意事项

- 确保您的Go环境已正确配置
- 确保已安装所有必要的依赖
- 如遇到编译问题，请检查原项目版本兼容性

如有任何问题，请提交Issue或Pull Request。 
