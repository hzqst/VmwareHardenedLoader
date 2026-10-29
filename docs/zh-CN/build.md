# 构建要求与动态数据

[返回 README](../../README.zh-CN.md) · [English](../en/build.md)

## 环境要求

- Visual Studio 2022
- Windows Driver Kit 10
- .NET SDK 9 或更高版本（用于 CustomBuildTool）

维护的构建配置包括 Release|x64、Debug|x64、Release|ARM64 和 Debug|ARM64。

## 构建

打开安装 WDK 的 Visual Studio 2022 Developer Command Prompt，然后执行：

~~~bat
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
~~~

调试构建使用：

~~~bat
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Debug /p:Platform=x64
~~~

将 /p:Platform=ARM64 与任一配置组合即可交叉构建 ARM64 驱动。动态数据准备工具仍以 x64 主机工具运行，并生成同时包含 AMD64 和 ARM64 记录的共享数据集。

在 C/C++ 编译前，项目会自动执行以下步骤：

1. 将最新 manifest 从 https://github.com/HLND2T/kphtools/releases/latest/download/kphdyn.xml 下载到临时文件；若已设置 VMLOADER_KPHDYN_URL 环境变量，则改为从该变量指定的 URL 下载。
2. 在禁用 DTD 处理的情况下解析 XML，并确认存在可用的固件记录。
3. 只有验证成功后，才原子替换 thirdparty/systeminformer/kphlib/kphdyn.xml。
4. 构建 System Informer 的 CustomBuildTool，生成 v20 内嵌源码和 ksidyn.bin。
5. 使用 RSA-PSS/SHA-512 对二进制文件签名，再用匹配的公钥验证，并发布结果。
6. 在中间构建目录下生成驱动公钥头文件。

构建过程不会使用缓存的 manifest。下载、XML 验证、生成、签名或验证任一步失败都会终止构建。

manifest 覆盖值会在下载前按绝对 HTTPS URL 校验，其他取值会终止构建。Nightly 工作流使用该变量针对 kphtools 的 nightly manifest 构建：

~~~bat
set VMLOADER_KPHDYN_URL=https://github.com/HLND2T/kphtools/releases/download/nightly/kphdyn.xml
msbuild VmLoader.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
~~~

构建需要访问 GitHub 的 HTTPS；还原 CustomBuildTool 包时可能需要访问 NuGet。

## 动态数据格式

构建生成 KPH 动态配置版本 20。在 System Informer v19 内核布局的基础上，新增以下 ULONG RVA：

- `nt!ExpFirmwareTableResource`
- `nt!ExpFirmwareTableProviderListHead`

每条记录都必须按以下字段精确匹配：

~~~text
Class + Machine + TimeDateStamp + SizeOfImage
~~~

缺少任一固件字段的记录会将缺失值写为 ULONG_MAX，并在运行时视为不受支持。

驱动在使用前会验证两个 RVA：它们必须非零、互不相同，并且位于运行中 ntoskrnl.exe 映像的可写且不可执行节中。

## 签名密钥

首次成功准备时，如果两个密钥文件都不存在，构建会在以下位置创建 VmLoader 专用的 4096 位 RSA 密钥对：

~~~text
thirdparty\systeminformer\tools\CustomSignTool\Resources\kph.key
thirdparty\systeminformer\tools\CustomSignTool\Resources\public.key
~~~

这两个文件由 System Informer 子模块忽略。私钥不会复制到父仓库、中间公钥头文件或打包输出中。

请同时备份 kph.key 和 public.key。如果只存在其中一个文件，构建会失败，而不会静默轮换签名身份。密钥对丢失或被替换后，必须重新构建驱动并重新签名所有外部动态数据。

## 构建输出

x64 和 ARM64 构建都会在 bin 下发布以下运行时文件：

~~~text
bin\vmloader.sys
bin\vmloader.pdb
bin\dyndata.bin
bin\dyndata.sig
~~~

构建目标会将驱动、动态数据文件和 PDB 复制到安装脚本所在的同一目录。在本地构建其他架构或配置会覆盖 bin 中之前生成的工件；CI 工作流会在隔离的 job 中构建每个目标并立即打包。

`vmloader.sys` 保持未签名状态。加载前必须使用测试或生产代码签名证书为其签名。
