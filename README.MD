# WappalyzerParse
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/iiiusky/WappalyzerParse)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/iiiusky/WappalyzerParse)
![GitHub](https://img.shields.io/github/license/iiiusky/WappalyzerParse)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/iiiusky/WappalyzerParse)
![GitHub top language](https://img.shields.io/github/languages/top/iiiusky/WappalyzerParse)

## 描述
> 该项目是我在小工具中使用到了[Wappalyzer](https://github.com/AliasIO/wappalyzer)的指纹库,并将其抽取出来作为一个简单的指纹识别库][reference].
> 当前支持直接解析源`technologies.json`文件,并且输出结构体或者json字符串信息,方便后续的使用.

## 使用方式
```
go get github.com/iiiusky/WappalyzerParse
```

### 直接获取指纹库结构体

```go
w := &WappalyzerParse{}
w.InitFingerPrintData()
fmt.Println(w.Fingerprints)
```

### 输出json字符串
```go
w := &WappalyzerParse{}
w.InitFingerPrintData()
str := w.FormatJson()
fmt.Println(str)
```

### 自定义文件路径
```go
w := &WappalyzerParse{
    Filename: "xxx.json",
}
w.InitFingerPrintData()
fmt.Println(w.Fingerprints)
```

### 开启错误信息输出

```go
w := &WappalyzerParse{
    IsDebug: true,
}
w.InitFingerPrintData()
fmt.Println(w.Fingerprints)
```

## todo
- 支持解析
- 兼容后续的官方指纹库信息

[reference]: https://github.com/AliasIO/wappalyzer)的指纹库,并将其抽取出来作为一个简单的指纹识别库