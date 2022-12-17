// 基于 TOTP 的 FRP 访问授权验证
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

var appName string
var buildRev string
var buildDate string
var buildVersion string

var entry = flag.String("e", "web", "工具启动入口")
var proxy = flag.String("p", "", "代理通道名")
var configFile = flag.String("c", "frp.otp.json", "OPT 配置文件")
var showVer = flag.Bool("v", false, "显示应用版本信息并退出")
var showHelp = flag.Bool("h", false, "显示应用帮助信息并退出")

// LoadJSON 从文件加载 JSON 到变量
func LoadJSON(file string, in interface{}) error {
	var err error
	var data []byte

	if data, err = ioutil.ReadFile(file); nil == err {
		err = json.Unmarshal(data, in)
	}

	return err
}

// SaveJSON 保存数据到 JSON 文件
func SaveJSON(file string, in interface{}) error {
	var bj, _ = json.Marshal(in)

	return ioutil.WriteFile(file, bj, 0644)
}

// IsFile returns true if given path is a file,
// or returns false when it's a directory or does not exist.
func IsFile(filePath string) bool {
	f, e := os.Stat(filePath)
	if e != nil {
		return false
	}
	return !f.IsDir()
}

// runWeb 运行 WEB 服务器
func runWeb(cfg *Config) error {
	var s, err = NewServer(cfg)
	if nil == err {
		err = s.Run()
	}

	return err
}

// genOtpKey 生成通道KEY
func genOtpKey(cfg *Config, proxy string) error {
	if c, ok := cfg.Channel[proxy]; ok {
		fmt.Println("正在生成通道 " + proxy + " 的 OTP KEY")
		c.GenerateOTP(proxy, cfg.Domain)
	} else {
		if "" == proxy {
			fmt.Println("请输入要生成 OTP KEY 的通道，当前可用通道列表：")
		} else {
			fmt.Println("输入的通道 " + proxy + " 不存在，当前可用通道列表：")
		}

		for k := range cfg.Channel {
			fmt.Println(k)
		}
	}

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "使用说明: ", filepath.Base(os.Args[0]), " 参数选项")
		fmt.Fprintln(os.Stderr, "欢迎使用 FRP 访问授权验证工具")
		fmt.Fprintln(os.Stderr, "更多信息: http://github.com/csg800/frp-otp")
		fmt.Fprintln(os.Stderr, "")

		fmt.Fprintln(os.Stderr, "参数选项:")
		flag.PrintDefaults()

		if *showHelp {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "启动入口：")
			fmt.Fprintln(os.Stderr, "          web      启用访问授权验证服务")
			fmt.Fprintln(os.Stderr, "          key      为通道生成访问授权KEY")
		}
	}

	flag.Parse()

	if *showVer {
		fmt.Println(appName + " " + "Ver: " + buildVersion + " build: " + buildDate + " Rev:" + buildRev)
		return
	}

	if *showHelp {
		flag.Usage()
		return
	}

	defer func() {
		if err := recover(); nil != err {
			fmt.Println("system error:", err)
		}
	}()

	var err error
	var cfg = new(Config)
	if IsFile(*configFile) {
		if err = LoadJSON(*configFile, cfg); nil == err {
			if 0 == len(cfg.Channel) {
				err = errors.New("配置文件中通道列表为空")
			} else {
				switch *entry {
				case "web":
					err = runWeb(cfg)
				case "key":
					err = genOtpKey(cfg, *proxy)
				default:
					flag.Usage()
				}
			}
		} else {
			err = errors.New("加载配置文件失败：" + err.Error())
		}
	} else {
		err = errors.New("配置文件 " + *configFile + " 不存在")
	}

	if nil != err {
		fmt.Println("错误：", err)
	}
}
