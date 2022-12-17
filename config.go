package main

import (
	"bytes"
	"fmt"
	"image/png"
	"io/ioutil"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Config 配置
type Config struct {
	Enforce     bool                `json:"enforce"`
	Domain      string              `json:"domain"`
	BindAddress string              `json:"BindAddress"`
	Channel     map[string]*Channel `json:"Channel"`
}

// GC 清理没用的数据
func (c *Config) GC() {
	for _, channel := range c.Channel {
		channel.GC()
	}
}

// Channel 通道配置
type Channel struct {
	Status    bool             `json:"status"`
	Model     string           `json:"model"`
	Secret    string           `json:"secret"`
	Issuer    string           `json:"issuer"`
	Lock      *sync.RWMutex    `json:"-"`
	Notifies  []Notify         `json:"notify"`
	Blacklist []string         `json:"blacklist"`
	Whitelist []string         `json:"whitelist"`
	Allow     map[string]int64 `json:"-"`
	Block     map[string]int64 `json:"-"`
}

// GenerateOTP 生成OTP二维码
func (c *Channel) GenerateOTP(proxy string, domain string) {
	var key, err = totp.Generate(totp.GenerateOpts{
		Period:      30,
		SecretSize:  32,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA512,
		Issuer:      domain,
		AccountName: proxy + "@" + domain,
	})

	if nil == err {
		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			fmt.Print(err)
		}

		png.Encode(&buf, img)

		fmt.Printf("Issuer:       %s\n", key.Issuer())
		fmt.Printf("Account Name: %s\n", key.AccountName())
		fmt.Printf("Secret:       %s\n", key.Secret())
		fmt.Println("Writing PNG to qr-code.png....")
		ioutil.WriteFile("qr-code.png", buf.Bytes(), 0644)
		fmt.Println("")
		fmt.Println(key.String())
		fmt.Println("")
	}
}

// Check 检查一次性验证码是否有效
func (c *Channel) Check(code string) bool {
	var opt = totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA512,
	}
	var valid, _ = totp.ValidateCustom(code, c.Secret, time.Now().UTC(), opt)

	return valid
}

// IsAllow 是否充许访问
func (c *Channel) IsAllow(ip string) bool {
	var ts int64
	var ok, allow, block bool

	c.Lock.RLock()
	defer c.Lock.RUnlock()

	for _, v := range c.Whitelist {
		if v == ip {
			allow = true
			break
		}
	}

	if !allow {
		for _, v := range c.Blacklist {
			if v == ip {
				block = true
				break
			}
		}
	}

	if !allow && !block {
		if ts, ok = c.Block[ip]; ok {
			if time.Now().Unix() < ts {
				block = true
			}
		}
	}

	if !allow && !block {
		if ts, ok = c.Allow[ip]; ok {
			if time.Now().Unix() < ts {
				allow = true
			}
		}
	}

	return allow
}

// IsBlock 是否被屏蔽
func (c *Channel) IsBlock(ip string) (int64, bool) {
	var ts int64
	var ok, block bool

	c.Lock.RLock()
	defer c.Lock.RUnlock()

	for _, v := range c.Blacklist {
		if v == ip {
			block = true
			break
		}
	}

	if !block {
		if ts, ok = c.Block[ip]; ok {
			if time.Now().Unix()+60 < ts {
				block = true
			}
		}
	}

	return ts, block
}

// AddAllow 添加白名单
func (c *Channel) AddAllow(ip string, ts int64) {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	if nil == c.Allow {
		c.Allow = make(map[string]int64, 100)
	}

	c.Allow[ip] = ts
}

// AddBlock 添加黑名单
func (c *Channel) AddBlock(ip string, ts int64, step int64) {
	c.Lock.Lock()
	defer c.Lock.Unlock()

	if nil == c.Block {
		c.Block = make(map[string]int64, 100)
	}

	if t, ok := c.Block[ip]; ok && t > ts {
		if t-ts < 60 {
			c.Block[ip] = t + step
		} else {
			c.Block[ip] = t + step*30
		}
	} else {
		c.Block[ip] = ts + step
	}
}

// GC 清理过期数据
func (c *Channel) GC() {
	var ts int64
	var ip string
	var now = time.Now().Unix()

	c.Lock.Lock()
	defer c.Lock.Unlock()

	for ip, ts = range c.Allow {
		if ts < now {
			delete(c.Allow, ip)
		}
	}
	for ip, ts = range c.Block {
		if ts < now {
			delete(c.Block, ip)
		}
	}
}

// Notify 通知配置
type Notify struct {
	Name   string                 `json:"name"`
	Action string                 `json:"action"`
	Config map[string]interface{} `json:"config"`
}
