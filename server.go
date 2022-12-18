package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	plugin "github.com/fatedier/frp/pkg/plugin/server"
)

// Server 服务器
type Server struct {
	ec   int
	cfg  *Config
	s    *http.Server
	h    map[string]func(r *http.Request, req *plugin.Request) *plugin.Response
	done chan struct{}
}

// NewServer 创建服务器
func NewServer(cfg *Config) (*Server, error) {
	s := &Server{
		cfg:  cfg,
		done: make(chan struct{}, 1),
	}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

// Run 开始运行
func (s *Server) Run() error {
	go s.handlerSignal()

	var err = s.s.ListenAndServe()
	<-s.done
	return err
}

// Stop 停止
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.s.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown HTTP server error: %v", err)
	}
	log.Printf("HTTP server exited")
	close(s.done)
	return nil
}

// init 初始化
func (s *Server) init() error {
	s.s = &http.Server{
		Handler: s,
		Addr:    s.cfg.BindAddress,
	}
	s.h = map[string]func(r *http.Request, req *plugin.Request) *plugin.Response{
		plugin.OpPing:        s.handlePing,
		plugin.OpLogin:       s.handleLogin,
		plugin.OpNewUserConn: s.handleNewUserConnect,
		plugin.OpNewProxy:    s.handleNewProxy,
		plugin.OpCloseProxy:  s.handleCloseProxy,
		plugin.OpNewWorkConn: s.handleNewWorkConnect,
	}

	for _, v := range s.cfg.Channel {
		if nil == v.Lock {
			v.Lock = new(sync.RWMutex)
		}
	}

	return nil
}

// handlerSignal 信号处理
func (s *Server) handlerSignal() {
	var sig = make(chan os.Signal, 2)
	var tick = time.After(time.Second * 300)

	signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sv := <-sig:
			switch sv {
			case os.Interrupt, syscall.SIGINT:
				if 0 == s.ec {
					log.Println("Send ^C to force exit...")
				}

				if s.ec > 0 {
					s.Stop()
				}

				s.ec++
			case os.Kill, syscall.SIGTERM:
				s.Stop()
			case syscall.SIGHUP:
				s.cfg.GC()
			}
		case <-tick:
			s.cfg.GC()
		}
	}
}

// ServeHTTP WEB 入口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var uri = strings.ToLower(r.URL.Path)

	if "/" == uri {
		s.WebIndex(w, r)
	} else if "/knock" == uri {
		s.WebKnock(w, r)
	} else if "/handler" == uri {
		s.HandleRPC(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// SendJSON 发送JSON输出
func (s *Server) SendJSON(w http.ResponseWriter, r *http.Request, data interface{}) {
	var err error
	var bj []byte

	if nil == data {
		bj = []byte(`{"status":false, "msg":"unknown action"}`)
	} else {
		if bj, err = json.Marshal(data); nil != err {
			bj = []byte(`{"status": false, "msg":"` + err.Error() + `":`)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(bj)
}

// SendHTML 发送 HTML 代码
func (s *Server) SendHTML(w http.ResponseWriter, r *http.Request, status int, html string) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.WriteHeader(status)

	w.Write([]byte(html))
}

// WebIndex 首页
func (s *Server) WebIndex(w http.ResponseWriter, r *http.Request) {
	s.SendHTML(w, r, http.StatusOK, "授权验证")
}

// WebKnock 敲门
func (s *Server) WebKnock(w http.ResponseWriter, r *http.Request) {
	var ip, content string
	var code = r.FormValue("code")
	var channel = r.URL.Query().Get("channel")

	if c, ok := s.cfg.Channel[channel]; ok {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		if ts, block := c.IsBlock(ip); block {
			if ts > 0 {
				c.AddBlock(ip, time.Now().Unix(), 10)
				content = "您的 IP " + ip + " 被自动屏蔽，请于 " + time.Unix(ts, 0).Format("2006-01-02 15:04:05") + " 后再重试"
			} else {
				content = "您的 IP " + ip + " 在黑名单中，请联系管理员"
			}

			http.Error(w, content, http.StatusForbidden)
		} else {
			if "" == code {
				content = "<html><head><title>请输入授权码</title></head><body><p>请输入授权码：</p><form method='POST'><input type='text' id='code' name='code' /><input type='submit' value='提交' /></form></body></html>"
			} else {
				if c.Check(code) {
					c.AddAllow(ip, time.Now().Unix()+300)
					content = "<html><head><title>验证成功</title><body>验证成功，请于五分钟内访问</body></html>"
				} else {
					c.AddBlock(ip, time.Now().Unix(), 10)
					content = "<html><head><title>请输入授权码</title></head><p>授权码错误，请输入授权码：</p><body><form method='POST'><input type='text' id='code' name='code' /><input type='submit' value='提交' /></form></body></html>"
				}
			}

			s.SendHTML(w, r, http.StatusOK, content)
		}
	} else if s.cfg.Enforce {
		http.Error(w, "Forbidden", http.StatusForbidden)
	} else {
		http.Error(w, "Ok", http.StatusOK)
	}
}

// HandleRPC 处理接口过来的请求
func (s *Server) HandleRPC(w http.ResponseWriter, r *http.Request) {
	var err error
	var req *plugin.Request
	var res *plugin.Response

	if req, err = s.parseRequest(r); nil == err {
		if fn, ok := s.h[req.Op]; ok {
			res = fn(r, req)
		} else {
			res = &plugin.Response{
				Reject:       true,
				RejectReason: "unknown operation",
			}
		}
	} else {
		res = &plugin.Response{
			Reject:       true,
			RejectReason: "parse request error: " + err.Error(),
		}
	}

	s.SendJSON(w, r, res)
}

// handlePing 处理心跳相关信息
func (s *Server) handlePing(r *http.Request, req *plugin.Request) *plugin.Response {
	var resp = new(plugin.Response)

	resp.Unchange = true

	return resp
}

// handleLogin 处理用户登录操作信息
func (s *Server) handleLogin(r *http.Request, req *plugin.Request) *plugin.Response {
	var resp = new(plugin.Response)
	// var content = req.Content.(*plugin.LoginContent)
	// var token = content.Metas["token"]

	// if content.User == "" || token == "" {
	// 	resp.Reject = true
	// 	resp.RejectReason = "user or meta token can not be empty"
	// } else if content.User != "" {
	// 	resp.Unchange = true
	// } else {
	// 	resp.Reject = true
	// 	resp.RejectReason = "invalid meta token"
	// }

	resp.Unchange = true

	return resp
}

// handleNewUserConnect 处理创建用户连接 (支持 tcp、stcp、https 和 tcpmux 协议)。
func (s *Server) handleNewUserConnect(r *http.Request, req *plugin.Request) *plugin.Response {
	var ip string
	var resp = new(plugin.Response)
	var content = req.Content.(*plugin.NewUserConnContent)

	if c, ok := s.cfg.Channel[content.ProxyName]; ok {
		if c.Status {
			if "bypass" == c.Model {
				resp.Unchange = true
				resp.Content = content
			} else {
				ip, _, _ = net.SplitHostPort(content.RemoteAddr)
				if c.IsAllow(ip) {
					resp.Unchange = true
					resp.Content = content
				} else {
					resp.Reject = true
					resp.RejectReason = "user ip not in allow Whitelist"
				}
			}
		} else {
			resp.Reject = true
			resp.RejectReason = "proxy is not enable"
		}
	} else if s.cfg.Enforce {
		resp.Reject = true
		resp.RejectReason = "proxy is not config"
	} else {
		resp.Unchange = true
		resp.Content = content
	}

	return resp
}

// handleNewProxy 处理创建代理的相关信息
func (s *Server) handleNewProxy(r *http.Request, req *plugin.Request) *plugin.Response {
	var resp = new(plugin.Response)
	var content = req.Content.(*plugin.NewProxyContent)

	if c, ok := s.cfg.Channel[content.ProxyName]; ok {
		if c.Status {
			resp.Unchange = true
			resp.Content = content
		} else {
			resp.Reject = true
			resp.RejectReason = "proxy is not enable"
		}
	} else if s.cfg.Enforce {
		resp.Reject = true
		resp.RejectReason = "proxy is not config"
	} else {
		resp.Unchange = true
		resp.Content = content
	}

	return resp
}

// handleCloseProxy 处理代理关闭。(仅用于通知)
func (s *Server) handleCloseProxy(r *http.Request, req *plugin.Request) *plugin.Response {
	var resp = new(plugin.Response)

	resp.Unchange = true

	return resp
}

// handleNewWorkConnect 处理创建工作连接
func (s *Server) handleNewWorkConnect(r *http.Request, req *plugin.Request) *plugin.Response {
	var resp = new(plugin.Response)

	resp.Unchange = true

	return resp
}

// parseRequest 解析请求数据
func (s *Server) parseRequest(r *http.Request) (*plugin.Request, error) {
	var err error
	var op string
	var findOp bool
	var data []byte
	var idx, cnt int
	var body interface{}
	var req *plugin.Request

	if data, err = io.ReadAll(r.Body); nil == err {
		for k, v := range data {
			if '"' == v {
				if k > 0 && '\\' == data[k-1] {
					continue
				}

				cnt++
				if 1 == cnt%2 {
					idx = k
				} else {
					if k-idx == 3 && (('o' == data[k-2] || 'O' == data[k-2]) && ('p' == data[k-1] || 'P' == data[k-1])) {
						findOp = true
					} else if findOp {
						op = string(data[idx+1 : k])

						break
					}
				}
			}
		}

		if findOp {
			switch op {
			case plugin.OpPing:
				body = &plugin.PingContent{}
			case plugin.OpLogin:
				body = &plugin.LoginContent{}
			case plugin.OpNewUserConn:
				body = &plugin.NewUserConnContent{}
			case plugin.OpNewProxy:
				body = &plugin.NewProxyContent{}
			case plugin.OpCloseProxy:
				body = &plugin.CloseProxyContent{}
			case plugin.OpNewWorkConn:
				body = &plugin.NewWorkConnContent{}
			default:
				err = errors.New("unknown operation")
			}

			if nil == err {
				req = &plugin.Request{
					Content: body,
				}

				err = json.Unmarshal(data, req)
			}
		}
	}

	return req, err
}
