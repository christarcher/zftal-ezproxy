package main

import (
	"embed"
	// "fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

//go:embed login_slogin.html
var content embed.FS 

var (
	backendURL         = "http://127.0.0.1"
	listenAddr         = ":8000"
	targetHost         = "newjw.cuz.edu.cn"
	targetPathSuffixes = []string{
		"/jwglxt/",
		"/zftal-ui-v5-1.0.2/",
	}
	allowedUsers = []string{
		"22010101",
	}
)

func main() {
	target, err := url.Parse(backendURL)
	if err != nil {
		log.Fatal("无法解析后端URL:", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// 修改头部和删除referer,origin
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetHost
		req.Header.Set("Host", targetHost)
		req.Header.Del("Referer")
		req.Header.Del("Origin")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		originalPath := r.URL.Path
		cleanPath := path.Clean(originalPath)

		if originalPath != "/" && strings.HasSuffix(originalPath, "/") && !strings.HasSuffix(cleanPath, "/") {
			cleanPath += "/"
		}

		if cleanPath != originalPath {
			log.Printf("可疑路径拦截: %s 访问了 %s", r.RemoteAddr, originalPath)
			http.Error(w, "非法路径", http.StatusBadRequest)
			return
		}

		// 设置合法的路径前缀以及合法路径
		allowed := false
		for _, prefix := range targetPathSuffixes {
			if strings.HasPrefix(cleanPath, prefix) {
				allowed = true
				break
			}
		}
		if cleanPath == "/jwglxt/xtgl/login_slogin.html" {
			allowed = true
		}

		if !allowed {
			log.Printf("未授权路径: %s - %s", r.RemoteAddr, cleanPath)
			http.NotFound(w, r)
			return
		}

		// 处理login_slogin.html的替换
		if r.Method == "GET" && cleanPath == "/jwglxt/xtgl/login_slogin.html" {
			success, err := serveLoginHTML(w, r)
			if !success {
				http.Error(w, err, http.StatusInternalServerError)
			}
			return
		}
		if r.Method == "POST" && cleanPath == "/jwglxt/xtgl/login_slogin.html" {
			success, err := validateLogin(w, r)
			if !success {
				http.Error(w, err, http.StatusForbidden)
				return
			}
		}

		proxy.ServeHTTP(w, r)
	})

	log.Printf("反向代理服务器启动在 %s", listenAddr)
	log.Printf("后端服务器: %s", backendURL)
	log.Printf("目标Host: %s", targetHost)
	log.Printf("允许的路径前缀: %v", targetPathSuffixes)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// 用于控制正方登录页面
func serveLoginHTML(w http.ResponseWriter, r *http.Request) (bool, string) {
	data, err := content.ReadFile("login_slogin.html")
	if err != nil {
		log.Printf("读取HTML文件失败: %v", err)
		return false, "Failed to get html file"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return true, ""
}

// validateLogin 验证POST登录请求
func validateLogin(w http.ResponseWriter, r *http.Request) (bool, string) {
	// 读取请求体并保存因为ParseForm会消耗掉body,注意需要恢复请求体
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("读取请求体失败: %v", err)
		return false, "Bad Request"
	}
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	if err := r.ParseForm(); err != nil {
		log.Printf("解析表单失败: %v", err)
		return false, "Bad Request"
	}
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	username := r.FormValue("yhm")
	if !isUserAllowed(username) {
		log.Printf("拒绝访问: 用户名%s不在白名单中", username)
		return false, "Access Denied"
	}

	log.Printf("验证通过: 用户名%s", username)
	return true, ""
}

// isUserAllowed 检查用户是否在白名单中
func isUserAllowed(username string) bool {
	for _, user := range allowedUsers {
		if user == username {
			return true
		}
	}
	return false
}
