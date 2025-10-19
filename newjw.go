package main

import (
	"embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

// 关于这个替换login_slogin.html,是为了防止有些学校使用sso,把流量302到sso上,用不上不开就ok
//go:embed static
var content embed.FS

var (
	backendURL         = "http://newjw.cuz.edu.cn"
	listenAddr         = ":8000"
	replaceLoginPage   = false
	targetHost         = "newjw.cuz.edu.cn"
	targetPathSuffixes = []string{
		"/jwglxt/",
		"/zftal-ui-v5-1.0.2/",
		"/zftal-ezproxy/", // 未来用于写控制面板,暂时先放这
	}
	allowedUsers = []string{
		"22010101",
	}
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

func logInfo(format string, args ...interface{}) {
	log.Printf("%s[INFO]%s "+format, append([]interface{}{colorGreen, colorReset}, args...)...)
}
func logWarn(format string, args ...interface{}) {
	log.Printf("%s[WARN]%s "+format, append([]interface{}{colorYellow, colorReset}, args...)...)
}
func logError(format string, args ...interface{}) {
	log.Printf("%s[ERROR]%s "+format, append([]interface{}{colorRed, colorReset}, args...)...)
}

func main() {
	target, err := url.Parse(backendURL)
	if err != nil {
		logInfo("无法解析后端URL:", err)
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
			logWarn("%s 访问了可疑路径 %s", r.RemoteAddr, originalPath)
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

		if !allowed {
			logWarn("%s 访问了未知路径 %s", r.RemoteAddr, cleanPath)
			http.NotFound(w, r)
			return
		}

		if cleanPath == "/jwglxt/xtgl/login_slogin.html" {
			// 替换login_slogin.html(如果需要)
			if r.Method == "GET" && replaceLoginPage {
				serveLoginHTML(w)
				return
			}
			// 进行身份验证, 注意这里需要把请求代理到后端, 没有错误不需要return
			if r.Method == "POST" {
				success, errMsg := validateLogin(r)
				if !success {
					http.Error(w, errMsg, http.StatusForbidden)
					return
				}
			}
		}

		proxy.ServeHTTP(w, r)
	})

	logInfo("反向代理服务器启动在 %s", listenAddr)
	logInfo("后端服务器: %s", backendURL)
	logInfo("目标Host: %s", targetHost)
	logInfo("允许的路径前缀: %v", targetPathSuffixes)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func serveLoginHTML(w http.ResponseWriter) {
	data, err := content.ReadFile("static/login_slogin.html")
	if err != nil {
		logError("读取HTML文件失败: %v", err)
		http.Error(w, "读取HTML文件失败", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

// 验证POST登录请求
func validateLogin(r *http.Request) (bool, string) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return false, fmt.Sprintf("读取请求体失败: %v", err)
	}
	defer r.Body.Close()

	// 恢复body
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	if err := r.ParseForm(); err != nil {
		return false, fmt.Sprintf("解析表单失败: %v", err)
	}

	username := r.FormValue("yhm")
	if !isUserAllowed(username) {
		logWarn("用户名%s不在白名单中", username)
		return false, fmt.Sprintf("Access Denied: %s 不在白名单中", username)
	}

	log.Printf("[validateLogin]验证通过: 用户名%s", username)
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
