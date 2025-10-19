package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
)

// 关于这个替换login_slogin.html,是为了防止有些学校使用sso,把流量302到sso上,用不上不开就ok
//
//go:embed static
var content embed.FS

var (
	backendURL         = "http://newjw.cuz.edu.cn"
	listenAddr         = ":8000"
	replaceLoginPage   = true
	targetHost         = "newjw.cuz.edu.cn"
	adminToken         = "hellofromint"
	targetPathSuffixes = []string{
		"/jwglxt/",
		"/zftal-ui-v5-1.0.2/",
		"/zftal-ezproxy/",
	}
)

var (
	usersMux sync.RWMutex
	usersMap = make(map[string]bool)
)

func init() {
	initialUsers := []string{"22010101"}
	for _, user := range initialUsers {
		usersMap[user] = true
	}
}

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

		// 处理login_slogin.html
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

		if strings.HasPrefix(cleanPath, "/zftal-ezproxy/") {
			switch cleanPath {
			case "/zftal-ezproxy/list":
				handleListUsers(w, r)
				return
			case "/zftal-ezproxy/add":
				handleAddUser(w, r)
				return
			case "/zftal-ezproxy/delete":
				handleDeleteUser(w, r)
				return
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

	// 恢复body,用于parseForm
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	if err := r.ParseForm(); err != nil {
		return false, fmt.Sprintf("解析表单失败: %v", err)
	}

	username := r.FormValue("yhm")
	if !isUserAllowed(username) {
		logWarn("用户名%s不在白名单中", username)
		return false, fmt.Sprintf("Access Denied: %s 不在白名单中", username)
	}

	// 再次恢复用于传输
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	logInfo("用户名%s验证通过", username)
	return true, ""
}

// isUserAllowed检查用户是否在白名单中
func isUserAllowed(username string) bool {
	usersMux.RLock()
	defer usersMux.RUnlock()
	return usersMap[username]
}

// Admin管理
func verifyToken(r *http.Request) bool {
	token := r.URL.Query().Get("token")
	return token == adminToken
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !verifyToken(r) {
		respondJSON(w, false, "token验证失败", nil)
		return
	}

	usersMux.RLock()
	defer usersMux.RUnlock()

	users := make([]string, 0, len(usersMap))
	for user := range usersMap {
		users = append(users, user)
	}

	respondJSON(w, true, "获取成功", users)
}

func handleAddUser(w http.ResponseWriter, r *http.Request) {
	if !verifyToken(r) {
		respondJSON(w, false, "token验证失败", nil)
		return
	}

	username := r.URL.Query().Get("user")
	if username == "" {
		respondJSON(w, false, "用户名不能为空", nil)
		return
	}

	usersMux.Lock()
	defer usersMux.Unlock()

	if usersMap[username] {
		respondJSON(w, false, "用户已存在", nil)
		return
	}

	usersMap[username] = true
	logInfo("添加用户: %s", username)
	respondJSON(w, true, "添加成功", username)
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !verifyToken(r) {
		respondJSON(w, false, "token验证失败", nil)
		return
	}

	username := r.URL.Query().Get("user")
	if username == "" {
		respondJSON(w, false, "用户名不能为空", nil)
		return
	}

	usersMux.Lock()
	defer usersMux.Unlock()

	if !usersMap[username] {
		respondJSON(w, false, "用户不存在", nil)
		return
	}

	delete(usersMap, username)
	logInfo("删除用户: %s", username)
	respondJSON(w, true, "删除成功", username)
}

func respondJSON(w http.ResponseWriter, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	response := map[string]interface{}{
		"success": success,
		"message": message,
		"data":    data,
	}
	json.NewEncoder(w).Encode(response)
}
