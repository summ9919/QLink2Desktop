package fnos

import (
	"encoding/json"
	"fmt"
	"html"
	"strconv"
	"strings"
)

// cgiScriptTemplate 生成子应用的 app/ui/index.cgi。
//
// 位置遵循官方约定：desktop_uidir=ui 时，桌面入口目录就是 app/ui/，
// 因此 .url 里声明的 /cgi/ThirdParty/<app>/index.cgi/… 也由这里的脚本承接。
//
// 它是「没有本地端口」的形态（网址快捷方式）唯一能跳出飞牛主机的出口：
// 入口配置里的 url 只能表达路径，host 永远是飞牛自己，只有 CGI 能返回 302
// 把浏览器发往真正的目标站点。
//
// ---------------------------------------------------------------------------
// 为什么脚本自己把活干完，不再转交给主程序（一次真机事故换来的结论）
// ---------------------------------------------------------------------------
// 早期版本在这里做三步：
//
//  1. 在一串候选路径里找主程序二进制（变量里混着未保护的 ${TRIM_APPDEST}）；
//  2. 找统一网关的 Unix Socket；
//  3. 两者都在就 `exec 主程序 --mode cgi …`。
//
// 真机实测（带 session 访问）一步步暴露了三个独立缺陷：
//
//  1. 脚本开头有 `set -u`，而 `${TRIM_APPDEST}` 在 CGI 环境下根本不存在。
//     bash 直接以 "unbound variable" 终止 —— **一行输出都没有**，
//     网关拿不到响应头，只能返回 500。用户看到的就是"网页出错了"。
//  2. 那串 exec 参数里的 `--app` 主程序压根没定义这个 flag
//     （`RunCGI` 内部是固定用 "qlink2desktop" 的）。`flag.Parse()` 报
//     "flag provided but not defined: -app" 并以状态码 2 退出 —— 又是 500。
//  3. 更要命的是 `exec` 会**替换**进程：只要它被调用，后面那段兜底 302
//     就永远执行不到。所谓"双保险"其实是一个坏掉的开关 ——
//     主程序那条路一旦失败，兜底根本没机会接。
//
// 而且即便前两个都修好，exec 过去也是死路：**服务端没有任何 `/redirect/…`
// 路由**（全项目 grep 不到），代理过去只会得到 404。
//
// 结论："跳到目标网址"这件事**不需要主程序** —— 一个 302 响应而已，
// 纯 shell 内建命令就能完成。少一层依赖就少一个故障点，这是纯粹的净收益。
const cgiScriptTemplate = `#!/bin/bash
# 由 QLink2Desktop 自动生成 —— 请勿手工修改，重新安装会覆盖。
#
# 这个脚本只做一件事：返回 302，把浏览器送到目标网址。
#
# 注意不要用 set -u 之外的"严格模式"去引用任何环境变量：CGI 环境下
# TRIM_* 系列**不一定存在**，未保护的展开会让脚本在第零行就死掉，
# 而没有任何输出 ⇔ 网关返回 500 ⇔ 用户看到一片错误页。
set -u

# 目标地址由 Go 侧按 shell 单引号规则拼好，这里不再自己加引号。
TARGET=%s

# 没有目标地址时给一张说明页，而不是让脚本因为没有输出变成 500。
# 「明确说清楚缺少什么」永远好过「用户对着错误页猜」。
if [ -z "${TARGET}" ]; then
  printf 'Status: 400 Bad Request\r\n'
  printf 'Content-Type: text/html; charset=utf-8\r\n'
  printf '\r\n'
  printf '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>未配置目标地址</title></head>'
  printf '<body style="font-family:system-ui,sans-serif;padding:24px;color:#475569">'
  printf '<p>这个桌面入口没有可跳转的目标地址，请在 QLink2Desktop 里重新编辑该链接。</p>'
  printf '</body></html>'
  exit 0
fi

printf 'Status: 302 Found\r\n'
printf 'Location: %%s\r\n' "${TARGET}"
printf 'Cache-Control: no-store\r\n'
printf 'Content-Type: text/html; charset=utf-8\r\n'
printf '\r\n'

# 响应体是兜底：绝大多数情况下浏览器拿到上面的 302 头就走了，根本不会渲染它。
# 留着是因为某些中间层会吃掉 Location 头 —— 那时这张页面还能把人送过去。
cat << 'QLINK_CGI_FALLBACK'
%s
QLINK_CGI_FALLBACK
exit 0
`

// buildCGIScript 组装 CGI 脚本。
//
// 模板里有两个占位符：302 目标（已按 shell 规则加引号）与兜底页面。
//
// 目标地址来自用户输入，**必须按 shell 的引号规则处理**，不能只做 HTML 转义 ——
// 含单引号或换行的地址会直接改掉脚本结构，等于给了用户一个在 NAS 上执行命令的入口。
//
// 兜底 HTML 是**格式化结果的一部分**（作为第二个参数的值插入），
// 所以即便目标网址里带 `%` 也不会被 fmt 再次当作占位符处理。
func buildCGIScript(target, fallbackHTML string) string {
	return fmt.Sprintf(cgiScriptTemplate, shellQuote(target), fallbackHTML)
}

// shellQuote 把字符串安全地放进 sh 的单引号里。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sanitizeTarget 去掉目标地址里的控制字符。
//
// 目标地址会被 CGI 原样写进 `Location:` 响应头。哪怕只有一个换行，也等于
// 给了响应拆分的口子（攻击者能在响应里插入任意头）。单引号保护不了换行 ——
// sh 的单引号可以跨行 —— 所以必须在拼进脚本之前就把控制字符清掉。
func sanitizeTarget(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// redirectPage 是跳转模式的兜底页面：立刻跳到目标地址。
//
// 用 meta refresh + JS 双保险：飞牛桌面弹窗里偶尔会拦截纯 JS 跳转。
// CGI 那边还会先发一个真正的 302 响应头，这张页面只是"头没被处理"时的兜底。
func redirectPage(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		// 正常流程不会走到这里（无端口形态要么是网址快捷方式、要么走端口模式）。
		// 真出现了也别说"正在跳转"——那会让用户一直等一个不存在的东西。
		return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>未配置目标地址</title></head>
<body style="font-family:system-ui,sans-serif;padding:24px;color:#475569">
<p>这个入口没有可跳转的目标地址，请在 QLink2Desktop 里重新编辑该链接。</p>
</body></html>`
	}
	escaped := html.EscapeString(target)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="0; url=%s">
<title>正在跳转…</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:#f8fafc;color:#475569}
  a{color:#2563eb}
</style>
</head>
<body>
<p>正在跳转至 <a href="%s">%s</a>…</p>
<script>window.location.replace(%q);</script>
</body>
</html>`, escaped, escaped, escaped, target)
}

// ---------------------------------------------------------------------------
// 外网优先公网反代
// ---------------------------------------------------------------------------

// wanCGIScriptTemplate 生成「外网走公网反代、内网直连本机」的 CGI 脚本。
//
// 飞牛入口配置只能声明一个 host（浏览器当前地址），没有「外网换域名」的字段，
// 所以分流只能发生在脚本里：按 HTTP_HOST 判断这次请求是内网还是外网。
//
// 判定用保守的白名单：私有 IP、localhost、无点主机名、*.local / *.lan、
// IPv6 字面量视为内网；其余一律视为外网。用带点的自定义局域网域名
// （例如 nas.home.example.com）会被当成外网 —— 这最多是多走一次反代，
// 不会把外网用户错误地留在中继上，方向是安全的。
const wanCGIScriptTemplate = `#!/bin/bash
# 由 QLink2Desktop 自动生成 —— 请勿手工修改，重新安装会覆盖。
#
# 外网优先走用户自己的公网反代，内网仍然直连本机端口。
# 判定依据是浏览器请求的 Host：
#   私有 IP / localhost / 无点主机名 / *.local / *.lan / IPv6 字面量 → 内网；
#   其余（飞牛中继域名、公网域名等）→ 302 到配置的公网反代地址。
set -u

PUBLIC_TARGET=%s
LOCAL_SCHEME=%s
LOCAL_PORT=%s
LOCAL_PATH=%s

host="${HTTP_HOST:-${SERVER_NAME:-}}"
# 有的网关会把 Host 改写成回环地址；这时原始域名在 X-Forwarded-Host 里。
# 只有 Host 缺失或确实是回环地址时才采信它，避免覆盖浏览器真实地址。
fwd="${HTTP_X_FORWARDED_HOST:-}"
case "$fwd" in
  *,*) fwd="${fwd%%,*}" ;;
esac
case "$host" in
  ""|localhost|127.*|\[::1\]) host="${fwd:-$host}" ;;
esac
# 去掉端口；IPv6 字面量形如 [fd00::1]:8000。
case "$host" in
  \[*\]:*) host="${host%%:*}" ;;
  \[*\]) ;;
  *:*) host="${host%%%%:*}" ;;
esac

is_lan=0
case "$host" in
  ""|localhost|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|\[*|*.local|*.lan)
    is_lan=1
    ;;
  *.*)
    is_lan=0
    ;;
  *)
    # 不带点的主机名（例如飞牛设备名）通常只在内网可达。
    is_lan=1
    ;;
esac

if [ "$is_lan" = "1" ] && [ -n "$host" ] && [ -n "$LOCAL_PORT" ]; then
  TARGET="${LOCAL_SCHEME}://${host}:${LOCAL_PORT}${LOCAL_PATH}"
else
  TARGET="${PUBLIC_TARGET}"
fi

printf 'Status: 302 Found\r\n'
printf 'Location: %%s\r\n' "${TARGET}"
printf 'Cache-Control: no-store\r\n'
printf 'Content-Type: text/html; charset=utf-8\r\n'
printf '\r\n'

# 兜底页面：中间层吃掉 Location 头时，用 JS 按同样的规则再跳一次。
cat << 'QLINK_CGI_FALLBACK'
%s
QLINK_CGI_FALLBACK
exit 0
`

// buildWANRedirectScript 组装「外网优先公网反代」的 CGI 脚本。
func buildWANRedirectScript(spec PackageSpec) string {
	publicTarget := sanitizeTarget(joinPublicTarget(spec.PublicURL, spec.Path))
	localScheme := spec.Scheme
	if localScheme == "" {
		localScheme = "http"
	}
	localPath := sanitizeTarget(strings.TrimSpace(spec.Path))
	if localPath == "" {
		localPath = "/"
	}
	localPort := ""
	if spec.LocalPort > 0 {
		localPort = strconv.Itoa(spec.LocalPort)
	}
	return fmt.Sprintf(wanCGIScriptTemplate,
		shellQuote(publicTarget),
		shellQuote(localScheme),
		shellQuote(localPort),
		shellQuote(localPath),
		wanRedirectPage(publicTarget, localScheme, spec.LocalPort, localPath),
	)
}

// joinPublicTarget 把反代地址与访问路径拼成完整目标。
// 反代地址允许带路径前缀（如 https://example.com/alist）。
func joinPublicTarget(base, path string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return base + "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// wanRedirectPage 是外网反代模式的兜底页面。
//
// 不能用静态的 meta refresh：目标取决于访问来源（内网 / 外网），
// 只能在浏览器里按 location.hostname 再判一次。
// 所有地址都经 json.Marshal 编码（它会转义 < > &），避免 </script> 之类的
// 内容提前闭合脚本。
func wanRedirectPage(publicTarget, localScheme string, localPort int, localPath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>正在跳转…</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:#f8fafc;color:#475569}
</style>
</head>
<body>
<p>正在跳转…</p>
<script>
(function () {
  var host = location.hostname || '';
  var pub = %s;
  var lan = host === 'localhost'
    || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)
    || host.indexOf('.') === -1;
  var target = pub;
  if (lan && host && %d > 0) { target = %s + '://' + host + ':' + %d + %s; }
  location.replace(target);
})();
</script>
</body>
</html>`, jsString(publicTarget), localPort, jsString(localScheme), localPort, jsString(localPath))
}

// jsString 把字符串编码成安全的 JS 字面量。
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
