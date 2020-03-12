package converter

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type Vmess struct {
	Add  string      `json:"add"`
	Aid  interface{} `json:"aid"`
	Host string      `json:"host"`
	ID   string      `json:"id"`
	Net  string      `json:"net"`
	Path string      `json:"path"`
	Port interface{} `json:"port"`
	PS   string      `json:"ps"`
	TLS  string      `json:"tls"`
	Type string      `json:"type"`
	V    interface{} `json:"v"`
}

type ClashVmess struct {
	Name           string            `json:"name,omitempty"`
	Type           string            `json:"type,omitempty"`
	Server         string            `json:"server,omitempty"`
	Port           interface{}       `json:"port,omitempty"`
	UUID           string            `json:"uuid,omitempty"`
	AlterID        interface{}       `json:"alterId,omitempty"`
	Cipher         string            `json:"cipher,omitempty"`
	TLS            bool              `json:"tls,omitempty"`
	Network        string            `json:"network,omitempty"`
	WSPATH         string            `json:"ws-path,omitempty"`
	WSHeaders      map[string]string `json:"ws-headers,omitempty"`
	SkipCertVerify bool              `json:"skip-cert-verify,omitempty"`
}

type ClashRSSR struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	Server        string      `json:"server"`
	Port          interface{} `json:"port"`
	Password      string      `json:"password"`
	Cipher        string      `json:"cipher"`
	Protocol      string      `json:"protocol"`
	ProtocolParam string      `json:"protocolparam"`
	OBFS          string      `json:"obfs"`
	OBFSParam     string      `json:"obfsparam"`
}

type Clash struct {
	Port      int `yaml:"port"`
	SocksPort int `yaml:"socks-port"`
	// RedirPort          int                      `yaml:"redir-port"`
	// Authentication     []string                 `yaml:"authentication"`
	AllowLan           bool   `yaml:"allow-lan"`
	Mode               string `yaml:"mode"`
	LogLevel           string `yaml:"log-level"`
	ExternalController string `yaml:"external-controller"`
	// ExternalUI         string                   `yaml:"external-ui"`
	// Secret             string                   `yaml:"secret"`
	// Experimental       map[string]interface{} 	`yaml:"experimental"`
	Proxy             []map[string]interface{} `yaml:"Proxy"`
	ProxyGroup        []map[string]interface{} `yaml:"Proxy Group"`
	Rule              []string                 `yaml:"Rule"`
	CFWByPass         []string                 `yaml:"cfw-bypass"`
	CFWLatencyTimeout int                      `yaml:"cfw-latency-timeout"`
}

func (this *Clash) LoadTemplate(path string, protos []interface{}) []byte {
	_, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		log.Printf("[%s] template doesn't exist.", path)
		return nil
	}
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("[%s] template open the failure.", path)
		return nil
	}
	err = yaml.Unmarshal(buf, &this)
	if err != nil {
		log.Printf("[%s] Template format error.", path)
	}

	this.Proxy = nil

	var proxys []map[string]interface{}
	var proxies []string
	names := map[string]int{}

	for _, proto := range protos {
		o := reflect.ValueOf(proto)
		nameField := o.FieldByName("Name")
		proxy := make(map[string]interface{})
		j, _ := json.Marshal(proto)
		json.Unmarshal(j, &proxy)
		name := nameField.String()
		if index, ok := names[name]; ok {
			names[name] = index + 1
			name = fmt.Sprintf("%s(%d)", name, index+1)

		} else {
			names[name] = 0
		}
		proxy["name"] = name
		proxys = append(proxys, proxy)
		this.Proxy = append(this.Proxy, proxy)
		proxies = append(proxies, name)
	}

	this.Proxy = proxys

	for _, group := range this.ProxyGroup {
		groupProxies := group["proxies"].([]interface{})
		for i, proxie := range groupProxies {
			if "1" == proxie {
				groupProxies = groupProxies[:i]
				var tmpGroupProxies []string
				for _, s := range groupProxies {
					tmpGroupProxies = append(tmpGroupProxies, s.(string))
				}
				tmpGroupProxies = append(tmpGroupProxies, proxies...)
				group["proxies"] = tmpGroupProxies
				break
			}
		}

	}

	d, err := yaml.Marshal(this)
	if err != nil {
		return nil
	}

	return d
}

func V2ray2Clash(w http.ResponseWriter, r *http.Request) {

	decodeBody := r.Header.Get("decodebody")

	scanner := bufio.NewScanner(strings.NewReader(decodeBody))
	var vmesss []interface{}
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "vmess://") {
			continue
		}
		s := scanner.Text()[8:]
		s = strings.TrimSpace(s)
		vmconfig, err := Base64DecodeStripped(s)
		if err != nil {
			continue
		}
		vmess := Vmess{}
		err = json.Unmarshal(vmconfig, &vmess)
		if err != nil {
			log.Println(err)
			continue
		}
		clashVmess := ClashVmess{}
		clashVmess.Name = vmess.PS
		clashVmess.Type = "vmess"
		clashVmess.Server = vmess.Add
		switch vmess.Port.(type) {
		case string:
			clashVmess.Port, _ = vmess.Port.(string)
		case int:
			clashVmess.Port, _ = vmess.Port.(int)
		case float64:
			clashVmess.Port, _ = vmess.Port.(float64)
		default:
			continue
		}
		clashVmess.UUID = vmess.ID
		clashVmess.AlterID = vmess.Aid
		clashVmess.Cipher = vmess.Type
		if "" != vmess.TLS {
			clashVmess.TLS = true
		} else {
			clashVmess.TLS = false
		}
		if "ws" == vmess.Net {
			clashVmess.Network = vmess.Net
			clashVmess.WSPATH = vmess.Path
		}

		vmesss = append(vmesss, clashVmess)
	}
	clash := Clash{}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "未知错误")
		return
	}
	temp := clash.LoadTemplate(homeDir + "/.config/clash/config.yaml", vmesss)
	if temp == nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "sublink 返回数据格式不对")
		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, UnicodeEmojiDecode(string(temp)))
}

const (
	SSRServer = iota
	SSRPort
	SSRProtocol
	SSRCipher
	SSROBFS
	SSRSuffix
)

func SSR2ClashR(w http.ResponseWriter, r *http.Request) {
	decodeBody := r.Header.Get("decodebody")

	scanner := bufio.NewScanner(strings.NewReader(decodeBody))
	var ssrs []interface{}
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), "ssr://") {
			continue
		}
		s := scanner.Text()[6:]
		s = strings.TrimSpace(s)
		rawSSRConfig, err := Base64DecodeStripped(s)
		if err != nil {
			continue
		}
		params := strings.Split(string(rawSSRConfig), `:`)
		if 6 != len(params) {
			continue
		}
		ssr := ClashRSSR{}
		ssr.Type = "ssr"
		ssr.Server = params[SSRServer]
		ssr.Port = params[SSRPort]
		ssr.Protocol = params[SSRProtocol]
		ssr.Cipher = params[SSRCipher]
		ssr.OBFS = params[SSROBFS]

		// 如果兼容ss协议，就转换为clash的ss配置
		// https://github.com/bjzhou/clash
		if "origin" == ssr.Protocol && "plain" == ssr.OBFS {
			switch ssr.Cipher {
			case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
				"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
				"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
				"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
				"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
				ssr.Type = "ss"
			}
		}

		suffix := strings.Split(params[SSRSuffix], "/?")
		if 2 != len(suffix) {
			continue
		}
		passwordBase64 := suffix[0]
		password, err := Base64DecodeStripped(passwordBase64)
		if err != nil {
			continue
		}
		ssr.Password = string(password)

		m, err := url.ParseQuery(suffix[1])
		if err != nil {
			continue
		}

		for k, v := range m {
			de, err := Base64DecodeStripped(v[0])
			if err != nil {
				continue
			}
			switch k {
			case "obfsparam":
				ssr.OBFSParam = string(de)
				continue
			case "protoparam":
				ssr.ProtocolParam = string(de)
				continue
			case "remarks":
				ssr.Name = string(de)
				continue
			case "group":
				continue
			}
		}

		ssrs = append(ssrs, ssr)
	}
	clash := Clash{}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "未知错误")
		return
	}
	temp := clash.LoadTemplate(homeDir + "/.config/clash/config.yaml", ssrs)
	if temp == nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "sublink 返回数据格式不对")
		return
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, UnicodeEmojiDecode(string(temp)))
}

func UnicodeEmojiDecode(s string) string {
	//emoji表情的数据表达式
	re := regexp.MustCompile("(?i)\\\\u[0-9a-zA-Z]+")
	//提取emoji数据表达式
	reg := regexp.MustCompile("(?i)\\\\u")
	src := re.FindAllString(s, -1)
	for i := 0; i < len(src); i++ {
		e := reg.ReplaceAllString(src[i], "")
		p, err := strconv.ParseInt(e, 16, 32)
		if err == nil {
			s = strings.Replace(s, src[i], string(rune(p)), -1)
		}
	}
	return s
}

func Base64DecodeStripped(s string) ([]byte, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	s = strings.ReplaceAll(s, " ", "+")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(s)
	}
	return decoded, err
}
