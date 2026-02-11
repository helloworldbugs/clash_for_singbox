package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"log/slog"

	"github.com/samber/lo"
	"github.com/tidwall/jsonc"
	"github.com/xmdhs/clash2sfa/model"
	"github.com/xmdhs/clash2sfa/utils"
	"github.com/xmdhs/clash2singbox/httputils"
)

type Convert struct {
	c *http.Client
	l *slog.Logger
}

func NewConvert(c *http.Client, l *slog.Logger) *Convert {
	return &Convert{
		c: c,
		l: l,
	}
}

func (c *Convert) MakeConfig(cxt context.Context, arg model.ConvertArg, configByte []byte, userAgent string) ([]byte, error) {
	if arg.Config == nil && arg.ConfigUrl == "" {
		arg.Config = configByte
	}
	if arg.ConfigUrl != "" {
		b, err := httputils.HttpGet(cxt, c.c, arg.ConfigUrl, 1000*1000*10)
		if err != nil {
			return nil, fmt.Errorf("MakeConfig: %w", err)
		}
		arg.Config = b
	}
	// 支持 jsonc
	m, nodeTag, err := convert2sing(cxt, c.c, jsonc.ToJSON(arg.Config), arg.Sub, arg.Include, arg.Exclude, arg.AddTag, c.l, !arg.DisableUrlTest, arg.OutFields, arg.Ver)
	if err != nil {
		return nil, fmt.Errorf("MakeConfig: %w", err)
	}
	m = applyProxyGroups(m, arg.ProxyGroups)
	m = applyInboundSettings(m, arg.EnableTun, arg.ProxyType, arg.ProxyPort)
	m, err = configUrlTestParser(m, nodeTag)
	if err != nil {
		return nil, fmt.Errorf("MakeConfig: %w", err)
	}

	// 根据 User-Agent 决定是否格式化 JSON
	var result []byte
	if utils.IsBrowser(userAgent) {
		// 浏览器请求，返回格式化的 JSON
		bw := &bytes.Buffer{}
		jw := json.NewEncoder(bw)
		jw.SetIndent("", "    ")
		err = jw.Encode(m)
		if err != nil {
			return nil, fmt.Errorf("MakeConfig: %w", err)
		}
		result = bw.Bytes()
	} else {
		// 非浏览器请求，返回压缩的 JSON
		result, err = json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("MakeConfig: %w", err)
		}
	}

	return result, nil
}

func applyProxyGroups(config map[string]any, groups []model.ProxyGroup) map[string]any {
	if len(groups) == 0 {
		return config
	}
	outbounds := utils.AnyGet[[]any](config, "outbounds")
	route := utils.AnyGet[map[string]any](config, "route")
	ruleSet := utils.AnyGet[[]any](route, "rule_set")
	rules := utils.AnyGet[[]any](route, "rules")

	for _, group := range groups {
		tag := strings.TrimSpace(group.Tag)
		if tag == "" {
			continue
		}
		groupType := strings.TrimSpace(group.Type)
		if groupType == "" {
			groupType = "urltest"
		}

		include := strings.TrimSpace(group.Include)
		exclude := strings.TrimSpace(group.Exclude)
		if include == "" && exclude == "" {
			include = ".*"
		}

		newOutbound := map[string]any{
			"type":      groupType,
			"tag":       tag,
			"outbounds": []any{},
		}
		if groupType == "urltest" {
			newOutbound["url"] = "https://cp.cloudflare.com/generate_204"
			newOutbound["interval"] = "10m"
			newOutbound["tolerance"] = 50
		}

		outboundItems := make([]any, 0, 2)
		if include != "" {
			outboundItems = append(outboundItems, "include: "+include)
		}
		if exclude != "" {
			outboundItems = append(outboundItems, "exclude: "+exclude)
		}
		newOutbound["outbounds"] = outboundItems
		outbounds = append(outbounds, newOutbound)

		srsURL := strings.TrimSpace(group.SrsURL)
		if srsURL != "" {
			ruleSetTag := tag + "-rule-set"
			ruleSet = append(ruleSet, map[string]any{
				"tag":    ruleSetTag,
				"type":   "remote",
				"format": "binary",
				"url":    srsURL,
			})
			rules = append(rules, map[string]any{
				"rule_set": ruleSetTag,
				"outbound": tag,
			})
		}
	}

	utils.AnySet(&config, outbounds, "outbounds")
	utils.AnySet(&route, ruleSet, "rule_set")
	utils.AnySet(&route, rules, "rules")
	utils.AnySet(&config, route, "route")
	return config
}

func applyInboundSettings(config map[string]any, enableTun bool, proxyType string, proxyPort int) map[string]any {
	inbounds := utils.AnyGet[[]any](config, "inbounds")
	if len(inbounds) == 0 {
		return config
	}

	if proxyType == "" {
		proxyType = "mixed"
	}
	if proxyPort <= 0 {
		proxyPort = 7890
	}

	filtered := make([]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		t := utils.AnyGet[string](inbound, "type")
		if t == "tun" {
			if enableTun {
				filtered = append(filtered, inbound)
			}
			continue
		}
		if t == "mixed" || t == "http" || t == "socks" || t == "socks5" {
			continue
		}
		filtered = append(filtered, inbound)
	}

	newInbound := map[string]any{
		"type":        proxyType,
		"tag":         "proxy-in",
		"listen":      "127.0.0.1",
		"listen_port": proxyPort,
	}
	if proxyType == "socks5" {
		newInbound["type"] = "socks"
	}
	filtered = append(filtered, newInbound)
	utils.AnySet(&config, filtered, "inbounds")
	return config
}

var (
	ErrJson = errors.New("错误的 json")
)

func filterTags(tags []string, include, exclude string) ([]string, error) {
	nt, err := filter(include, tags, true)
	if err != nil {
		return nil, fmt.Errorf("filterTags: %w", err)
	}
	nt, err = filter(exclude, nt, false)
	if err != nil {
		return nil, fmt.Errorf("filterTags: %w", err)
	}
	return nt, nil
}

func filter(reg string, tags []string, need bool) ([]string, error) {
	if reg == "" {
		return tags, nil
	}
	r, err := regexp.Compile(reg)
	if err != nil {
		return nil, fmt.Errorf("filter: %w", err)
	}
	tag := lo.Filter(tags, func(item string, index int) bool {
		has := r.MatchString(item)
		return has == need
	})
	return tag, nil
}

func configUrlTestParser(config map[string]any, tags []TagWithVisible) (map[string]any, error) {
	outL, ok := config["outbounds"].([]any)
	if !ok {
		return nil, fmt.Errorf("configUrlTestParser: outbounds is not []any or missing")
	}

	newOut := make([]any, 0, len(outL))

	for _, value := range outL {
		outList := utils.AnyGet[[]any](value, "outbounds")

		if len(outList) == 0 {
			newOut = append(newOut, value)
			continue
		}

		tag := utils.AnyGet[string](value, "tag")

		outListS := lo.FilterMap(outList, func(item any, index int) (string, bool) {
			s, ok := item.(string)
			return s, ok
		})
		var tagStr []string

		if tag != "" && utils.AnyGet[string](value, "detour") != "" {
			tagStr = lo.FilterMap(tags, func(item TagWithVisible, index int) (string, bool) {
				return item.Tag, len(item.Visible) != 0 && slices.Contains(item.Visible, tag)
			})
			m, ok := value.(map[string]any)
			if ok && m != nil {
				delete(m, "detour")
			}
		} else {
			tagStr = lo.FilterMap(tags, func(item TagWithVisible, index int) (string, bool) {
				return item.Tag, len(item.Visible) == 0
			})
		}

		tl, err := urlTestParser(outListS, tagStr)
		if err != nil {
			return nil, fmt.Errorf("configUrlTestParser: %w", err)
		}
		if tl == nil {
			newOut = append(newOut, value)
			continue
		}
		utils.AnySet(&value, tl, "outbounds")
		newOut = append(newOut, value)
	}
	utils.AnySet(&config, newOut, "outbounds")
	return config, nil
}

func urlTestParser(outbounds, tags []string) ([]string, error) {
	var include, exclude string
	extTag := []string{}

	for _, s := range outbounds {
		if after, ok := strings.CutPrefix(s, "include: "); ok {
			include = after
		} else if after, ok := strings.CutPrefix(s, "exclude: "); ok {
			exclude = after
		} else {
			extTag = append(extTag, s)
		}
	}

	if include == "" && exclude == "" {
		return nil, nil
	}

	tags, err := filterTags(tags, include, exclude)
	if err != nil {
		return nil, fmt.Errorf("urlTestParser: %w", err)
	}

	return lo.Union(append(extTag, tags...)), nil
}
