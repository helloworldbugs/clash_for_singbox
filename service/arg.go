package service

import (
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

func (c *Convert) MakeConfig(cxt context.Context, arg model.ConvertArg, configByte []byte) ([]byte, error) {
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
	m, err = applyGlobalNodeFilter(m, arg.Include, arg.Exclude)
	if err != nil {
		return nil, fmt.Errorf("MakeConfig: %w", err)
	}

	result, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("MakeConfig: %w", err)
	}

	return result, nil
}

func applyGlobalNodeFilter(config map[string]any, include, exclude string) (map[string]any, error) {
	include = strings.TrimSpace(include)
	exclude = strings.TrimSpace(exclude)
	if include == "" && exclude == "" {
		return config, nil
	}

	outbounds := utils.AnyGet[[]any](config, "outbounds")
	if len(outbounds) == 0 {
		return config, nil
	}

	candidateIndexes := make([]int, 0, len(outbounds))
	candidateTags := make([]string, 0, len(outbounds))
	for i, outbound := range outbounds {
		tag := utils.AnyGet[string](outbound, "tag")
		if tag == "" || tag == "direct" || tag == "block" || tag == "dns-out" {
			continue
		}
		candidateIndexes = append(candidateIndexes, i)
		candidateTags = append(candidateTags, tag)
	}

	filteredTags, err := filterTags(candidateTags, include, exclude)
	if err != nil {
		return nil, fmt.Errorf("applyGlobalNodeFilter: %w", err)
	}
	if len(filteredTags) == len(candidateTags) {
		return config, nil
	}

	keepNodeSet := make(map[string]struct{}, len(filteredTags))
	for _, tag := range filteredTags {
		keepNodeSet[tag] = struct{}{}
	}

	keepOutbound := make([]bool, len(outbounds))
	for i := range outbounds {
		keepOutbound[i] = true
	}
	for idx, tag := range candidateTags {
		if _, ok := keepNodeSet[tag]; !ok {
			keepOutbound[candidateIndexes[idx]] = false
		}
	}

	newOutbounds := make([]any, 0, len(outbounds))
	for i, outbound := range outbounds {
		if !keepOutbound[i] {
			continue
		}
		refs := utils.AnyGet[[]any](outbound, "outbounds")
		if len(refs) != 0 {
			filteredRefs := make([]any, 0, len(refs))
			for _, ref := range refs {
				refTag, ok := ref.(string)
				if !ok {
					filteredRefs = append(filteredRefs, ref)
					continue
				}
				if strings.HasPrefix(refTag, "include: ") || strings.HasPrefix(refTag, "exclude: ") {
					filteredRefs = append(filteredRefs, ref)
					continue
				}
				if _, ok := keepNodeSet[refTag]; ok {
					filteredRefs = append(filteredRefs, ref)
				}
			}
			utils.AnySet(&outbound, filteredRefs, "outbounds")
		}
		newOutbounds = append(newOutbounds, outbound)
	}

	utils.AnySet(&config, newOutbounds, "outbounds")
	return config, nil
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

	newInbounds := make([]any, 0, len(inbounds))
	proxySet := false
	for _, inbound := range inbounds {
		t := utils.AnyGet[string](inbound, "type")
		if t == "tun" {
			if enableTun {
				newInbounds = append(newInbounds, inbound)
			}
			continue
		}
		if t == "mixed" || t == "http" || t == "socks" {
			if proxySet {
				continue
			}
			utils.AnySet(&inbound, proxyType, "type")
			utils.AnySet(&inbound, "proxy-in", "tag")
			utils.AnySet(&inbound, proxyPort, "listen_port")
			newInbounds = append(newInbounds, inbound)
			proxySet = true
			continue
		}
		newInbounds = append(newInbounds, inbound)
	}

	if !proxySet {
		newInbounds = append(newInbounds, map[string]any{
			"type":        proxyType,
			"tag":         "proxy-in",
			"listen":      "127.0.0.1",
			"listen_port": proxyPort,
		})
	}

	utils.AnySet(&config, newInbounds, "inbounds")
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
