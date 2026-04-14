package service

import (
	"testing"

	"github.com/xmdhs/clash2sfa/model"
	"github.com/xmdhs/clash2sfa/utils"
)

func TestApplyProxyGroupsReuseTo(t *testing.T) {
	config := map[string]any{
		"outbounds": []any{},
		"route": map[string]any{
			"rule_set": []any{},
			"rules":    []any{},
		},
	}

	groups := []model.ProxyGroup{
		{
			Tag:     "gemini",
			Type:    "selector",
			Include: ".*",
			ReuseTo: []string{"select", "gemini-test"},
		},
		{
			Tag:     "gemini-test",
			Type:    "urltest",
			Include: ".*",
		},
	}

	got := applyProxyGroups(config, groups)
	outbounds := utils.AnyGet[[]any](got, "outbounds")
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	first := outbounds[0]
	firstTag := utils.AnyGet[string](first, "tag")
	if firstTag != "gemini" {
		t.Fatalf("expected first outbound tag=gemini, got %q", firstTag)
	}
	firstOutbounds := utils.AnyGet[[]any](first, "outbounds")
	if !containsString(firstOutbounds, "select") || !containsString(firstOutbounds, "gemini-test") {
		t.Fatalf("expected gemini outbounds to contain select and gemini-test, got %#v", firstOutbounds)
	}
}

func TestApplyProxyGroupsReuseToCyclePrevented(t *testing.T) {
	config := map[string]any{
		"outbounds": []any{},
		"route": map[string]any{
			"rule_set": []any{},
			"rules":    []any{},
		},
	}

	groups := []model.ProxyGroup{
		{
			Tag:     "gemini-test",
			Type:    "urltest",
			Include: ".*",
			ReuseTo: []string{"gemini"},
		},
		{
			Tag:     "gemini",
			Type:    "selector",
			Include: ".*",
			ReuseTo: []string{"gemini-test"},
		},
	}

	got := applyProxyGroups(config, groups)
	outbounds := utils.AnyGet[[]any](got, "outbounds")
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	geminiTestOut := utils.AnyGet[[]any](outbounds[0], "outbounds")
	geminiOut := utils.AnyGet[[]any](outbounds[1], "outbounds")

	if !containsString(geminiTestOut, "gemini") {
		t.Fatalf("expected gemini-test to contain gemini, got %#v", geminiTestOut)
	}
	if containsString(geminiOut, "gemini-test") {
		t.Fatalf("expected cycle edge gemini->gemini-test to be skipped, got %#v", geminiOut)
	}
}

func containsString(items []any, target string) bool {
	for _, item := range items {
		v, ok := item.(string)
		if ok && v == target {
			return true
		}
	}
	return false
}
