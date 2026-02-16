package handle

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"log/slog"

	"github.com/xmdhs/clash2sfa/model"
	"github.com/xmdhs/clash2sfa/service"
	"github.com/xmdhs/clash2sfa/utils"

	cmodel "github.com/xmdhs/clash2singbox/model"
)

type Handle struct {
	convert  *service.Convert
	l        *slog.Logger
	configFs fs.FS
}

func NewHandle(convert *service.Convert, l *slog.Logger, configFs fs.FS) *Handle {
	return &Handle{
		convert:  convert,
		l:        l,
		configFs: configFs,
	}
}

func Frontend(frontendByte []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(frontendByte)
	}
}

func (h *Handle) Sub(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	config := r.FormValue("config")
	curl := r.FormValue("configurl")
	sub := r.FormValue("sub")
	include := r.FormValue("include")
	exclude := r.FormValue("exclude")
	addTag := r.FormValue("addTag")
	disableUrlTest := r.FormValue("disableUrlTest")
	outFields := r.FormValue("outFields")
	enableTun := r.FormValue("enableTun")
	proxyType := r.FormValue("proxyType")
	proxyPort := r.FormValue("proxyPort")
	proxyGroups := r.FormValue("proxyGroups")
	disableUrlTestb := false
	addTagb := false
	enableTunb := true

	if sub == "" {
		h.l.DebugContext(ctx, "sub 不得为空")
		http.Error(w, "sub 不得为空", 400)
		return
	}
	if addTag == "true" {
		addTagb = true
	}
	if disableUrlTest == "true" {
		disableUrlTestb = true
	}

	v := utils.GetSingBoxVersion(r)
	defaultConfig := utils.GetConfig(cmodel.SING112, h.configFs)

	a := model.ConvertArg{
		Sub:            sub,
		Include:        include,
		Exclude:        exclude,
		ConfigUrl:      curl,
		AddTag:         addTagb,
		DisableUrlTest: disableUrlTestb,
		OutFields:      false,
		EnableTun:      true,
		ProxyType:      "mixed",
		ProxyPort:      2333,
		Ver:            v,
	}

	if enableTun == "false" {
		enableTunb = false
	}
	a.EnableTun = enableTunb

	if proxyType == "mixed" || proxyType == "http" || proxyType == "socks5" {
		a.ProxyType = proxyType
	}
	if proxyPort != "" {
		var parsed int
		_, err := fmt.Sscanf(proxyPort, "%d", &parsed)
		if err != nil || parsed <= 0 || parsed > 65535 {
			h.l.WarnContext(ctx, "invalid proxyPort")
			http.Error(w, "proxyPort must be in range 1-65535", 400)
			return
		}
		a.ProxyPort = parsed
	}
	if proxyGroups != "" {
		b, err := zlibDecode(proxyGroups)
		if err != nil {
			h.l.WarnContext(ctx, err.Error())
			http.Error(w, err.Error(), 400)
			return
		}
		err = json.Unmarshal(b, &a.ProxyGroups)
		if err != nil {
			h.l.WarnContext(ctx, err.Error())
			http.Error(w, err.Error(), 400)
			return
		}
	}

	if outFields == "1" || outFields == "true" {
		a.OutFields = true
	}

	if a.ConfigUrl != "" && !strings.HasPrefix(a.ConfigUrl, "http") {
		b, err := func() ([]byte, error) {
			f, err := h.configFs.Open(a.ConfigUrl)
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			return b, nil
		}()
		if err != nil {
			h.l.WarnContext(ctx, err.Error())
			http.Error(w, err.Error(), 400)
			return
		}
		a.Config = b
		a.ConfigUrl = ""
	}

	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(2 * time.Minute))

	b, err := func() ([]byte, error) {
		if config != "" {
			b, err := zlibDecode(config)
			if err != nil {
				return nil, err
			}
			a.Config = b
		}
		return h.convert.MakeConfig(ctx, a, defaultConfig, r.UserAgent())
	}()
	if err != nil {
		h.l.WarnContext(ctx, err.Error())
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(b)

}

func zlibDecode(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	b, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return b, nil
}
