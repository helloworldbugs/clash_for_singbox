package model

import (
	"github.com/xmdhs/clash2singbox/model"
)

type ConvertArg struct {
	Sub            string
	Include        string
	Exclude        string
	ProxyGroups    []ProxyGroup
	Config         []byte
	ConfigUrl      string
	AddTag         bool
	DisableUrlTest bool
	OutFields      bool
	Ver            model.SingBoxVer
}

type ProxyGroup struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	Include string `json:"include"`
	Exclude string `json:"exclude"`
	SrsURL  string `json:"srsUrl"`
}
