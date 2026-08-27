// Package plugins 集中导入所有 Go 插件子包，触发 init() 自动注册。
// 新增插件时只需在此文件添加一行 import。
package plugins

import (
	// 编译期注册各插件
	_ "github.com/gosleek/gosleek/plugins/cve_2022_22947"
	_ "github.com/gosleek/gosleek/plugins/cve_2022_22963"
	_ "github.com/gosleek/gosleek/plugins/jwt_secret_bruteforce"
	_ "github.com/gosleek/gosleek/plugins/api_endpoint_discovery"
)
