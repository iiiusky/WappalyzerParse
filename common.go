/*
Copyright © 2020 iiusky sky@03sec.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package WappalyzerParse

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// 指纹类别信息抽取
func categoriesExtractor(data interface{}) map[string]FingerprintCategories {
	var cats map[string]FingerprintCategories

	marshal, _ := json.Marshal(data)
	_ = json.Unmarshal(marshal, &cats)

	return cats
}

// 技术指纹信息抽取
func technologiesExtractor(data interface{}) map[string]interface{} {
	var fingerprints map[string]interface{}

	marshal, _ := json.Marshal(data)
	_ = json.Unmarshal(marshal, &fingerprints)

	return fingerprints
}

// 结果输出
func outputData(fingerprints map[string]interface{}, cats map[string]FingerprintCategories) []Fingerprint {
	var results []Fingerprint

	for name, valueInterface := range fingerprints {
		// 初始化默认值，不然json序列化出来的的空数据为null。
		_name := name
		_slug := slugify(name)
		_url := ""
		_description := ""
		_categories := make([]FingerprintCategories, 0)
		_headers := make(map[string]string)
		_dns := make(map[string][]string)
		_cookies := make(map[string]string)
		_dom := []DomInfo{}
		_html := []string{}
		_css := []string{}
		_certIssuer := ""
		_robots := ""
		_meta := make(map[string]string)
		_scripts := []string{}
		_js := make(map[string]string)
		_implies := []string{}
		_excludes := []string{}
		_icon := "default.svg"
		_website := ""
		_cpe := ""

		valueMap := valueInterface.(map[string]interface{})
		for mapKey, mapValueInterface := range valueMap {
			// 根据不同的key进行不同的处理
			switch mapKey {
			case "url":
				_url = mapValueInterface.(string)
				break
			case "description":
				_description = mapValueInterface.(string)
				break
			case "cats":
				for _, interfaceValue := range mapValueInterface.([]interface{}) {
					_categories = append(_categories, cats[strconv.Itoa(int(interfaceValue.(float64)))])
				}
				break
			case "headers":
				for interfaceKey, interfaceValue := range mapValueInterface.(map[string]interface{}) {
					_headers[interfaceKey] = interfaceValue.(string)
				}
				break
			case "dns":
				for interfaceKey, interfaceValue := range mapValueInterface.(map[string]interface{}) {
					if reflect.TypeOf(interfaceValue).Kind() == reflect.String {
						_dns[interfaceKey] = append(_dns[interfaceKey], interfaceValue.(string))
					} else {
						for _, _interfaceValue := range interfaceValue.([]interface{}) {
							_dns[interfaceKey] = append(_dns[interfaceKey], _interfaceValue.(string))
						}
					}
				}
				break
			case "cookies":
				for interfaceKey, interfaceValue := range mapValueInterface.(map[string]interface{}) {
					_cookies[interfaceKey] = interfaceValue.(string)
				}
				break
			case "dom":
				for key, domInfo := range mapValueInterface.(map[string]interface{}) {
					for attr, info := range domInfo.(map[string]interface{}) {
						for label, rule := range info.(map[string]interface{}) {
							_dom = append(_dom, DomInfo{
								Key:   key,
								Attr:  attr,
								Label: label,
								Rule:  rule.(string),
							})
						}
					}
				}
				break
			case "html":
				if reflect.TypeOf(mapValueInterface).Kind() == reflect.String {
					_html = append(_html, mapValueInterface.(string))
				} else {
					for _, interfaceValue := range mapValueInterface.([]interface{}) {
						_html = append(_html, interfaceValue.(string))
					}
				}
				break
			case "css":
				if reflect.TypeOf(mapValueInterface).Kind() == reflect.String {
					_css = append(_css, mapValueInterface.(string))
				} else {
					for _, interfaceValue := range mapValueInterface.([]interface{}) {
						_css = append(_css, interfaceValue.(string))
					}
				}
				break
			case "cert_issuer":
				_certIssuer = mapValueInterface.(string)
				break
			case "robots":
				// todo: 不知道robots的结构是什么样的,暂时空置.
				break
			case "meta":
				for interfaceKey, interfaceValue := range mapValueInterface.(map[string]interface{}) {
					_meta[interfaceKey] = interfaceValue.(string)
				}
				break
			case "scripts":
				if reflect.TypeOf(mapValueInterface).Kind() == reflect.String {
					_scripts = append(_scripts, mapValueInterface.(string))
				} else {
					for _, interfaceValue := range mapValueInterface.([]interface{}) {
						_scripts = append(_scripts, interfaceValue.(string))
					}
				}
				break
			case "js":
				for interfaceKey, interfaceValue := range mapValueInterface.(map[string]interface{}) {
					_js[interfaceKey] = interfaceValue.(string)
				}
				break
			case "implies":
				if reflect.TypeOf(mapValueInterface).Kind() == reflect.String {
					_implies = append(_implies, mapValueInterface.(string))
				} else {
					for _, interfaceValue := range mapValueInterface.([]interface{}) {
						_implies = append(_implies, interfaceValue.(string))
					}
				}
				break
			case "excludes":
				if reflect.TypeOf(mapValueInterface).Kind() == reflect.String {
					_excludes = append(_excludes, mapValueInterface.(string))
				} else {
					for _, interfaceValue := range mapValueInterface.([]interface{}) {
						_excludes = append(_excludes, interfaceValue.(string))
					}
				}
				break
			case "icon":
				_icon = mapValueInterface.(string)
				break
			case "website":
				_website = mapValueInterface.(string)
				break
			case "cpe":
				_cpe = mapValueInterface.(string)
				break
			}

		}

		// 将赋值后的key填充至fingerprint,并将其追加至results列表中
		results = append(results, Fingerprint{
			Name:        _name,
			Slug:        _slug,
			URL:         _url,
			Description: _description,
			Categories:  _categories,
			Headers:     _headers,
			DNS:         _dns,
			Cookies:     _cookies,
			Dom:         _dom,
			HTML:        _html,
			Css:         _css,
			CertIssuer:  _certIssuer,
			Robots:      _robots,
			Meta:        _meta,
			Scripts:     _scripts,
			Js:          _js,
			Implies:     _implies,
			Excludes:    _excludes,
			Icon:        _icon,
			Website:     _website,
			CPE:         _cpe,
		})
	}

	return results
}

func slugify(slug string) string {
	slug = strings.ToLower(slug)
	slug = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(slug, "-")
	slug = regexp.MustCompile(`--+`).ReplaceAllString(slug, "-")
	slug = regexp.MustCompile(`(?:^-|-$)`).ReplaceAllString(slug, "")

	return slug
}
