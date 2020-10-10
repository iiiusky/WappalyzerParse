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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type WappalyzerParse struct {
	Filename     string        // 指纹库路径,如果不指定,则使用默认内置路径
	IsDebug      bool          // 开启后将直接打印出错误信息
	Fingerprints []Fingerprint // 指纹库结果
}

// 获取wappalyzer指纹库的结果,返回包装好的结构体类型
func (w *WappalyzerParse) InitFingerPrintData() {
	var dataJson map[string]interface{}
	var dataByte []byte
	var err error

	if w.Filename == "" {
		w.Filename = "technologies.json"
	}

	dataByte, err = ioutil.ReadFile(w.Filename)
	if err != nil {
		if w.IsDebug {
			fmt.Printf("open file err: %v \n", err)
		}
		return
	}

	err = json.Unmarshal(dataByte, &dataJson)
	if err != nil {
		if w.IsDebug {
			fmt.Printf("json unmarshal err: %v  \n", err)
		}
		return
	}

	categories := categoriesExtractor(dataJson["categories"])
	technologies := technologiesExtractor(dataJson["technologies"])

	w.Fingerprints = outputData(technologies, categories)
}

// 输出格式转为json,涉及到json序列化后html标签实体化问题,通过自定义json.encoder解决
func (w *WappalyzerParse) FormatJson() string {
	bf := bytes.NewBuffer([]byte{})

	jsonEncoder := json.NewEncoder(bf)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.SetIndent("", " ")
	_ = jsonEncoder.Encode(w.Fingerprints)

	return bf.String()
}
