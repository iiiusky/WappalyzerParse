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
	"testing"
)

func TestWappalyzerParse_GetFingerPrintData(t *testing.T) {
	type fields struct {
		Filename   string
		IsDebug    bool
		FormatJson bool
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			"Test Open Debug Mode",
			fields{
				Filename:   "xxxx.json",
				IsDebug:    true,
				FormatJson: false,
			},
			-1,
		},
		{
			"Test Success",
			fields{
			},
			1,
		},
		{
			"Test Json",
			fields{
				FormatJson: true,
			},
			1,
		},
		{
			"Test External File",
			fields{
				Filename: "technologies.json",
			},
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &WappalyzerParse{
				Filename: tt.fields.Filename,
				IsDebug:  tt.fields.IsDebug,
			}
			w.InitFingerPrintData()

			if got := len(w.Fingerprints); got <= tt.want {
				t.Errorf("Fingerprints length = %v, want <=  %v", got, tt.want)
			}
		})
	}
}
