package gateway

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

func hasJSONMediaType(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func hasUnsupportedChatContent(data []byte) bool {
	var request map[string]json.RawMessage
	if decodeJSON(data, &request, false) != nil || request == nil {
		return false
	}
	for _, field := range []string{"audio", "image", "images", "input_audio", "input_image", "file", "files"} {
		if _, ok := request[field]; ok {
			return true
		}
	}
	if modalities, ok := request["modalities"]; ok && hasNonTextModality(modalities) {
		return true
	}

	var messages []json.RawMessage
	if rawMessages, ok := request["messages"]; !ok || json.Unmarshal(rawMessages, &messages) != nil {
		return false
	}
	for _, rawMessage := range messages {
		var message map[string]json.RawMessage
		if json.Unmarshal(rawMessage, &message) != nil || message == nil {
			continue
		}
		for _, field := range []string{"audio", "image", "image_url", "input_audio", "file", "file_id", "attachments"} {
			if _, ok := message[field]; ok {
				return true
			}
		}
		if content, ok := message["content"]; ok {
			trimmed := bytes.TrimSpace(content)
			if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') {
				return true
			}
		}
	}
	return false
}

func hasNonTextModality(data []byte) bool {
	var modalities []string
	if json.Unmarshal(data, &modalities) != nil {
		return false
	}
	for _, modality := range modalities {
		if modality != "text" {
			return true
		}
	}
	return false
}
