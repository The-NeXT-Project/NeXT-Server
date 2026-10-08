// Package serverv1 implements NeXT-Panel Server API V1 (/api/server/v1).
package serverv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/The-NeXT-Project/NeXT-Server/adapter"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	boxOption "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const defaultTimeout = 30 * time.Second

// Error is an API error response: {"error": {"code", "message"}}.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return "HTTP " + http.StatusText(e.Status)
	}
	return e.Code + ": " + e.Message
}

// ErrNodeUnavailable is wrapped by FetchUsers when the panel refuses to serve
// users to this node at all, and the node must stop accepting them.
var ErrNodeUnavailable = errors.New("node unavailable")

var _ adapter.APIClient = (*Client)(nil)

type Client struct {
	httpClient *http.Client
	baseURL    string
	key        string
	localTLS   *boxOption.InboundTLSOptions

	// Fetches only happen on the pull goroutine, so the ETags need no lock.
	infoETag  string
	usersETag string
	rulesETag string
}

func NewClient(options option.ServerOptions) (*Client, error) {
	baseURL, err := url.Parse(options.URL)
	if err != nil {
		return nil, E.Cause(err, "parse url")
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, E.New("url must be http or https: ", options.URL)
	}
	if options.Key == "" {
		return nil, E.New("missing key")
	}
	timeout := time.Duration(options.Timeout)
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    strings.TrimSuffix(baseURL.String(), "/") + "/api/server/v1",
		key:        options.Key,
		localTLS:   options.TLS,
	}, nil
}

// get fetches path into data. It returns false when the panel answered 304
// for the ETag in *etag, and updates *etag after a fresh response.
func (c *Client) get(ctx context.Context, path string, etag *string, data any) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return false, err
	}
	if *etag != "" {
		request.Header.Set("If-None-Match", *etag)
	}
	response, err := c.do(request, data)
	if err != nil {
		return false, E.Cause(err, "GET ", path)
	}
	if response.StatusCode == http.StatusNotModified {
		return false, nil
	}
	*etag = response.Header.Get("ETag")
	return true, nil
}

func (c *Client) send(ctx context.Context, method string, path string, body any) error {
	content, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(content))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	_, err = c.do(request, nil)
	if err != nil {
		return E.Cause(err, method, " ", path)
	}
	return nil
}

func (c *Client) do(request *http.Request, data any) (*http.Response, error) {
	request.Header.Set("Authorization", "Bearer "+c.key)
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return response, nil
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		apiErr := &Error{Status: response.StatusCode}
		var errorResponse struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(content, &errorResponse) == nil {
			apiErr.Code = errorResponse.Error.Code
			apiErr.Message = errorResponse.Error.Message
		}
		return nil, apiErr
	}
	if data != nil {
		envelope := struct {
			Data any `json:"data"`
		}{data}
		err = json.Unmarshal(content, &envelope)
		if err != nil {
			return nil, E.Cause(err, "decode response")
		}
	}
	return response, nil
}

func (c *Client) Heartbeat(ctx context.Context, onlineUsers int) error {
	return c.send(ctx, http.MethodPut, "/heartbeat", map[string]any{"online_user": onlineUsers})
}

func (c *Client) ReportTraffic(ctx context.Context, items []adapter.UserTraffic) error {
	type entry struct {
		UserID int   `json:"user_id"`
		U      int64 `json:"u"`
		D      int64 `json:"d"`
	}
	entries := make([]entry, 0, len(items))
	for _, item := range items {
		entries = append(entries, entry{item.UserID, item.Upload, item.Download})
	}
	return c.send(ctx, http.MethodPost, "/users/traffic", map[string]any{"traffic": entries})
}

func (c *Client) ReportOnline(ctx context.Context, items []adapter.UserOnline) error {
	type entry struct {
		UserID int    `json:"user_id"`
		IP     string `json:"ip"`
	}
	entries := make([]entry, 0, len(items))
	for _, item := range items {
		entries = append(entries, entry{item.UserID, item.IP})
	}
	return c.send(ctx, http.MethodPost, "/users/online", map[string]any{"online": entries})
}

func (c *Client) ReportDetectLogs(ctx context.Context, items []adapter.DetectLog) error {
	type entry struct {
		UserID int `json:"user_id"`
		RuleID int `json:"rule_id"`
	}
	entries := make([]entry, 0, len(items))
	for _, item := range items {
		entries = append(entries, entry{item.UserID, item.RuleID})
	}
	return c.send(ctx, http.MethodPost, "/users/detect_logs", map[string]any{"logs": entries})
}
