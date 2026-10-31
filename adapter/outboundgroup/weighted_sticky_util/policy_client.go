package weightedsticky

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrControlUnauthorized means the control server rejected the credential
	// (401). It is a configuration error, not an account state.
	ErrControlUnauthorized = errors.New("weighted-sticky: control credential rejected")

	// ErrControlNodeNotFound means the node does not exist or is not owned by
	// this account (404). Also a configuration/authorization error.
	ErrControlNodeNotFound = errors.New("weighted-sticky: control node not found")

	// ErrControlUnexpected covers every other response: redirects, 429, 5xx,
	// malformed responses and transport failures. It must never change the
	// cached account state.
	ErrControlUnexpected = errors.New("weighted-sticky: control query failed")
)

// ControlClient queries the management simulator directly. It never uses the
// managed proxy group, an environment proxy or a redirect. The UUID is only
// placed in the Authorization header and is never included in errors or logs.
type ControlClient struct {
	baseURL string
	uuid    string
	timeout time.Duration
	client  *http.Client
}

type ControlClientOptions struct {
	BaseURL string
	UUID    string
	Timeout time.Duration
}

func NewControlClient(options ControlClientOptions) (*ControlClient, error) {
	// Reuse the parser's validation so the two entry points cannot drift.
	if _, err := validateControlBaseURL(options.BaseURL); err != nil {
		return nil, fmt.Errorf("weighted-sticky control base-url: %w", err)
	}
	if strings.TrimSpace(options.UUID) == "" || strings.ContainsAny(options.UUID, " \t\r\n") {
		return nil, errors.New("weighted-sticky control uuid is empty or malformed")
	}
	if options.Timeout <= 0 {
		return nil, errors.New("weighted-sticky control timeout must be positive")
	}

	transport := &http.Transport{
		// No Proxy: the status query must be a direct connection to the
		// management address, never through an egress under management.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   options.Timeout,
		ResponseHeaderTimeout: options.Timeout,
	}
	return &ControlClient{
		baseURL: strings.TrimSuffix(options.BaseURL, "/"),
		uuid:    options.UUID,
		timeout: options.Timeout,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Return the redirect response instead of following it. A 3xx
				// is then an unexpected response, never a state.
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Check queries GET {base}/v1/nodes/{node}/status. Only 200/409/403 carry an
// account state. Every other outcome is an error and the caller keeps the
// previously known state.
func (c *ControlClient) Check(ctx context.Context, nodeID string) (AccountStatus, error) {
	if nodeID == "" || strings.ContainsAny(nodeID, "/ \t\r\n") {
		return AccountStatusUnknown, fmt.Errorf("%w: invalid node id", ErrControlUnexpected)
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	endpoint := c.baseURL + "/v1/nodes/" + url.PathEscape(nodeID) + "/status"
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return AccountStatusUnknown, fmt.Errorf("%w: %v", ErrControlUnexpected, err)
	}
	request.Header.Set("Authorization", "Bearer "+c.uuid)
	request.Header.Set("Accept", "*/*")

	response, err := c.client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return AccountStatusUnknown, ctx.Err()
		}
		return AccountStatusUnknown, fmt.Errorf("%w: %v", ErrControlUnexpected, err)
	}
	defer response.Body.Close()

	// The status response body is documented as empty. The status code is the
	// whole protocol, so it is handled before touching the body; an unusual
	// server cannot hold this query until the read timeout by keeping the body
	// open. A body read failure is never interpreted as an account state.
	switch response.StatusCode {
	case http.StatusOK:
		return AccountStatusNormal, nil
	case http.StatusConflict:
		return AccountStatusGrace, nil
	case http.StatusForbidden:
		return AccountStatusDisabled, nil
	case http.StatusUnauthorized:
		return AccountStatusUnknown, ErrControlUnauthorized
	case http.StatusNotFound:
		return AccountStatusUnknown, ErrControlNodeNotFound
	default:
		return AccountStatusUnknown, fmt.Errorf("%w: HTTP %d", ErrControlUnexpected, response.StatusCode)
	}
}

// CloseIdleConnections releases keep-alive connections when a strategy is
// closed or reloaded. In-flight requests are cancelled through their context.
func (c *ControlClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}
