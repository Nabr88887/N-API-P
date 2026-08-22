package healthcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	defaultListenAddress = ":8080"
	readinessPath        = "/health/ready"
)

var errProbeFailed = errors.New("readiness probe failed")

func CheckFromEnvironment(timeout time.Duration) error {
	listenAddress := os.Getenv("N_API_P_LISTEN_ADDRESS")
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}
	return probe(listenAddress, timeout)
}

func probe(listenAddress string, timeout time.Duration) error {
	if timeout <= 0 {
		return errProbeFailed
	}
	_, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return errProbeFailed
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errProbeFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(portNumber))+readinessPath,
		nil,
	)
	if err != nil {
		return errProbeFailed
	}

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:              nil,
			DialContext:        dialer.DialContext,
			DisableKeepAlives:  true,
			DisableCompression: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errProbeFailed
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return errProbeFailed
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errProbeFailed
	}
	return nil
}
