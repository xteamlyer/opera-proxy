package seclient

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	"golang.org/x/net/publicsuffix"
)

type StdJar struct {
	jar *cookiejar.Jar
	mux sync.RWMutex
}

func NewStdJar() (*StdJar, error) {
	var jar StdJar

	err := jar.Reset()
	if err != nil {
		return nil, err
	}

	return &jar, nil
}

// SetCookies writes cookies into the jar.
// Must use Lock (not RLock): cookiejar.Jar.SetCookies mutates internal state
// and is not safe for concurrent use with any other Jar method.
func (j *StdJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mux.Lock()
	j.jar.SetCookies(u, cookies)
	j.mux.Unlock()
}

func (j *StdJar) Cookies(u *url.URL) []*http.Cookie {
	j.mux.RLock()
	c := j.jar.Cookies(u)
	j.mux.RUnlock()
	return c
}

func (j *StdJar) Reset() error {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return err
	}

	j.mux.Lock()
	j.jar = jar
	j.mux.Unlock()
	return nil
}
