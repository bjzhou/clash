package converter

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	r   *http.Response
	err error
}

func httpGet(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := make(chan Result)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		c <- Result{r: resp, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-c:
		if res.err != nil || res.r.StatusCode != http.StatusOK {
			return nil, err
		}
		defer res.r.Body.Close()
		s, err := ioutil.ReadAll(res.r.Body)
		return s, err
	}
}

func PreMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawURI := r.URL.RawQuery
		if len(rawURI) <= 9 {
			next.ServeHTTP(w, r)
			return
		}
		sublink := rawURI[9:]
		s, err := httpGet(sublink)

		if nil != err {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "sublink 不能访问")
			return
		}
		protoPrefix := "vmess://"
		switch r.URL.Path {
		case "/ssr2clashr":
			protoPrefix = "ssr://"
		}
		decodeBody, err := Base64DecodeStripped(string(s))
		if nil != err || !strings.HasPrefix(string(decodeBody), protoPrefix) {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, "sublink 返回数据格式不对")
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if strings.HasPrefix(rawURI, "sub_link") {
			requestURL := fmt.Sprintf("%s://%s%s?lan_link=%s", scheme, r.Host, r.URL.Path, sublink)
			r.Header.Add("request_url", requestURL)
		}
		r.Header.Add("decodebody", string(decodeBody))
		next.ServeHTTP(w, r)
	})
}
