package converter

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/bjzhou/clash/log"

	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
)

var (
	listenAddr string = "0.0.0.0"
	listenPort string = "5050"
	h          bool   = false
)

func DownLoadTemplate(url string, path string) {
	log.Infoln("Rule template URL: %s", url)
	log.Infoln("Start downloading the rules template")
	resp, err := http.Get(url)
	if nil != err {
		log.Errorln("Rule template download failed, please manually download save as [%s]\n", path)
	}
	defer resp.Body.Close()
	s, err := ioutil.ReadAll(resp.Body)
	if nil != err || resp.StatusCode != http.StatusOK {
		log.Errorln("Rule template download failed, please manually download save as [%s]\n", path)
	}
	ioutil.WriteFile(path, s, 0777)
	log.Infoln("Rules template download complete. [%s]\n", path)
}

func Main() {

	if h {
		flag.Usage()
		return
	}

	router := chi.NewRouter()
	cors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         300,
	})

	router.Use(cors.Handler)

	router.Use(PreMiddleware)

	router.Get("/v2ray2clash", V2ray2Clash)
	router.Get("/ssr2clashr", SSR2ClashR)

	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", listenAddr, listenPort),
		Handler: router,
	}

	go func() {
		// 服务连接
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorln("listen: %s\n", err)
		}
	}()
	log.Infoln("converter API listening at: 0.0.0.0:5050")
}
