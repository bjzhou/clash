package mmdb

import (
	"sync"

	C "github.com/bjzhou/clash/constant"
	"github.com/bjzhou/clash/log"

	"github.com/oschwald/geoip2-golang"
)

var mmdb *geoip2.Reader
var once sync.Once

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})
}

func Instance() *geoip2.Reader {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})

	return mmdb
}
