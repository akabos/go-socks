// Copyright 2017 Mikhail Lukyanchenko. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/akabos/go-socks/socks"
)

func main() {
	proxy, err := socks.NewProxy("127.0.0.1:1080")
	if err != nil {
		log.Panic(err)
	}
	tr := &http.Transport{
		Dial: proxy.Dial,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://httpbin.org/get")
	if err != nil {
		log.Panic(err.Error())
	}
	fmt.Println("Status:", resp.StatusCode)
	io.Copy(os.Stdout, resp.Body)
}
