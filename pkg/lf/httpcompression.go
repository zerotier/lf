/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package lf

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

var gzPool = sync.Pool{
	New: func() interface{} {
		w, _ := gzip.NewWriterLevel(ioutil.Discard, gzip.BestCompression)
		return w
	},
}

type compressedResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *compressedResponseWriter) WriteHeader(status int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(status)
}

func (w *compressedResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func httpCompressionHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		if strings.Contains(ae, "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzPool.Get().(*gzip.Writer)
			gz.Reset(w)
			next.ServeHTTP(&compressedResponseWriter{ResponseWriter: w, Writer: gz}, r)
			gz.Close()
			gzPool.Put(gz)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
