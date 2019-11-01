/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

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
			_ = gz.Close()
			gzPool.Put(gz)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
