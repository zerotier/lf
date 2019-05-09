/*
 * LF: Global Fully Replicated Key/Value Store
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
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
