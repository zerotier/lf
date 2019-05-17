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
	"net"
	"strconv"
	"strings"
)

// DNSLookupNodeP2P looks up node P2P IPs, ports, and identities (public keys) from TXT records.
// TXT records are formatted: IP/port/identity where identity is base62 encoded. P2P nodes may
// have A and AAAA records too, but the TXT records are the ones actually used by LF. Multiple
// TXT records may exist. All apparently valid records are returned.
func DNSLookupNodeP2P(hostname string) ([]APIPeer, error) {
	txt, err := net.LookupTXT(hostname)
	if err != nil {
		return nil, err
	}
	if len(txt) == 0 {
		return nil, nil
	}

	var p []APIPeer
	for _, trec := range txt {
		tfields := strings.Split(trec, "/")
		if len(tfields) >= 3 {
			ip := net.ParseIP(strings.TrimSpace(tfields[0]))
			if len(ip) == 4 || len(ip) == 16 {
				port, err := strconv.Atoi(strings.TrimSpace(tfields[1]))
				if err == nil && port > 0 && port <= 65535 {
					id := Base62Decode(strings.TrimSpace(tfields[2]))
					if len(id) > 0 {
						p = append(p, APIPeer{ip, port, id})
					}
				}
			}
		}
	}

	return p, nil
}
