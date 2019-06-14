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
	"encoding/json"
	"io/ioutil"
	"os"
	"os/user"
	"sort"
	"strings"
)

// Client config is mostly used by the code in cmd/lf but it's here so Node can
// manipulate it easily.

// ClientConfigName is the default name of the client config file
const ClientConfigName = "client.json"

// ClientConfigOwner is a locally configured owner with private key information.
type ClientConfigOwner struct {
	Public  OwnerPublic
	Private Blob
	Default bool
}

// GetOwner gets an Owner object (including private key) from this ClientConfigOwner
func (co *ClientConfigOwner) GetOwner() (o *Owner, err error) {
	o, err = NewOwnerFromPrivateBytes(co.Private)
	return
}

// ClientConfig is the JSON format for the client configuration file.
type ClientConfig struct {
	URLs    []RemoteNode                  ``         // Remote nodes
	Oracles []OwnerPublic                 ``         // Oracles to trust during queries
	Owners  map[string]*ClientConfigOwner ``         // Owners by name
	Dirty   bool                          `json:"-"` // Non-persisted flag that can be used to indicate the config should be saved on client exit
}

// Load loads this client config from disk or initializes it with defaults if load fails.
func (c *ClientConfig) Load(path string) error {
	d, err := ioutil.ReadFile(path)
	if err == nil && len(d) > 0 {
		err = json.Unmarshal(d, c)
	}
	if c.Owners == nil {
		c.Owners = make(map[string]*ClientConfigOwner)
	}
	c.Dirty = false

	// Make sure remote node URLs don't end with / (fix for older configs)
	for i := range c.URLs {
		u := string(c.URLs[i])
		if strings.HasSuffix(u, "/") && len(u) > 2 {
			u = u[0 : len(u)-1]
			c.URLs[i] = RemoteNode(u)
		}
	}

	// If the file didn't exist, init config with defaults.
	if err != nil && os.IsNotExist(err) {
		c.URLs = SolDefaultNodeURLs
		owner, _ := NewOwner(OwnerTypeNistP224)
		dflName := "default"
		u, _ := user.Current()
		if u != nil && len(u.Username) > 0 {
			dflName = strings.ReplaceAll(u.Username, " ", "") // use the current login user name if it can be determined
		}
		var priv []byte
		priv, err = owner.PrivateBytes()
		if err != nil {
			return err
		}
		c.Owners[dflName] = &ClientConfigOwner{
			Public:  owner.Public,
			Private: priv,
			Default: true,
		}
		c.Dirty = true
		err = nil
	}

	return err
}

// Save writes this client config to disk and reset the dirty flag.
func (c *ClientConfig) Save(path string) error {
	// Make sure there is one and only one default owner.
	if len(c.Owners) > 0 {
		haveDfl := false
		var names []string
		for n, o := range c.Owners {
			names = append(names, n)
			if haveDfl {
				if o.Default {
					o.Default = false
				}
			} else if o.Default {
				haveDfl = true
			}
		}
		if !haveDfl {
			sort.Strings(names)
			c.Owners[names[0]].Default = true
		}
	}

	err := ioutil.WriteFile(path, []byte(PrettyJSON(c)), 0600) // 0600 since this file contains secrets
	if err == nil {
		c.Dirty = false
		return nil
	}
	return err
}
