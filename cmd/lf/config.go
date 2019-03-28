package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/user"
	"sort"
	"strings"

	"../../pkg/lf"
)

// ConfigOwner contains info about an owner.
type ConfigOwner struct {
	Owner        []byte
	OwnerPrivate []byte
	Default      bool
}

var defaultNodeUrls = []string{}

// Config is the format of the JSON client configuration stored on disk
type Config struct {
	NodeHTTPPort int                     //
	NodeP2PPort  int                     //
	Urls         []string                // URLs of full nodes and/or proxies
	Owners       map[string]*ConfigOwner // Owners by name

	dirty bool // internal flag that causes client config to get written
}

func (c *Config) load(path string) error {
	d, err := ioutil.ReadFile(path)
	if err == nil && len(d) > 0 {
		err = json.Unmarshal(d, c)
	}
	if c.Owners == nil {
		c.Owners = make(map[string]*ConfigOwner)
	}
	c.dirty = false

	// If the file didn't exist, init config with defaults.
	if err != nil && os.IsNotExist(err) {
		c.Urls = defaultNodeUrls
		owner, _ := lf.NewOwner(lf.OwnerTypeEd25519)
		dflName := "user"
		u, _ := user.Current()
		if u != nil && len(u.Username) > 0 {
			dflName = strings.ReplaceAll(u.Username, " ", "") // use the current login user name if it can be determined
		}
		c.Owners[dflName] = &ConfigOwner{
			Owner:        owner.Bytes(),
			OwnerPrivate: owner.PrivateBytes(),
			Default:      true,
		}
		c.dirty = true
		err = nil
	}

	return err
}

func (c *Config) save(path string) error {
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

	d, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, d, 0600) // 0600 since this file contains secrets
	if err == nil {
		c.dirty = false
		return nil
	}
	return err
}
