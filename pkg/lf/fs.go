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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc64"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	fuse "bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"golang.org/x/net/context"
)

var crc64ECMATable = crc64.MakeTable(crc64.ECMA)
var fsUsernamePrefixes = [14]string{"lf0000000000000", "lf000000000000", "lf00000000000", "lf0000000000", "lf000000000", "lf00000000", "lf0000000", "lf000000", "lf00000", "lf0000", "lf000", "lf00", "lf0", "lf"}
var one = 1
var eight = 8

// PassphraseToOwnerAndMaskingKey generates both an owner and a masking key from a secret string.
func PassphraseToOwnerAndMaskingKey(passphrase string) (*Owner, []byte) {
	pp := []byte(passphrase)
	mkh := sha256.Sum256(pp)
	mkh = sha256.Sum256(mkh[:]) // double hash to ensure difference from seededprng
	owner, err := NewOwnerFromSeed(OwnerTypeNistP384, pp)
	if err != nil {
		panic(err)
	}
	return owner, mkh[:]
}

// fsLfOwnerToUser generates a Unix username and UID from a hash of an owner's public key.
// A cryptographic hash is used instead of CRC64 just to make it a little bit harder to
// intentionally collide these, but uniqueness of these should not be depended upon!
func fsLfOwnerToUser(o []byte) (string, uint32) {
	h := sha256.Sum256(o)
	c64 := binary.BigEndian.Uint64(h[0:8])
	es := strconv.FormatUint(c64, 36)
	uid := uint32(c64 & 0x7fffffff)
	if uid < 65536 {
		uid += 65536
	}
	return (fsUsernamePrefixes[len(es)] + es), uid
}

func fsIsValidExternalFilename(name string) bool {
	if len(name) > 0 {
		if name == "." || name == ".." || name == ".passwd" || strings.ContainsAny(name, "/\\") {
			return false
		}
		return true
	}
	return false
}

type fsFuseNode interface {
	fusefs.Node
	fusefs.Handle
	commit() error
	header() *fsFileHeader
	writable() bool
}

type fsCacheEntry struct {
	parent *fsDir
	fsn    fsFuseNode
	ts     uint64
}

type fsPasswdEntry struct {
	public string // @base62
	uid    uint32 // computed UID
}

// FS allows the LF to be mounted as a FUSE filesystem.
type FS struct {
	ds               []LF
	normalLog        *log.Logger
	warningLog       *log.Logger
	gp               *GenesisParameters
	mountPoint       string
	maxFileSize      int
	rootSelectorName []byte
	root             fsDir
	owner            *Owner
	ownerUID         uint32
	maskingKey       []byte
	passwd           map[string]fsPasswdEntry
	passwdLock       sync.Mutex
	dirty            map[uint64]fsFuseNode
	dirtyLock        sync.Mutex
	cache            map[uint64]fsCacheEntry
	cacheLock        sync.Mutex
	fconn            *fuse.Conn
	fconnLock        sync.Mutex
	commitQueue      chan fsFuseNode
	runningLock      sync.Mutex
	workFunc         *Wharrgarblr
	workFuncLock     sync.Mutex
}

// fsImpl just hides FUSE methods from everyone outside the LF package.
type fsImpl struct{ FS }

func (impl *fsImpl) Root() (fusefs.Node, error) { return &impl.root, nil }

func (impl *fsImpl) GenerateInode(parentInode uint64, name string) uint64 {
	i := parentInode + crc64.Checksum([]byte(name), crc64ECMATable)
	if i < 1024 { // inodes under 1024 are reserved for special pseudo-files
		i += 1024
	}
	return i
}

func (impl *fsImpl) getWorkFunction() *Wharrgarblr {
	impl.workFuncLock.Lock()

	if impl.workFunc == nil {
		// If we are running locally within a Node share its MakeRecord work function instance.
		for _, dsi := range impl.ds {
			n, _ := dsi.(*Node)
			if n != nil {
				impl.workFunc = n.getMakeRecordWorkFunction()
				break
			}
		}

		// Otherwise make one to save here
		if impl.workFunc == nil {
			impl.workFunc = NewWharrgarblr(RecordDefaultWharrgarblMemory, runtime.NumCPU())
		}
	}

	wf := impl.workFunc
	impl.workFuncLock.Unlock()

	return wf
}

func (impl *fsImpl) Statfs(ctx context.Context, req *fuse.StatfsRequest, resp *fuse.StatfsResponse) error {
	resp.Blocks = 2147483647
	resp.Bfree = 2147483647
	resp.Bavail = 2147483647
	resp.Files = 2147483647
	resp.Ffree = 2147483647
	resp.Bsize = 4096
	resp.Namelen = fsMaxNameLength
	resp.Frsize = 1
	return nil
}

//////////////////////////////////////////////////////////////////////////////

const (
	fsFileTypeNormal  = 0x000 // normal data file
	fsFileTypeDir     = 0x200 // name of a subdirectory, no data
	fsFileTypeLink    = 0x400 // symbolic link
	fsFileTypeDeleted = 0x600 // dead entry (LF itself has no suitable delete semantic, so just mark it as such)
	fsFileTypeMask    = 0x600 // bit mask for file type from mode

	fsMaxNameLength      = 511     // max length of the name field in fsFileHeader (9-bit size, must be a bit mask)
	fsMaxFileSize        = 4194304 // sanity limit for global max file size (can be increased... but 4mb is already crazy)
	fsMinRecordValueSize = 1024    // minimum record value size in LF data store to use lffs
)

type fsFileHeader struct {
	mode          uint   // 2-bit type and 9-bit Unix rwxrwxrwx mode (11 bits total)
	oversizeDepth uint   // depth of oversize file decomposition recursion
	name          []byte // full name of file
}

func (h *fsFileHeader) appendTo(b []byte) []byte {
	var qw [10]byte
	b = append(b, qw[0:binary.PutUvarint(qw[:], uint64(h.mode&0x7ff)|(uint64(len(h.name)&fsMaxNameLength)<<11)|uint64(h.oversizeDepth<<20))]...)
	b = append(b, h.name...)
	return b
}

func (h *fsFileHeader) readFrom(b []byte) ([]byte, error) {
	i, n := binary.Uvarint(b) // read header varint that contains mode, name length, has-next-block flag, and optional large file size
	if n <= 0 {
		return nil, ErrInvalidObject
	}
	b = b[n:]
	h.mode = uint(i & 0x7ff)
	h.oversizeDepth = uint(i >> 20)
	h.name = make([]byte, uint((i>>11)&fsMaxNameLength))
	if len(b) < len(h.name) {
		return nil, ErrInvalidObject
	}
	copy(h.name, b[0:len(h.name)])
	b = b[len(h.name):]
	return b, nil
}

//////////////////////////////////////////////////////////////////////////////

// NewFS creates and mounts a new virtual filesystem.
func NewFS(ds []LF, normalLog *log.Logger, warningLog *log.Logger, mountPoint string, rootSelectorName []byte, owner *Owner, maxFileSize int, maskingKey []byte) (*FS, error) {
	if len(ds) == 0 {
		return nil, errors.New("at least one data source must be supplied (Node, RemoteNode, etc.)")
	}

	var gp *GenesisParameters
	for _, ds2 := range ds {
		gp, _ = ds2.GenesisParameters()
		if gp != nil {
			break
		}
	}
	if gp == nil {
		return nil, errors.New("unable to retrieve genesis parameters from any data source")
	}
	if gp.RecordMaxValueSize < fsMinRecordValueSize {
		return nil, fmt.Errorf("network must permit record values of at least %d bytes", fsMinRecordValueSize)
	}

	os.MkdirAll(mountPoint, 0755)
	mpInfo, err := os.Stat(mountPoint)
	if err != nil || !mpInfo.IsDir() {
		return nil, errors.New("mount point is not a directory (mkdir attempt failed)")
	}

	if maxFileSize <= 0 {
		maxFileSize = fsMaxFileSize
	}
	if maxFileSize > fsMaxFileSize {
		return nil, fmt.Errorf("max file size cannot be larger than %d", fsMaxFileSize)
	}
	ownerName, ownerUID := fsLfOwnerToUser(owner.Public)
	dsCopy := make([]LF, len(ds))
	copy(dsCopy, ds)
	fs := &fsImpl{FS: FS{
		ds:               dsCopy,
		normalLog:        normalLog,
		warningLog:       warningLog,
		gp:               gp,
		mountPoint:       mountPoint,
		maxFileSize:      maxFileSize,
		rootSelectorName: rootSelectorName,
		root: fsDir{
			fsFileHeader: fsFileHeader{
				mode: 0777 | fsFileTypeDir,
				name: nil,
			},
			inode:        1,
			ts:           time.Now(),
			uid:          uint32(os.Getuid()),
			gid:          uint32(os.Getgid()),
			selectorName: rootSelectorName,
			keyRange:     [2]Blob{MakeSelectorKey(rootSelectorName, 0), MakeSelectorKey(rootSelectorName, OrdinalMaxValue)},
			owner:        owner,
		},
		owner:       owner,
		ownerUID:    ownerUID,
		maskingKey:  maskingKey,
		passwd:      make(map[string]fsPasswdEntry),
		dirty:       make(map[uint64]fsFuseNode),
		cache:       make(map[uint64]fsCacheEntry),
		commitQueue: make(chan fsFuseNode),
	}}
	fs.root.fs = fs
	fs.passwd[ownerName] = fsPasswdEntry{uid: ownerUID, public: owner.Public.String()}

	// Include only ASCII printable characters in volume name so as not to cause UI issues (Mac Finder only AFIAK).
	nameEscaped := make([]byte, 0, len(rootSelectorName))
	for _, c := range rootSelectorName {
		if (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == '-' || c == '.' || c == ',' || c == '!' {
			nameEscaped = append(nameEscaped, c)
		} else {
			nameEscaped = append(nameEscaped, '_')
		}
	}

	//fuse.Debug = func(msg interface{}) { fmt.Printf("%v\n", msg) }

	normalLog.Printf("lffs: mounting %s at %s with records owned by %s", rootSelectorName, mountPoint, owner.String())
	fuse.Unmount(mountPoint)
	time.Sleep(time.Millisecond * 100)
	fuse.Unmount(mountPoint)
	time.Sleep(time.Millisecond * 100) // HACK for already mounted to dead daemon case
	fs.fconn, err = fuse.Mount(
		mountPoint,
		fuse.DaemonTimeout("120"),
		fuse.FSName("lffs"),
		fuse.Subtype("lffs"),
		fuse.VolumeName("lf-"+string(nameEscaped)),
		fuse.LocalVolume(),
		fuse.NoAppleXattr(),
		fuse.NoAppleDouble(),
		fuse.AllowNonEmptyMount(),
		fuse.AllowOther(),
	)
	if err != nil {
		warningLog.Printf("lffs: FUSE mount failed: %s", err.Error())
		return nil, err
	}

	go func() {
		defer func() {
			e := recover()
			if e != nil {
				warningLog.Printf("WARNING: unexpected panic in fs layer: %v", e)
			}
		}()

		<-fs.fconn.Ready

		if fs.fconn.MountError != nil {
			fs.fconnLock.Lock()
			isClosed := fs.fconn == nil
			fs.fconnLock.Unlock()
			if !isClosed {
				warningLog.Printf("WARNING: lffs: FUSE subsystem failed to enter server mode: %s", fs.fconn.MountError.Error())
			}
		} else {
			normalLog.Printf("lffs: serving at %s", mountPoint)
			err := fusefs.Serve(fs.fconn, fs)
			fs.fconnLock.Lock()
			isClosed := fs.fconn == nil
			fs.fconnLock.Unlock()
			if err != nil && !isClosed {
				warningLog.Printf("WARNING: lffs: FUSE subsystem failed to enter server mode: %s", err.Error())
			} else {
				normalLog.Printf("lffs: unmounted from %s", mountPoint)
			}
			fuse.Unmount(mountPoint)
		}

		fs.fconnLock.Lock()
		if fs.fconn != nil {
			fs.fconn.Close()
			fs.fconn = nil
		}
		fs.fconnLock.Unlock()
	}()

	go func() {
		var fswg sync.WaitGroup
		var lastCheckedCache uint64
		inflightLimit := runtime.NumCPU() * 16
		for {
			for inflight := 0; inflight < inflightLimit; inflight++ { // limit in-flight commits to something sane for this machine
				fsn := <-fs.commitQueue
				if fsn == nil {
					fswg.Wait()
					fs.runningLock.Unlock()
					return
				}

				fswg.Add(1)
				go func() {
					defer func() {
						e := recover()
						if e != nil {
							fs.warningLog.Printf("WARNING: lffs: panic during FS commit operation: %v", e)
						}
						fswg.Done()
					}()
					fsn.commit()
				}()
			}

			now := TimeSec()
			if (now - lastCheckedCache) >= 60 {
				lastCheckedCache = now
				fs.cacheLock.Lock()
				for ci, ce := range fs.cache {
					if (now - ce.ts) >= 600 {
						delete(fs.cache, ci)
					}
				}
				fs.cacheLock.Unlock()
			}

			fswg.Wait()
		}
	}()

	fs.runningLock.Lock()

	return &fs.FS, nil
}

// IsOpen returns true if this FS instance is open and serving, false after Close() or if an internal error occurs.
func (fs *FS) IsOpen() bool {
	fs.fconnLock.Lock()
	o := fs.fconn != nil
	fs.fconnLock.Unlock()
	return o
}

// Close unmounts this filesystem.
// If this FS has outstanding commits that need proof of work this may block
// for a period of time.
func (fs *FS) Close() error {
	fs.commitQueue <- nil
	fs.runningLock.Lock()
	fs.runningLock.Unlock()

	fs.fconnLock.Lock()
	fconn := fs.fconn
	fs.fconn = nil
	fs.fconnLock.Unlock()

	if fconn != nil {
		// HACK: Linux likes to hang on Close() until something touches the filesystem, so
		// frob the filesystem until it actually closes.
		var closed uint32
		go func() {
			fconn.Close()
			atomic.StoreUint32(&closed, 1)
		}()
		for atomic.LoadUint32(&closed) == 0 {
			runtime.Gosched()
			ioutil.ReadFile(path.Join(fs.mountPoint, ".passwd"))
			time.Sleep(time.Millisecond * 50)
		}

		// HACK: Linux also likes to not unmount the fuse mount on daemon exit... :P
		for _, cmd := range []string{"/bin/umount", "/sbin/umount", "/usr/sbin/umount", "/usr/bin/umount"} {
			if _, err := os.Stat(cmd); err == nil {
				if p, _ := os.StartProcess(cmd, []string{"-f", fs.mountPoint}, nil); p != nil {
					p.Wait()
				}
				break
			}
		}
	}

	return nil
}

// WaitForClose blocks until this FS instance is closed.
func (fs *FS) WaitForClose() {
	fs.runningLock.Lock()
	fs.runningLock.Unlock()
}

//////////////////////////////////////////////////////////////////////////////

// fsDir implements Node and Handle for directories
type fsDir struct {
	fsFileHeader
	inode        uint64    // inode a.k.a. LF ordinal, parent inode + CRC64-ECMA(name)
	ts           time.Time // node timestamp
	uid, gid     uint32    // Unix UID and GID
	selectorName []byte    // name of selector for this directory
	keyRange     [2]Blob   // precomputed (for performance) key range to query all ordinals for entries in this directory
	parent       *fsDir    // parent directory, if any
	fs           *fsImpl   // parent FS instance
	owner        *Owner    // owner instance or nil if none
}

func (fsn *fsDir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Valid = time.Second * 10
	a.Inode = fsn.inode
	a.Size = 0
	a.Blocks = 0
	a.Atime = fsn.ts
	a.Mtime = fsn.ts
	a.Ctime = fsn.ts
	a.Crtime = fsn.ts
	modeMask := uint(0x1ff)
	if !fsn.writable() {
		modeMask = 0x16d // mask off write flags if we do not own this file
	}
	a.Mode = os.FileMode(fsn.fsFileHeader.mode&modeMask) | os.ModeDir
	a.Nlink = 1
	a.Uid = fsn.uid
	a.Gid = fsn.gid
	return nil
}

func (fsn *fsDir) Lookup(ctx context.Context, name string) (fusefs.Node, error) {
	if name == ".passwd" {
		if len(fsn.fsFileHeader.name) == 0 {
			var pwdata strings.Builder
			fsn.fs.passwdLock.Lock()
			for o, pe := range fsn.fs.passwd {
				pwdata.WriteString(o)
				pwdata.WriteString(":x:")
				pwdata.WriteString(strconv.FormatUint(uint64(pe.uid), 10))
				pwdata.WriteRune(':')
				pwdata.WriteString(strconv.FormatUint(uint64(fsn.gid), 10))
				pwdata.WriteRune(':')
				pwdata.WriteString(pe.public)
				pwdata.WriteRune(':')
				pwdata.WriteString(fsn.fs.mountPoint)
				pwdata.WriteString(":/usr/bin/false\n")
			}
			fsn.fs.passwdLock.Unlock()
			return &fsFile{
				fsFileHeader: fsFileHeader{
					mode: 0444 | fsFileTypeNormal,
					name: []byte(".passwd"),
				},
				inode:  2,
				ts:     time.Now(),
				uid:    fsn.fs.root.uid,
				gid:    fsn.fs.root.gid,
				parent: fsn,
				data:   []byte(pwdata.String()),
				owner:  nil,
			}, nil
		}
		return nil, fuse.EPERM
	}

	inode := fsn.fs.GenerateInode(fsn.inode, name)

	// Grab cache entry but note that we still check LF itself to make sure LF is
	// not newer. The main purpose of the cache is to hold entries while insertion
	// is taking place, especially when PoW is needed as this might take a while.
	fsn.fs.cacheLock.Lock()
	ce := fsn.fs.cache[inode]
	fsn.fs.cacheLock.Unlock()

	maskingKey := fsn.fs.maskingKey
	if len(maskingKey) == 0 {
		maskingKey = fsn.selectorName
	}
	q := &Query{
		Ranges:     []QueryRange{QueryRange{KeyRange: []Blob{MakeSelectorKey(fsn.selectorName, inode)}}},
		MaskingKey: maskingKey,
		Limit:      &eight,
	}
	var qr QueryResults
	for _, ds := range fsn.fs.ds {
		qr, _ = ds.ExecuteQuery(q)
		if qr != nil {
			break
		}
	}

	for _, results := range qr {
		for _, result := range results {
			if len(result.Value) > 0 {
				var f fsFile
				v, err := f.fsFileHeader.readFrom(result.Value)
				if err == nil && string(f.fsFileHeader.name) == name {
					var owner *Owner
					if bytes.Equal(result.Record.Owner, fsn.fs.owner.Public) {
						owner = fsn.fs.owner
					} else {
						owner = &Owner{Private: nil, Public: result.Record.Owner}
					}
					ownerName, ownerUID := fsLfOwnerToUser(owner.Public)
					fsn.fs.passwdLock.Lock()
					fsn.fs.passwd[ownerName] = fsPasswdEntry{uid: ownerUID, public: owner.Public.String()}
					fsn.fs.passwdLock.Unlock()

					if ce.ts > result.Record.Timestamp {
						if (ce.fsn.header().mode & fsFileTypeMask) == fsFileTypeDeleted {
							return nil, fuse.ENOENT
						}
						return ce.fsn, nil
					}
					fsn.fs.cacheLock.Lock()
					delete(fsn.fs.cache, inode)
					fsn.fs.cacheLock.Unlock()

					switch f.fsFileHeader.mode & fsFileTypeMask {

					case fsFileTypeNormal, fsFileTypeLink:
						f.inode = inode
						f.ts = time.Unix(int64(result.Record.Timestamp), 0)
						f.uid = ownerUID
						f.gid = fsn.fs.root.gid
						f.parent = fsn
						f.data = v
						f.owner = owner
						return &f, nil

					case fsFileTypeDir:
						sn := make([]byte, 0, len(fsn.selectorName)+len(f.fsFileHeader.name)+1)
						sn = append(sn, fsn.selectorName...)
						sn = append(sn, byte('/'))
						sn = append(sn, f.fsFileHeader.name...)
						return &fsDir{
							fsFileHeader: fsFileHeader{
								mode: f.fsFileHeader.mode,
								name: f.fsFileHeader.name,
							},
							inode:        inode,
							ts:           time.Unix(int64(result.Record.Timestamp), 0),
							uid:          ownerUID,
							gid:          fsn.fs.root.gid,
							selectorName: sn,
							keyRange:     [2]Blob{MakeSelectorKey(sn, 0), MakeSelectorKey(sn, OrdinalMaxValue)},
							parent:       fsn,
							fs:           fsn.fs,
							owner:        owner,
						}, nil

					case fsFileTypeDeleted:
						return nil, fuse.ENOENT

					}
				}
			}
		}
	}

	if ce.fsn != nil && (ce.fsn.header().mode&fsFileTypeMask) != fsFileTypeDeleted {
		return ce.fsn, nil
	}

	return nil, fuse.ENOENT
}

type fsDirEntryTmp struct {
	de fuse.Dirent
	ts uint64
}

func (fsn *fsDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	dirByName := make(map[string]fsDirEntryTmp)

	if len(fsn.fsFileHeader.name) == 0 {
		dirByName[".passwd"] = fsDirEntryTmp{
			de: fuse.Dirent{
				Inode: 2,
				Type:  fuse.DT_File,
				Name:  ".passwd",
			},
			ts: 0xffffffffffffffff,
		}
	}

	maskingKey := fsn.fs.maskingKey
	if len(maskingKey) == 0 {
		maskingKey = fsn.selectorName
	}
	q := &Query{
		Ranges:     []QueryRange{QueryRange{KeyRange: []Blob{MakeSelectorKey(fsn.selectorName, 0), MakeSelectorKey(fsn.selectorName, OrdinalMaxValue)}}},
		MaskingKey: maskingKey,
		Limit:      &one,
	}
	var qr QueryResults
	for _, ds := range fsn.fs.ds {
		qr, _ = ds.ExecuteQuery(q)
		if qr != nil {
			break
		}
	}

	fsn.fs.cacheLock.Lock()
	defer fsn.fs.cacheLock.Unlock()

	for _, results := range qr {
		for _, result := range results {
			if len(result.Value) > 0 {
				ownerName, ownerUID := fsLfOwnerToUser(result.Record.Owner)
				fsn.fs.passwdLock.Lock()
				fsn.fs.passwd[ownerName] = fsPasswdEntry{uid: ownerUID, public: result.Record.Owner.String()}
				fsn.fs.passwdLock.Unlock()

				var fh fsFileHeader
				_, err := fh.readFrom(result.Value)
				if err == nil && len(fh.name) > 0 {
					name := string(fh.name)
					if fsIsValidExternalFilename(name) {
						inode := fsn.fs.GenerateInode(fsn.inode, name)

						ts := result.Record.Timestamp
						ce := fsn.fs.cache[inode]
						if ce.ts > ts {
							ts = ce.ts
							fh = *ce.fsn.header()
						} else {
							delete(fsn.fs.cache, inode)
						}

						if dirByName[name].ts < ts {
							var dt fuse.DirentType
							switch fh.mode & fsFileTypeMask {
							case fsFileTypeNormal:
								dt = fuse.DT_File
							case fsFileTypeDir:
								dt = fuse.DT_Dir
							case fsFileTypeLink:
								dt = fuse.DT_Link
							default:
								dt = fuse.DT_Unknown
							}
							dirByName[name] = fsDirEntryTmp{
								de: fuse.Dirent{
									Inode: inode,
									Type:  dt,
									Name:  name,
								},
								ts: ts,
							}
						}

						break
					}
				}
			}
		}
	}

	for ci, ce := range fsn.fs.cache {
		if ce.parent == fsn {
			fh := ce.fsn.header()
			name := string(fh.name)

			if dirByName[name].ts < ce.ts {
				var dt fuse.DirentType
				switch fh.mode & fsFileTypeMask {
				case fsFileTypeNormal:
					dt = fuse.DT_File
				case fsFileTypeDir:
					dt = fuse.DT_Dir
				case fsFileTypeLink:
					dt = fuse.DT_Link
				default:
					dt = fuse.DT_Unknown
				}
				dirByName[name] = fsDirEntryTmp{
					de: fuse.Dirent{
						Inode: ci,
						Type:  dt,
						Name:  name,
					},
					ts: ce.ts,
				}
			}
		}
	}

	dir := make([]fuse.Dirent, 0, len(dirByName))
	for _, e := range dirByName {
		if e.de.Type != fuse.DT_Unknown {
			dir = append(dir, e.de)
		}
	}
	sort.Slice(dir, func(a, b int) bool {
		return strings.Compare(dir[a].Name, dir[b].Name) < 0
	})

	return dir, nil
}

func (fsn *fsDir) internalMkdir(ctx context.Context, name string, mode uint, commitNow bool) (*fsDir, error) {
	if !fsn.writable() {
		return nil, fuse.EPERM
	}
	if !fsIsValidExternalFilename(name) {
		return nil, fuse.EIO
	}

	exists, _ := fsn.Lookup(ctx, name)
	if exists != nil {
		return nil, fuse.EEXIST
	}

	nameBytes := []byte(name)
	sn := make([]byte, 0, len(fsn.selectorName)+1+len(nameBytes))
	sn = append(sn, fsn.selectorName...)
	sn = append(sn, byte('/'))
	sn = append(sn, nameBytes...)

	d := &fsDir{
		fsFileHeader: fsFileHeader{
			mode: mode | fsFileTypeDir,
			name: nameBytes,
		},
		inode:        fsn.fs.GenerateInode(fsn.inode, name),
		ts:           time.Now(),
		uid:          fsn.fs.ownerUID,
		gid:          fsn.fs.root.gid,
		selectorName: sn,
		keyRange:     [2]Blob{MakeSelectorKey(sn, 0), MakeSelectorKey(sn, OrdinalMaxValue)},
		parent:       fsn,
		fs:           fsn.fs,
		owner:        fsn.fs.owner,
	}

	if commitNow {
		fsn.fs.commitQueue <- d
	}

	return d, nil
}

func (fsn *fsDir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	return fsn.internalMkdir(ctx, req.Name, 0777, true) // TODO: right now we just set permission rw on everything
}

func (fsn *fsDir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	if !fsIsValidExternalFilename(req.Name) {
		return fuse.EIO
	}

	exists, _ := fsn.Lookup(ctx, req.Name)
	if exists == nil {
		return fuse.ENOENT
	}
	existsFsn, _ := exists.(fsFuseNode)
	if existsFsn == nil || !existsFsn.writable() {
		return fuse.EPERM
	}

	f := &fsFile{
		fsFileHeader: fsFileHeader{
			mode: fsFileTypeDeleted,
			name: []byte(req.Name),
		},
		inode:  fsn.fs.GenerateInode(fsn.inode, req.Name),
		ts:     time.Now(),
		uid:    fsn.fs.ownerUID,
		gid:    fsn.fs.root.gid,
		parent: fsn,
		data:   nil,
		owner:  fsn.fs.owner,
	}

	fsn.fs.commitQueue <- f

	return nil
}

func (fsn *fsDir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fusefs.Node) error {
	if !fsIsValidExternalFilename(req.NewName) {
		return fuse.EIO
	}

	if newDir == nil {
		return fuse.EIO
	}
	nd, _ := newDir.(*fsDir)
	if nd == nil {
		return fuse.EIO
	}
	if !nd.writable() {
		return fuse.EIO
	}

	oldNode, err := fsn.Lookup(ctx, req.OldName)
	if err != nil {
		return err
	}
	if oldNode == nil {
		return fuse.ENOENT
	}
	oldNodeFsn, _ := oldNode.(fsFuseNode)
	if oldNodeFsn == nil || !oldNodeFsn.writable() {
		return fuse.EPERM
	}

	var oldAttr fuse.Attr
	oldNode.Attr(ctx, &oldAttr)

	var cresp fuse.CreateResponse
	newNode, _, err := nd.Create(ctx, &fuse.CreateRequest{
		Header: req.Header,
		Name:   req.NewName,
		Flags:  fuse.OpenFlags(os.O_CREATE | os.O_WRONLY | os.O_TRUNC),
		Mode:   oldAttr.Mode,
	}, &cresp)
	if err != nil {
		return err
	}

	nnf, _ := newNode.(*fsFile)
	if nnf != nil {
		of, _ := oldNode.(*fsFile)
		if of != nil {
			nnf.data = of.data
		}

		fsn.fs.commitQueue <- nnf

		fsn.Remove(ctx, &fuse.RemoveRequest{
			Header: req.Header,
			Name:   req.OldName,
			Dir:    false,
		})

		return nil
	}

	nnd, _ := newNode.(*fsDir)
	if nnd != nil {
		fsn.fs.commitQueue <- nnd

		fsn.Remove(ctx, &fuse.RemoveRequest{
			Header: req.Header,
			Name:   req.OldName,
			Dir:    true,
		})

		return nil
	}

	return fuse.EIO
}

func (fsn *fsDir) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fusefs.Node, error) {
	if !fsIsValidExternalFilename(req.NewName) || len(req.Target) == 0 {
		return nil, fuse.EIO
	}

	exists, _ := fsn.Lookup(ctx, req.NewName)
	if exists != nil {
		return nil, fuse.EEXIST
	}

	f := &fsFile{
		fsFileHeader: fsFileHeader{
			mode: 0666 | fsFileTypeLink,
			name: []byte(req.NewName),
		},
		inode:  fsn.fs.GenerateInode(fsn.inode, req.NewName),
		ts:     time.Now(),
		uid:    fsn.fs.ownerUID,
		gid:    fsn.fs.root.gid,
		parent: fsn,
		data:   []byte(req.Target),
		owner:  fsn.fs.owner,
	}

	fsn.fs.commitQueue <- f

	return f, nil
}

func (fsn *fsDir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fusefs.Node, fusefs.Handle, error) {
	if !fsIsValidExternalFilename(req.Name) {
		return nil, nil, fuse.EIO
	}

	//perm := uint(req.Mode.Perm())
	perm := uint(0666) // TODO: right now we don't support setattr and perm == rw for all

	if req.Mode.IsDir() {
		nn, err := fsn.internalMkdir(ctx, req.Name, perm|0111, false)

		fsn.fs.cacheLock.Lock()
		fsn.fs.cache[nn.inode] = fsCacheEntry{
			parent: nn.parent,
			fsn:    nn,
			ts:     uint64(nn.ts.Unix()),
		}
		fsn.fs.cacheLock.Unlock()

		return nn, nn, err
	}

	if req.Mode.IsRegular() {
		exists, _ := fsn.Lookup(ctx, req.Name)
		if exists != nil {
			return nil, nil, fuse.EEXIST
		}

		f := &fsFile{
			fsFileHeader: fsFileHeader{
				mode: perm | fsFileTypeNormal,
				name: []byte(req.Name),
			},
			inode:  fsn.fs.GenerateInode(fsn.inode, req.Name),
			ts:     time.Now(),
			uid:    fsn.fs.ownerUID,
			gid:    fsn.fs.root.gid,
			parent: fsn,
			data:   nil,
			owner:  fsn.fs.owner,
		}

		fsn.fs.dirtyLock.Lock()
		fsn.fs.dirty[f.inode] = f
		fsn.fs.dirtyLock.Unlock()

		fsn.fs.cacheLock.Lock()
		fsn.fs.cache[f.inode] = fsCacheEntry{
			parent: f.parent,
			fsn:    f,
			ts:     uint64(f.ts.Unix()),
		}
		fsn.fs.cacheLock.Unlock()

		return f, f, nil
	}

	return nil, nil, fuse.ENOTSUP
}

func (fsn *fsDir) commit() error {
	if fsn.parent == nil {
		return fuse.EIO
	}

	rdata := make([]byte, 0, len(fsn.fsFileHeader.name)+16)
	rdata = fsn.fsFileHeader.appendTo(rdata)

	var os *OwnerStatus
	for _, ds := range fsn.fs.ds {
		os, _ = ds.OwnerStatus(fsn.fs.owner.Public)
		if os != nil {
			break
		}
	}
	if os == nil {
		return fuse.EIO
	}

	ts := TimeSec()

	fsn.fs.cacheLock.Lock()
	fsn.fs.cache[fsn.inode] = fsCacheEntry{
		parent: fsn.parent,
		fsn:    fsn,
		ts:     ts,
	}
	fsn.fs.cacheLock.Unlock()

	var wf *Wharrgarblr
	if !os.HasCurrentCertificate {
		wf = fsn.fs.getWorkFunction()
	}

	rec, err := NewRecord(RecordTypeDatum, rdata, CastHashBlobsToArrays(os.NewRecordLinks), fsn.fs.maskingKey, [][]byte{fsn.parent.selectorName}, []uint64{fsn.inode}, ts, wf, fsn.fs.owner)
	if err != nil {
		return err
	}

	var addErr error
	for _, ds := range fsn.fs.ds {
		addErr = ds.AddRecord(rec)
		if addErr == nil {
			break
		}
	}
	return addErr
}

func (fsn *fsDir) header() *fsFileHeader {
	return &fsn.fsFileHeader
}

func (fsn *fsDir) writable() bool {
	return fsn.owner != nil && fsn.owner.Private != nil
}

func (fsn *fsDir) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	return nil
}

func (fsn *fsDir) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	return nil
}

func (fsn *fsDir) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	fsn.fs.dirtyLock.Lock()
	_, dirty := fsn.fs.dirty[fsn.inode]
	delete(fsn.fs.dirty, fsn.inode)
	fsn.fs.dirtyLock.Unlock()
	if dirty {
		fsn.fs.commitQueue <- fsn
	}
	return nil
}

//////////////////////////////////////////////////////////////////////////////

// fsFile implements Node and Handle for regular files and links (for links the data is the link target)
type fsFile struct {
	fsFileHeader
	inode     uint64     // inode a.k.a. ordinal computed from parent inode + CRC64-ECMA(name)
	ts        time.Time  // timestamp from LF record
	uid, gid  uint32     // Unix UID/GID
	parent    *fsDir     // parent directory node
	data      []byte     // file's data
	writeLock sync.Mutex //
	owner     *Owner     // owner or nil for pseudo-files
}

func (fsn *fsFile) dechunk() error {
	var rec *Record
	for fsn.fsFileHeader.oversizeDepth > 0 {
		fsn.fsFileHeader.oversizeDepth--
		newData := make([]byte, 0, 1024)
		for i := 0; (i + 48) <= len(fsn.data); i += 48 {
			for _, ds := range fsn.parent.fs.ds {
				rec, _ = ds.GetRecord(fsn.data[i : i+32])
				if rec != nil {
					break
				}
			}
			if rec == nil {
				return fuse.EIO
			}
			rdata, err := rec.GetValue(fsn.data[i+32 : i+48])
			if err != nil {
				return err
			}
			newData = append(newData, rdata...)
		}
		fsn.data = newData
	}
	return nil
}

func (fsn *fsFile) Attr(ctx context.Context, a *fuse.Attr) error {
	err := fsn.dechunk()
	if err != nil {
		return fuse.EIO
	}
	a.Valid = time.Second * 10
	a.Inode = fsn.inode
	a.Size = uint64(len(fsn.data))
	a.Blocks = a.Size / 512
	a.Atime = fsn.ts
	a.Mtime = fsn.ts
	a.Ctime = fsn.ts
	a.Crtime = fsn.ts
	modeMask := uint(0x1ff)
	if !fsn.writable() {
		modeMask = 0x16d // mask off write flags if we do not own this file
	}
	if (fsn.fsFileHeader.mode & fsFileTypeMask) == fsFileTypeLink {
		a.Mode = os.FileMode(fsn.fsFileHeader.mode&modeMask) | os.ModeSymlink
	} else {
		a.Mode = os.FileMode(fsn.fsFileHeader.mode & modeMask)
	}
	a.Nlink = 1
	a.Uid = fsn.uid
	a.Gid = fsn.gid
	a.BlockSize = 4096
	return nil
}

func (fsn *fsFile) ReadAll(ctx context.Context) ([]byte, error) {
	if (fsn.fsFileHeader.mode & fsFileTypeMask) == fsFileTypeNormal {
		if fsn.dechunk() == nil {
			return fsn.data, nil
		}
	}
	return nil, fuse.EIO
}

func (fsn *fsFile) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {
	if (fsn.fsFileHeader.mode & fsFileTypeMask) == fsFileTypeLink {
		if fsn.dechunk() == nil {
			return string(fsn.data), nil
		}
	}
	return "", fuse.EIO
}

func (fsn *fsFile) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	data, err := fsn.ReadAll(ctx)
	if err != nil {
		return err
	}
	if req.Offset > int64(len(data)) {
		return fuse.EIO
	}
	data = data[uint(req.Offset):]
	if len(data) > req.Size {
		data = data[0:req.Size]
	}
	resp.Data = data
	return nil
}

func (fsn *fsFile) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	if (fsn.fsFileHeader.mode & fsFileTypeMask) != fsFileTypeNormal {
		return fuse.EIO
	}
	if !fsn.writable() {
		return fuse.EPERM
	}

	if len(req.Data) == 0 {
		return nil
	}

	err := fsn.dechunk()
	if err != nil {
		return fuse.EIO
	}

	if req.Offset >= int64(fsn.parent.fs.maxFileSize) {
		return syscall.ENOSPC
	}

	fsn.parent.fs.dirtyLock.Lock()
	fsn.parent.fs.dirty[fsn.inode] = fsn
	fsn.parent.fs.dirtyLock.Unlock()

	fsn.writeLock.Lock()
	defer fsn.writeLock.Unlock()

	eofPos := int(req.Offset + int64(len(req.Data)))
	if eofPos > fsn.parent.fs.maxFileSize {
		eofPos = fsn.parent.fs.maxFileSize
	}
	if eofPos == int(req.Offset) {
		return nil
	}

	written := eofPos - int(req.Offset)
	if eofPos > len(fsn.data) {
		d2 := make([]byte, eofPos)
		copy(d2, fsn.data)
		copy(d2[int(req.Offset):], req.Data[0:written])
		fsn.data = d2
	} else if bytes.Equal(fsn.data[int(req.Offset):], req.Data[0:written]) {
		return nil // avoid unnecessary commits by just returning if the data hasn't changed
	} else {
		copy(fsn.data[int(req.Offset):], req.Data[0:written])
	}

	resp.Size = written

	return nil
}

func (fsn *fsFile) commit() error {
	if !fsn.writable() {
		return fuse.EPERM
	}
	if fsn.parent == nil { // sanity check, should be impossible
		return ErrInvalidObject
	}

	var os *OwnerStatus
	for _, ds := range fsn.parent.fs.ds {
		os, _ = ds.OwnerStatus(fsn.parent.fs.owner.Public)
	}
	if os == nil {
		return fuse.EIO
	}

	var wf *Wharrgarblr
	if !os.HasCurrentCertificate {
		wf = fsn.parent.fs.getWorkFunction()
	}

	ts := TimeSec()

	fsn.parent.fs.cacheLock.Lock()
	fsn.parent.fs.cache[fsn.inode] = fsCacheEntry{
		parent: fsn.parent,
		fsn:    fsn,
		ts:     ts,
	}
	fsn.parent.fs.cacheLock.Unlock()

	fdata := fsn.data
	rdata := make([]byte, 0, len(fdata)+len(fsn.fsFileHeader.name)+16)
	rdata = fsn.fsFileHeader.appendTo(rdata)
	rdata = append(rdata, fdata...)

	links := CastHashBlobsToArrays(os.NewRecordLinks)

	// If record data is too large, break it into chunks at data dependent breakage
	// points and store these chunks. The file then becomes hashes of chunks. This
	// is done recursively until it fits. Chunks are stored by their hash with a
	// selector name and masking key that is their content hash, meaning that this
	// acts as a global (across the whole LF data store) deduplicating storage
	// system. This doesn't compromise data privacy since if you don't know the hash
	// of the content you want you can't look it up or decrypt it.
	maxValueSize := int(fsn.parent.fs.gp.RecordMaxValueSize)
	if len(rdata) > maxValueSize {
		fh := fsn.fsFileHeader
		fh.oversizeDepth = 0

		storeChunkByIdentityHash := func(chunk, chunkHash []byte) (*Record, error) {
			q := &Query{
				Ranges:     []QueryRange{QueryRange{KeyRange: []Blob{MakeSelectorKey(chunkHash, 0)}}},
				MaskingKey: chunkHash[0:16],
				Limit:      &one,
			}
			var qr QueryResults
			var err error
			for _, ds := range fsn.parent.fs.ds {
				qr, err = ds.ExecuteQuery(q)
				if err == nil {
					break
				}
			}
			if err != nil {
				return nil, err
			}
			for _, results := range qr {
				for _, result := range results {
					if len(result.Value) > 0 {
						h := sha256.Sum256(result.Value)
						if bytes.Equal(h[:], chunkHash) {
							return result.Record, nil
						}
					}
				}
			}

			if links == nil {
				for _, ds := range fsn.parent.fs.ds {
					links, ts, err = ds.Links(0)
					if len(links) > 0 {
						break
					}
				}
				if err != nil {
					return nil, err
				}
			}

			rec, err := NewRecord(RecordTypeDatum, chunk, links, chunkHash[0:16], [][]byte{chunkHash}, []uint64{0}, ts, wf, fsn.parent.fs.owner)
			if err != nil {
				return nil, err
			}
			for _, ds := range fsn.parent.fs.ds {
				err = ds.AddRecord(rec)
				if err == nil {
					break
				}
			}

			links = nil

			return rec, err
		}

		// Make average chunk size a little more than half the value size. Chunks will be
		// cut off at random data-dependent positions for lengths near this or when their
		// size equals the maximum record value size. We also don't bother storing chunks
		// smaller than 64 bytes unless they happen to be final chunks.
		chunkModulus := (uint64(maxValueSize) / 3) * 2

		// Perform identity keyed chunking repeatedly until the list of hashes is small
		// enough to fit in the final record.
		chunk := make([]byte, 0, maxValueSize)
		for len(rdata) > maxValueSize {
			newfdata := make([]byte, 0, maxValueSize)
			var accum uint64
			for _, b := range fdata {
				chunk = append(chunk, b)
				accum += uint64(b)
				if len(chunk) >= maxValueSize || ((accum%chunkModulus) == 0 && len(chunk) >= 64) {
					chunkHash := sha256.Sum256(chunk)
					rec, err := storeChunkByIdentityHash(chunk, chunkHash[:])
					if err != nil {
						return err
					}
					rh := rec.Hash()
					newfdata = append(newfdata, rh[:]...)
					newfdata = append(newfdata, chunkHash[0:16]...)
					chunk = chunk[:0]
				}
			}
			if len(chunk) > 0 {
				chunkHash := sha256.Sum256(chunk)
				rec, err := storeChunkByIdentityHash(chunk, chunkHash[:])
				if err != nil {
					fmt.Printf("%v\n", err)
					return err
				}
				rh := rec.Hash()
				newfdata = append(newfdata, rh[:]...)
				newfdata = append(newfdata, chunkHash[0:16]...)
				chunk = chunk[:0]
			}

			fdata = newfdata
			rdata = rdata[:0]
			fh.oversizeDepth++
			rdata = fh.appendTo(rdata)
			rdata = append(rdata, fdata...)
		}
	}

	if links == nil {
		var err error
		for _, ds := range fsn.parent.fs.ds {
			links, ts, err = ds.Links(0)
			if len(links) > 0 {
				break
			}
		}
		if err != nil {
			return err
		}
	}

	rec, err := NewRecord(RecordTypeDatum, rdata, links, fsn.parent.fs.maskingKey, [][]byte{fsn.parent.selectorName}, []uint64{fsn.inode}, ts, wf, fsn.parent.fs.owner)
	if err != nil {
		return err
	}

	for _, ds := range fsn.parent.fs.ds {
		err = ds.AddRecord(rec)
		if err == nil {
			break
		}
	}
	return err
}

func (fsn *fsFile) header() *fsFileHeader {
	return &fsn.fsFileHeader
}

func (fsn *fsFile) writable() bool {
	return fsn.owner != nil && fsn.owner.Private != nil
}

func (fsn *fsFile) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	return nil
}

func (fsn *fsFile) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	return nil
}

func (fsn *fsFile) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	if fsn.parent == nil {
		return nil
	}
	fsn.parent.fs.dirtyLock.Lock()
	_, dirty := fsn.parent.fs.dirty[fsn.inode]
	delete(fsn.parent.fs.dirty, fsn.inode)
	fsn.parent.fs.dirtyLock.Unlock()
	if dirty {
		fsn.parent.fs.commitQueue <- fsn
	}
	return nil
}
