package libdsm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"
	"sync"
)
/*
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bdsm.h>

uint32_t get_addr(char* host)
{
	struct in_addr  addr;
	inet_aton(host, &addr);
	return addr.s_addr;
}

ssize_t smb_fread_wrapper(smb_session* s, smb_fd f, void* p, unsigned long buf_size)
{
	return smb_fread(s, f, p, buf_size);
}

ssize_t smb_fwrite_wrapper(smb_session* s, smb_fd f, void* p, unsigned long buf_size)
{
	return smb_fwrite(s, f, p, buf_size);
}

ssize_t smb_fseek_wrapper(smb_session* s, smb_fd f, long long offset, int whence)
{
	return smb_fseek(s, f, offset, whence);
}
*/
import "C"

type Smb struct {
	session *C.smb_session
	tid C.smb_tid
	mutex sync.Mutex
}

type cSmbStat struct {
	smbStat *C.smb_file
}

type smbStat struct {
	name string
	isDir bool
	modTime time.Time
	mode os.FileMode
	size int64
}

type smbFile struct {
	smb		*Smb
	fd		C.smb_fd
	path	string
	*smbStat
}

func NewSmb() *Smb {
	return &Smb{
		session: C.smb_session_new(),
	}
}

func (s *Smb) Connect(host string, share string, user string, password string) error {
	var ip string
	if goIP:=net.ParseIP(host); goIP == nil {
		if ips, err := net.LookupIP(host); err != nil {
			return err
		} else {
			for _, result := range ips {
				if result.To4() != nil {
					ip = result.To4().String()
					break
				}
			}
		}
	} else {
		ip = goIP.String()
	}
	if code:=C.smb_session_connect(s.session, C.CString(host), C.get_addr(C.CString(ip)), C.SMB_TRANSPORT_TCP); code != 0 {
		return errors.New(fmt.Sprintf("unable to connect to %s, code %d", host, int(code)))
	}
	C.smb_session_set_creds(s.session, C.CString(host), C.CString(user), C.CString(password))
	if code:=C.smb_session_login(s.session); code != 0 {
		return errors.New(fmt.Sprintf("wrong username or password, code %d", int(code)))
	}
	if code:=C.smb_tree_connect(s.session, C.CString(share), &s.tid); code != 0 || s.tid == 0 {
		return errors.New(fmt.Sprintf("cannot access share, code %d", int(code)))
	}
	return nil
}

func (s* Smb) Disconnect() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.session != nil {
		C.smb_tree_disconnect(s.session, s.tid);
		C.smb_session_destroy(s.session);
		s.session = nil
	}
}


func (s* Smb) OpenFile(path string, mode int) (*smbFile, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.session == nil {
		return nil, errors.New("opening file on closed session")
	}
	var smbMode C.uint32_t
	switch mode {
	case os.O_RDONLY:
		smbMode = C.SMB_MOD_RO
	case os.O_RDWR:
		smbMode = C.SMB_MOD_RW
	default:
		return nil, errors.New("please only use RDONLY or RDWR modes")
	}
	file := &smbFile{
		smb: s,
		path: path,
	}
	if code := C.smb_fopen(s.session, s.tid, C.CString(path), C.uint(smbMode), &file.fd); code != 0 || file.fd == 0 {
		return nil, errors.New(fmt.Sprintf("file open failed, code %d", int(code)))
	}
	st := cSmbStat{smbStat: C.smb_stat_fd(s.session, file.fd)}
	file.smbStat = st.toGoStat()
	return file, nil
}

func (f *smbFile) Read(p []byte) (n int, err error) {
	f.smb.mutex.Lock()
	defer f.smb.mutex.Unlock()
	if f.fd == C.uint(0) || f.smb.session == nil {
		return 0, io.EOF
	}
	n=int(C.smb_fread_wrapper(f.smb.session, f.fd, unsafe.Pointer(&p[0]), C.ulong(len(p))));
	if n <= 0 {
		err=io.EOF
	}
	return
}

func (f *smbFile) Stat() (os.FileInfo, error) {
	return f, nil
}

func (f *smbFile) Seek(offset int64, whence int) (res int64, err error){
	f.smb.mutex.Lock()
	defer f.smb.mutex.Unlock()
	if f.fd == C.uint(0) || f.smb.session == nil {
		return 0, io.EOF
	}
	realOffset := offset
	if whence == io.SeekEnd {
		realOffset = f.Size()+offset
		whence = io.SeekStart
	}
	res = int64(C.smb_fseek_wrapper(f.smb.session, f.fd, C.longlong(realOffset), C.int(whence)))
	if res < 0 {
		err = errors.New("seek error")
	}
	return
}

func (f *smbFile) Readdir(count int) (infos []os.FileInfo, err error) {
	f.smb.mutex.Lock()
	defer f.smb.mutex.Unlock()
	findPath := strings.Replace(f.path,"/","\\", -1)+"\\*"
	list := C.smb_find(f.smb.session, f.smb.tid, C.CString(findPath))
	defer C.smb_stat_list_destroy(list)
	size := int(C.smb_stat_list_count(list))
	if count <= 0 {
		count = size
	}
	infos=make([]os.FileInfo, count)
	var stat unsafe.Pointer
	stat = unsafe.Pointer(list)
	for i:=0; i<size && i<count; i++ {
		st := cSmbStat{smbStat: (*C.smb_file)(stat)}
		infos[i] = st.toGoStat()
		stat=unsafe.Pointer(C.smb_stat_list_next((*C.smb_file)(stat)))
	}
	if len(infos) < 1 {
		err = io.EOF
	}
	return
}

func (f *smbFile) Write(p []byte) (n int, err error) {
	f.smb.mutex.Lock()
	defer f.smb.mutex.Unlock()
	if f.fd == C.uint(0) || f.smb.session == nil {
		return 0, io.EOF
	}
	n=int(C.smb_fwrite_wrapper(f.smb.session, f.fd, unsafe.Pointer(&p[0]), C.ulong(len(p))));
	if n <= 0 {
		err = errors.New("write error")
	}
	return
}

func (f *smbFile) Close() error {
	f.smb.mutex.Lock()
	defer f.smb.mutex.Unlock()
	if f.fd == C.uint(0) || f.smb.session == nil {
		return nil
	}
	C.smb_fclose(f.smb.session, f.fd);
	f.fd = C.uint(0)
	return nil
}

func (f *cSmbStat) Name() string {
	return C.GoString(C.smb_stat_name(f.smbStat))
}

func (f *cSmbStat) IsDir() bool {
	return C.smb_stat_get(f.smbStat, C.SMB_STAT_ISDIR) > 0
}

func (f *cSmbStat) ModTime() time.Time {
	return time.Unix(int64(C.smb_stat_get(f.smbStat, C.SMB_STAT_MTIME)),0)
}

func (f *cSmbStat) Size() int64 {
	return int64(C.smb_stat_get(f.smbStat, C.SMB_STAT_SIZE))
}

func (f *cSmbStat) Mode() os.FileMode {
	return 666
}

func (f *smbStat) Name() string {
	return f.name
}

func (f *smbStat) IsDir() bool {
	return f.isDir
}

func (f *smbStat) ModTime() time.Time {
	return f.modTime
}

func (f *smbStat) Size() int64 {
	return f.size
}

func (f *smbStat) Mode() os.FileMode {
	return f.mode
}

func (f *smbStat) Sys() interface{} {
	return nil
}

func (f *cSmbStat) toGoStat() *smbStat {
	return &smbStat{
		name:     f.Name(),
		isDir:    f.IsDir(),
		modTime:  f.ModTime(),
		mode:     f.Mode(),
		size:	  f.Size(),
	}
}

func (f *cSmbStat) Sys() interface{} {
	return nil
}




