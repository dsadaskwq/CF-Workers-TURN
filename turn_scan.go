package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// STUN magic cookie and message types
var magic = [4]byte{0x21, 0x12, 0xA4, 0x42}

const (
	allocReq, allocOK, allocErr = 0x0003, 0x0103, 0x0113
	permReq, permOK             = 0x0008, 0x0108
	connReq, connOK             = 0x000A, 0x010A
	bindReq, bindOK             = 0x000B, 0x010B
	sendInd, dataInd            = 0x0016, 0x0017

	aUser, aIntegrity, aError = 0x0006, 0x0008, 0x0009
	aRealm, aNonce, aPeer     = 0x0014, 0x0015, 0x0012
	aTransport, aConnID       = 0x0019, 0x002A
	aSoftware, aData          = 0x8022, 0x0013
)

const (
	verifyHost, verifyPath = "api.ipapi.is", "/"
	verifyPort, dnsIP      = 443, "8.8.8.8"
)

var (
	optPing, optTimeout, optConn time.Duration
	flagConcur, flagPingConcur   int
	verifyIP                     string
)

var creds = [][2]string{
	{"test", "test"}, {"test", "test123"}, {"test", "1234"}, {"test", "123456"},
	{"coturn", "coturn"}, {"coturn", "coturn123"}, {"coturn", "password"},
	{"guest", "guest"}, {"guest", "guest123"},
	{"admin", "admin"}, {"admin", "admin123"}, {"admin", "password"}, {"admin", "123456"},
	{"user", "user"}, {"user", "password"}, {"user", "user123"},
	{"turn", "turn"}, {"turn", "turn123"}, {"turn", "password"},
	{"root", "root"}, {"root", "password"}, {"root", "123456"},
	{"username", "password"}, {"demo", "demo"}, {"webrtc", "webrtc"},
}

// ── STUN primitives ──

func mkAttr(t uint16, v []byte) []byte {
	pad := (4 - len(v)%4) % 4
	b := make([]byte, 4+len(v)+pad)
	binary.BigEndian.PutUint16(b, t)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	copy(b[4:], v)
	return b
}

func mkMsg(tp uint16, tid []byte, attrs ...[]byte) []byte {
	var size int
	for _, a := range attrs {
		size += len(a)
	}
	m := make([]byte, 20, 20+size)
	binary.BigEndian.PutUint16(m, tp)
	binary.BigEndian.PutUint16(m[2:], uint16(size))
	copy(m[4:], magic[:])
	copy(m[8:], tid)
	for _, a := range attrs {
		m = append(m, a...)
	}
	return m
}

func signMsg(m, key []byte) []byte {
	mc := make([]byte, len(m), len(m)+24)
	copy(mc, m)
	binary.BigEndian.PutUint16(mc[2:], uint16(len(m)-20+24))
	h := hmac.New(sha1.New, key)
	h.Write(mc)
	return append(mc, mkAttr(aIntegrity, h.Sum(nil))...)
}

func sign(m, key []byte) []byte {
	if key == nil {
		return m
	}
	return signMsg(m, key)
}

func xorAddr(ip string, port uint16) []byte {
	b := make([]byte, 8)
	b[1] = 1
	binary.BigEndian.PutUint16(b[2:], port^0x2112)
	for i, p := range strings.SplitN(ip, ".", 4) {
		v, _ := strconv.Atoi(p)
		b[4+i] = byte(v) ^ magic[i]
	}
	return b
}

func randTID() []byte {
	b := make([]byte, 12)
	rand.Read(b)
	return b
}

// ── STUN parsing ──

type stunMsg struct {
	tp    uint16
	attrs map[uint16][]byte
}

func (m *stunMsg) is(t uint16) bool    { return m != nil && m.tp == t }
func (m *stunMsg) get(k uint16) []byte { return m.attrs[k] }
func (m *stunMsg) sw() string          { return string(m.attrs[aSoftware]) }

func (m *stunMsg) errCode() int {
	if d := m.attrs[aError]; len(d) >= 4 {
		return int(d[2]&7)*100 + int(d[3])
	}
	return 0
}

func parseMsg(data []byte) *stunMsg {
	if len(data) < 20 || *(*[4]byte)(data[4:8]) != magic {
		return nil
	}
	ml := int(binary.BigEndian.Uint16(data[2:4]))
	attrs := make(map[uint16][]byte)
	for o := 20; o+4 <= 20+ml && o+4 <= len(data); {
		at := binary.BigEndian.Uint16(data[o:])
		al := int(binary.BigEndian.Uint16(data[o+2:]))
		if o+4+al > len(data) {
			break
		}
		attrs[at] = append([]byte(nil), data[o+4:o+4+al]...)
		o += 4 + al + (4-al%4)%4
	}
	return &stunMsg{tp: binary.BigEndian.Uint16(data[:2]), attrs: attrs}
}

// ── TCP connection ──

type stunConn struct {
	net.Conn
	br *bufio.Reader
}

func dial(addr string, timeout time.Duration) (*stunConn, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &stunConn{c, bufio.NewReader(c)}, nil
}

func (c *stunConn) readMsg(dl time.Time) *stunMsg {
	hdr := make([]byte, 20)
	if c.readN(hdr, dl) != nil || hdr[0]&0xC0 != 0 {
		return nil
	}
	if ml := int(binary.BigEndian.Uint16(hdr[2:4])); ml > 0 {
		body := make([]byte, ml)
		if c.readN(body, dl) != nil {
			return nil
		}
		return parseMsg(append(hdr, body...))
	}
	return parseMsg(hdr)
}

func (c *stunConn) readN(buf []byte, dl time.Time) error {
	for n := 0; n < len(buf); {
		if time.Now().After(dl) {
			return io.ErrNoProgress
		}
		nn, err := c.br.Read(buf[n:])
		if n += nn; err != nil {
			return err
		}
	}
	return nil
}

func (c *stunConn) send(m []byte, timeout time.Duration) *stunMsg {
	dl := time.Now().Add(timeout)
	c.SetDeadline(dl)
	c.Write(m)
	return c.readMsg(dl)
}

func (c *stunConn) recv(timeout time.Duration) *stunMsg {
	dl := time.Now().Add(timeout)
	c.SetDeadline(dl)
	return c.readMsg(dl)
}

// ── DNS probe ──

func buildDNSQuery() ([]byte, []byte) {
	txid := make([]byte, 2)
	rand.Read(txid)
	pkt := make([]byte, 29)
	copy(pkt, txid)
	pkt[2], pkt[5] = 0x01, 1
	copy(pkt[12:], []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1})
	return pkt, txid
}

func checkDNS(data, txid []byte) bool {
	return len(data) >= 12 && data[0] == txid[0] && data[1] == txid[1] &&
		(data[2]>>4)&0xF == 8 && data[3]&0xF == 0
}

// ── Auth ──

type authInfo struct {
	key, aa        []byte
	sw, cred       string
	noAuth         bool
}

func (a *authInfo) sign(m []byte) []byte { return sign(m, a.key) }

func doAlloc(c *stunConn, transport byte, knownCred string) *authInfo {
	tp := []byte{transport, 0, 0, 0}
	r := c.send(mkMsg(allocReq, randTID(), mkAttr(aTransport, tp)), optTimeout)
	if r == nil {
		return nil
	}
	sw := r.sw()
	if r.is(allocOK) {
		return &authInfo{sw: sw, noAuth: true}
	}
	if !r.is(allocErr) || r.errCode() != 401 {
		return nil
	}

	realm, nonce := string(r.get(aRealm)), r.get(aNonce)
	tryList := creds
	if knownCred != "" {
		if p := strings.SplitN(knownCred, ":", 2); len(p) == 2 {
			tryList = [][2]string{{p[0], p[1]}}
		}
	}

	for _, cr := range tryList {
		user, passwd := cr[0], cr[1]
		h := md5.Sum([]byte(user + ":" + realm + ":" + passwd))
		aa := append(mkAttr(aUser, []byte(user)), mkAttr(aRealm, []byte(realm))...)
		aa = append(aa, mkAttr(aNonce, nonce)...)
		m := signMsg(mkMsg(allocReq, randTID(), mkAttr(aTransport, tp), aa), h[:])

		if r = c.send(m, optTimeout); r == nil {
			return nil
		}
		if r.is(allocOK) {
			return &authInfo{key: h[:], aa: aa, sw: sw, cred: user + ":" + passwd}
		}
		if r.is(allocErr) {
			if n := r.get(aNonce); n != nil {
				nonce = n
			}
			if nr := r.get(aRealm); nr != nil {
				realm = string(nr)
			}
		}
	}
	return nil
}

// ── TCP relay test ──

func testTCP(c *stunConn, addr string, auth *authInfo) (ok bool, country, ipType string) {
	peer := mkAttr(aPeer, xorAddr(verifyIP, verifyPort))
	permMsg := auth.sign(mkMsg(permReq, randTID(), peer, auth.aa))
	connMsg := auth.sign(mkMsg(connReq, randTID(), peer, auth.aa))

	dl := time.Now().Add(optConn)
	c.SetDeadline(dl)
	c.Write(append(permMsg, connMsg...))

	if r := c.readMsg(dl); !r.is(permOK) {
		return
	}
	r := c.recv(optConn)
	if !r.is(connOK) || r.get(aConnID) == nil {
		return
	}

	dc, err := dial(addr, optTimeout)
	if err != nil {
		return
	}
	defer dc.Close()

	bindMsg := auth.sign(mkMsg(bindReq, randTID(), mkAttr(aConnID, r.get(aConnID)), auth.aa))
	if br := dc.send(bindMsg, optTimeout); !br.is(bindOK) {
		return
	}

	tc := tls.Client(dc.Conn, &tls.Config{ServerName: verifyHost})
	tc.SetDeadline(time.Now().Add(optTimeout))
	if tc.Handshake() != nil {
		return
	}
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		verifyPath, verifyHost)
	resp, _ := io.ReadAll(io.LimitReader(tc, 8192))

	idx := strings.Index(string(resp), "\r\n\r\n")
	if idx < 0 {
		return
	}

	var j map[string]any
	if json.Unmarshal(resp[idx+4:], &j) != nil {
		return true, "", ""
	}

	// parse location
	if loc, _ := j["location"].(map[string]any); loc != nil {
		country, _ = loc["country"].(string)
		state, _ := loc["state"].(string)
		city, _ := loc["city"].(string)
		switch {
		case state != "" && city != "" && city != state:
			country += "-" + state + " " + city
		case state != "":
			country += "-" + state
		case city != "":
			country += "-" + city
		}
	}

	// determine IP type
	isDC, _ := j["is_datacenter"].(bool)
	isProxy, _ := j["is_proxy"].(bool)
	isVPN, _ := j["is_vpn"].(bool)
	compType := ""
	if comp, _ := j["company"].(map[string]any); comp != nil {
		compType, _ = comp["type"].(string)
	}
	if !isDC && !isProxy && !isVPN && strings.EqualFold(compType, "isp") {
		ipType = "住宅IP"
	} else {
		ipType = "商企IP"
	}
	return true, country, ipType
}

// ── UDP relay test ──

func testUDP(addr, knownCred string) (*authInfo, bool) {
	c, err := dial(addr, optPing)
	if err != nil {
		return nil, false
	}
	defer c.Close()

	auth := doAlloc(c, 17, knownCred)
	if auth == nil {
		return nil, false
	}

	permMsg := auth.sign(mkMsg(permReq, randTID(), mkAttr(aPeer, xorAddr(dnsIP, 0)), auth.aa))
	if r := c.send(permMsg, optTimeout); !r.is(permOK) {
		return auth, false
	}

	dnsQ, txid := buildDNSQuery()
	sendMsg := mkMsg(sendInd, randTID(), mkAttr(aPeer, xorAddr(dnsIP, 53)), mkAttr(aData, dnsQ))
	if r := c.send(sendMsg, optTimeout); r.is(dataInd) {
		return auth, checkDNS(r.get(aData), txid)
	}
	return auth, false
}

// ── scan ──

type scanInfo struct {
	IP, SW, Cred, Country, IPType, Mode string
	Port                                int
	NoAuth, TCP, UDP                    bool
}

func scanOne(ip string, port int, sem, pingSem chan struct{}, alive *int64) *scanInfo {
	addr := ip + ":" + strconv.Itoa(port)

	pingSem <- struct{}{}
	c, err := net.DialTimeout("tcp", addr, optPing)
	<-pingSem
	if err != nil {
		return nil
	}
	c.Close()
	atomic.AddInt64(alive, 1)

	sem <- struct{}{}
	defer func() { <-sem }()

	info := &scanInfo{IP: ip, Port: port}

	// TCP relay
	if tc, err := dial(addr, optTimeout); err == nil {
		if auth := doAlloc(tc, 6, ""); auth != nil {
			info.SW, info.NoAuth, info.Cred = auth.sw, auth.noAuth, auth.cred
			info.TCP, info.Country, info.IPType = testTCP(tc, addr, auth)
		}
		tc.Close()
	}

	// UDP relay
	if udpAuth, udpOK := testUDP(addr, info.Cred); udpAuth != nil {
		info.UDP = udpOK
		if info.SW == "" {
			info.SW = udpAuth.sw
		}
		if !info.NoAuth && info.Cred == "" {
			info.NoAuth, info.Cred = udpAuth.noAuth, udpAuth.cred
		}
	}

	switch {
	case info.TCP && info.UDP:
		info.Mode = "ALL"
	case info.TCP:
		info.Mode = "TCP"
	case info.UDP:
		info.Mode = "UDP"
	default:
		return nil
	}
	return info
}

// ── main ──

func main() {
	var pt, t, ct int
	flag.IntVar(&flagConcur, "c", 100, "扫描并发数")
	flag.IntVar(&flagPingConcur, "p", 500, "TCPing并发数")
	flag.IntVar(&pt, "pt", 3, "TCPing超时(秒)")
	flag.IntVar(&t, "t", 5, "扫描超时(秒)")
	flag.IntVar(&ct, "ct", 8, "Connect超时(秒)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: turn_scan [参数] <ip_list.txt | ->\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	optPing = time.Duration(pt) * time.Second
	optTimeout = time.Duration(t) * time.Second
	optConn = time.Duration(ct) * time.Second

	// load targets
	var sc *bufio.Scanner
	if flag.Arg(0) == "-" {
		sc = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Println("打开文件失败:", err)
			os.Exit(1)
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	}

	type target struct {
		ip   string
		port int
	}
	var targets []target
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if i := strings.LastIndex(line, ":"); i > 0 {
			p, _ := strconv.Atoi(line[i+1:])
			targets = append(targets, target{line[:i], p})
		} else {
			targets = append(targets, target{line, 3478})
		}
	}
	total := len(targets)

	if addrs, err := net.LookupHost(verifyHost); err != nil || len(addrs) == 0 {
		fmt.Println("解析验证主机失败:", err)
		os.Exit(1)
	} else {
		verifyIP = addrs[0]
	}

	sem := make(chan struct{}, flagConcur)
	pingSem := make(chan struct{}, flagPingConcur)
	var alive, done, allCnt, tcpCnt, udpCnt int64
	var mu sync.Mutex
	results := make([]scanInfo, 0, 64)
	t0 := time.Now()

	printBar := func() {
		n, a := atomic.LoadInt64(&done), atomic.LoadInt64(&alive)
		ac, tc, uc := atomic.LoadInt64(&allCnt), atomic.LoadInt64(&tcpCnt), atomic.LoadInt64(&udpCnt)
		hit := ac + tc + uc
		elapsed := time.Since(t0).Seconds()
		rate := float64(n) / max(elapsed, 0.001)
		pct := int(n * 100 / max(int64(total), 1))
		w := 24
		bar := strings.Repeat("█", w*pct/100) + strings.Repeat("░", w-w*pct/100)
		fmt.Fprintf(os.Stderr, "\r\033[KTURN Scan | [%s] %d%% | %d/%d, Alive=%d, %.0f/s | HIT=%d (A=%d, T=%d, U=%d)",
			bar, pct, n, total, a, rate, hit, ac, tc, uc)
	}

	printHit := func(line string) {
		mu.Lock()
		fmt.Fprintf(os.Stderr, "\r\033[K%s\n", line)
		printBar()
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for _, tgt := range targets {
		wg.Add(1)
		go func(ip string, port int) {
			defer wg.Done()
			info := scanOne(ip, port, sem, pingSem, &alive)
			atomic.AddInt64(&done, 1)
			if info == nil {
				mu.Lock()
				printBar()
				mu.Unlock()
				return
			}

			switch info.Mode {
			case "ALL":
				atomic.AddInt64(&allCnt, 1)
			case "TCP":
				atomic.AddInt64(&tcpCnt, 1)
			case "UDP":
				atomic.AddInt64(&udpCnt, 1)
			}

			auth := "NO_AUTH"
			if !info.NoAuth {
				auth = "WEAK(" + info.Cred + ")"
			}
			sw := info.SW
			if sw == "" {
				sw = "?"
			}
			loc, ipt := "", ""
			if info.Country != "" {
				loc = " " + info.Country
			}
			if info.IPType != "" {
				ipt = " [" + info.IPType + "]"
			}
			printHit(fmt.Sprintf("[+] %-21s %-3s %-24s %s%s%s",
				info.IP+":"+strconv.Itoa(info.Port), info.Mode, sw, auth, loc, ipt))

			mu.Lock()
			results = append(results, *info)
			mu.Unlock()
		}(tgt.ip, tgt.port)
	}
	wg.Wait()

	fmt.Fprintf(os.Stderr, "\r\033[K")
	elapsed := time.Since(t0).Seconds()
	hit := allCnt + tcpCnt + udpCnt
	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Printf("完成: %d 目标, %.1fs, %.0f/s\n", total, elapsed, float64(total)/max(elapsed, 0.001))
	fmt.Printf("  存活: %d, 可用: %d (ALL=%d TCP=%d UDP=%d)\n", alive, hit, allCnt, tcpCnt, udpCnt)

	if len(results) > 0 {
		if out, err := os.Create("turn_results.txt"); err == nil {
			for _, r := range results {
				auth := "NO_AUTH"
				if !r.NoAuth {
					auth = "CRED(" + r.Cred + ")"
				}
				fmt.Fprintf(out, "turn://%s:%d %s %s [%s] %s %s\n",
					r.IP, r.Port, r.Mode, r.Country, r.IPType, auth, r.SW)
			}
			out.Close()
		}
		fmt.Println("结果: turn_results.txt")
		for _, r := range results {
			auth := "无认证"
			if !r.NoAuth {
				auth = r.Cred
			}
			fmt.Printf("  %s:%d %s %s [%s] (%s) [%s]\n",
				r.IP, r.Port, r.Mode, r.Country, r.IPType, auth, r.SW)
		}
	}
}
