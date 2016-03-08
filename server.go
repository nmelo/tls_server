package main

import (
	"fmt"
	"net"
	"crypto/tls"
	"bytes"
	"encoding/gob"
)

func (d *Security_Header) GobEncode() ([]byte, error) {
	w := new(bytes.Buffer)
	encoder := gob.NewEncoder(w)
	err := encoder.Encode(d.Number)
	if err!=nil {
		return nil, err
	}
	return w.Bytes(), nil
}

func (d *Security_Header) GobDecode(buf []byte) error {
	r := bytes.NewBuffer(buf)
	decoder := gob.NewDecoder(r)
	return decoder.Decode(&d.Number)
}

type Security_Header struct {
	Number  uint16
}

func Listen() {

	const ServerPEM = `
-----BEGIN CERTIFICATE-----
MIIFgTCCA2mgAwIBAgIQaGspJuAtkROyDe6D7YcWiTANBgkqhkiG9w0BAQsFADBA
MQswCQYDVQQGEwJVUzEUMBIGA1UECgwLQ29kZU1vZExhYnMxGzAZBgNVBAMMEkNv
ZGVNb2RMYWJzIFN1YiBDQTAeFw0xNjAzMDUwMDMzNDRaFw0xNzAzMDUwMDMzNDRa
MH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJGTDEUMBIGA1UEChMLQ29kZU1vZExh
YnMxDDAKBgNVBAsTA0RldjEYMBYGA1UEAxMPY29kZW1vZGxhYnMuY29tMSQwIgYJ
KoZIhvcNAQkBFhVubWVsb0Bjb2RlbW9kbGFicy5jb20wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDCaO+K27aVDQ/FWwpkv1yNGacz+n9oRY7yiaTSW/5s
RvvJ9CxBClJMgLsryVmzKtaoE4h12/L1Z+rYQzC22ujFRzVXlqMxbdSRY3H0Gp+e
unK6UQwtHHGZoNfIch9nYEfmDOZM/icetWjP8dFaEIva+AQglv14p8iYsPJW7jl5
H+ZYHMm/Cn/jq2Z5KvsLH3RC0p5mDv1wTgQNx/aHY9Ek3Tik6ivVGn82zHtIxh6O
I/hGEFh79Du+TVjJc75JH3FdJZFxL2jCcuqdtnqkmRw87Lk3fcPv2v54H65YJhdC
EYzEEn2bxotXZNbWlLtuY0xqyR7VFbk1kso5WIUq9I+dAgMBAAGjggE3MIIBMzB5
BggrBgEFBQcBAQRtMGswNAYIKwYBBQUHMAKGKGh0dHA6Ly9zdWItY2EuY29kZW1v
ZGxhYnMuY29tL3N1Yi1jYS5jcnQwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9vY3NwLnN1
Yi1jYS5jb2RlbW9kbGFicy5jb206OTA4MTAfBgNVHSMEGDAWgBS8ntXI9KEH78ms
vOJI3TbtkZz8azAMBgNVHRMBAf8EAjAAMDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6
Ly9zdWItY2EuY29kZW1vZGxhYnMuY29tL3N1Yi1jYS5jcmwwHQYDVR0lBBYwFAYI
KwYBBQUHAwIGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAdBgNVHQ4EFgQU/2hi
fMe8l4qoUKBKCFxMqan2zbAwDQYJKoZIhvcNAQELBQADggIBAIOPQoPkgd70+WyV
QA1FHJcqFPNhDVZZxsmO8FfWm3U+pqMwjEPjA8Nd5NBGHAKjnEyLc+aEYKWa7RJE
z432nMO8wFrSuryqz9LrUT8PLinnPn1ML+1/YZA/s/ipzh8zlajii5uR2jZMJcsW
TesTKGtkEhPAmU2TlPtkwoBRXvJM0hBG115IxqZhJIi1X06yRFvrC+ti3izr97ZW
YfJHAcbiwRkwnz8rtJN3+rX1fmDnCkx0LzLbVUgut63umKM27snRJCkknB0CYcJj
7r1lA37VrXPt/TRIA2aSTEh7JdFQa9B0rhUEKjhK9l/2VzvhIDDtV6NZIB6a59nu
POv5FQiDa3lb0XXBPttoHCfVYnRyesf6st0RstObmQNnPO/CAwOMUn5mfqVjPJtq
39zQ9ECT0eWfuepr8SqLL27nmY3//uZCn0enx5RVC3dLYrT4RMZnX5P2Lefq2nLi
Xn7HkIg3eYjkAGANKCJHaKcTzJ4on439oOj6fUeFwdDVEdQyGyV5I1H0IMwKJGAo
P6i5MRQeqPdOZWnkUorFeFIzW8uLi6vwuwJUL6RGm7hYXOO4ljDPr+ufn24wwx9h
dd1DNPIVf3uujZpc1TvnlrkZg5V2s7AKXkI0/KEdr56tesHJykrywgf9Dx0K1mIp
K7jv3Ygm17ocLFxn0fz0I7aUew0p
-----END CERTIFICATE-----
`

	const ServerKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwmjvitu2lQ0PxVsKZL9cjRmnM/p/aEWO8omk0lv+bEb7yfQs
QQpSTIC7K8lZsyrWqBOIddvy9Wfq2EMwttroxUc1V5ajMW3UkWNx9BqfnrpyulEM
LRxxmaDXyHIfZ2BH5gzmTP4nHrVoz/HRWhCL2vgEIJb9eKfImLDyVu45eR/mWBzJ
vwp/46tmeSr7Cx90QtKeZg79cE4EDcf2h2PRJN04pOor1Rp/Nsx7SMYejiP4RhBY
e/Q7vk1YyXO+SR9xXSWRcS9ownLqnbZ6pJkcPOy5N33D79r+eB+uWCYXQhGMxBJ9
m8aLV2TW1pS7bmNMaske1RW5NZLKOViFKvSPnQIDAQABAoIBAH5gDGctkDCv/vKB
ze3T32vxoxlM2wmDPfs3sqb0Gh10vzR2v1XASeNlQ0ahaufnDwbPO8OxqOwSEz1l
4ALdpranJWu8hnUZOjcQeAEAVYavGOk4yjuA4+/D+MFaPkPK+LH47LRb+j4iGvIh
9b8gRmmfE7/Dpx2JpAJt8/rCfSXYjUrtKqCsfYb9/UOMmjBYVn7h7TapmTnrzBSf
pAPZ3bTgmpZoZaN2TUyk+LBGzHqO0If4ZK7cyzt5xtMgbail4WsNLugoXwv/wked
JF0Pe4Nrm7GQYuWDbIALawf4G2Kw8eLVWG14BO6jRuzznfw677CF3/480wzmxTOU
Ll90gNkCgYEA9gzhpngloklYVN2cdcg1QoZ/xpDISvwMVbo/6t8nIZhoHMeoqqhr
Bg0vfBPLt1Kv/sLv/i5UtGeTUSoaFEsteec8vDVLjGH/1BB5bYHGG2nupuwP9Fpi
W4ng9n12aMF3L8ADB4yC86B0mjdSCPe+72lHY7wsdzRDTyON4REzjaMCgYEAykV4
tbUz1gvmR0J9k5HDXtIWB8Uty8eGThHjvZ0rQxFaXxy0xWD3DJio8m+kYmSMLDyD
iP+aov22tgBXe+hc/QsfwaXxcjrKqcQ/0+FKMkkmGPIY2fG1iFyPiMIvsQiNEVan
eNS4erkELXpQMzED1iQGk7yqnHSyzHhqsBjSwb8CgYEA7XubZEh80nmGV0sak5gs
x8v3khj2KWHDKg89WB4Qr91hR73x7t3lho69cT3OF2Ao3HUcnLHtMb7yspk3WLUC
7LEirumlxJZmDTHlcaubIaSKIvSfpZKDcqTOzDpmSk/JEP58LhIR5sHNKXgRpvQw
hvWPYRUjud5oxP6lF0G6B48CgYBiF0qwpA1dUiv8hswrUlbyluNEJWVOG5aQKbDN
9XhTcAjpcxxfU+S64RWdbHLFnIk1sqr/NyWgwXVn0cabOlZOCKT/3h+3C7fYmGlz
sR+wPzUQh+dxWfx1Ap5A7hr+uWzf6awRtuc37J2QCG74RF7d7F6cKrR6Z0WGTyc9
+uvKNQKBgQDquk6qDnUTi2PszL4tJacUvKQTrwEOLfcHiICePogsbydZUNha3avj
sQxez1ameuF1amZKDPcwxKrW1flWwCbWMy6w86jn0dpAAoTTOgLvVTmnItsigjyS
1IY94FgdvoIS9De484oIeneGGWPreJ3w/jhhNa+iMImdLwllukW9sQ==
-----END RSA PRIVATE KEY-----`

	fmt.Println("Listening localhost:8080...")

	cert, err := tls.X509KeyPair([]byte(ServerPEM), []byte(ServerKey))
	if err != nil {
		panic("failed to parse server certificate: " + err.Error())
	}

	var config = &tls.Config{
		Certificates: []tls.Certificate{cert},
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		MinVersion: tls.VersionTLS12,
		//ClientAuth : tls.RequireAndVerifyClientCert,  // enable to require server side validation of client certs
	}

	ln, err := tls.Listen("tcp", ":8080", config)
	if err != nil {
		panic("error starting server: " + err.Error())
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic("error starting server: " + err.Error())
		}
		go HandleConnection(conn)
	}
}

func HandleConnection(conn net.Conn) {

	defer conn.Close()

	fmt.Println("Handling connection from: " + conn.RemoteAddr().String())
	fmt.Println("Handling connection as: " + conn.LocalAddr().String())

	// Serializing fake security header into gob
	sec_header := Security_Header{Number: 777}
	sec_bytes, err := sec_header.GobEncode()
	if err != nil {
		panic("failed encode sec header: " + err.Error())
	}

	fmt.Println("Sending sec header bytes: ", len(sec_bytes))
	conn.Write(sec_bytes)

	fmt.Println("Closing connection...shutting down server")
}
