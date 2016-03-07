package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

func Connect() {

	const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIFTzCCAzegAwIBAgIRAMaVkHWGu5N5rd6z0yy5C6kwDQYJKoZIhvcNAQELBQAw
QTELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0NvZGVNb2RMYWJzMRwwGgYDVQQDDBND
b2RlTW9kTGFicyBSb290IENBMB4XDTE2MDMwNDIzMDIxNVoXDTI2MDMwMjIzMDIx
NVowQTELMAkGA1UEBhMCVVMxFDASBgNVBAoMC0NvZGVNb2RMYWJzMRwwGgYDVQQD
DBNDb2RlTW9kTGFicyBSb290IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAujmhdugWFEIla+OtajFpt/ZMZmeKlYm7lUB5qd4iQPHLafpFJDRPePHE
fvJu90dFJCjDlTtxJFTeYVJrq3fLYLnpaHDhfP6MKp5CQAiRM5kKhVj+EkaKMAyo
CJbmrQ4CCAzxweIYVus5inKjiCuwfTsKvu4l3LXVwU8t+Zsv4ggJK6x0+fmoPtaQ
NHryMfOzuXnPQwN9YmzATw3495CUe1lekh8y//QFUp6ZfCO5uYk/sfz+A6nGI+Yz
UKAFF037la/muS+1UlMA+W531F/laAv/loT8+WE5rhqRtF7bQcWA1bRSrberoyJ0
9n+LRB4b6T8fV1Mdnp5Ta6DQQ48m7b0c34P1bRcuyrxRnyqHVxMglxaBoXrX+wgp
9GVKWQ39sklB7Y2kheHg75m5qyjFIGF8zWVb789AhQY+f1NRYSBktcBgx+ZVMOPo
r7W6y8mgrdIX93eAYeHH71xXB9vgokv2++XOpHxYbaw/Odyxhf+6fW5I7Dkg7boE
IG/+xQTXPZrR+T58aBHKOcettPmWH0TeXcwD3GLSIueqKj+ep5N7cnKRsOKhEKQB
qOKKv/f4MSHkG8w/mXVxzxrA6xfw6gJ4yFt3GwyeFnWSOpmJjA1f/syBrGYj3Dyo
bVnBFeCJG3U/xfOXLQuXA6b2JW1jww3s6VSfdrtc/zRUucLBIr8CAwEAAaNCMEAw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDOpMDbR
UZ0xu4GjujaQHQNa/kpAMA0GCSqGSIb3DQEBCwUAA4ICAQCY8TVfsIc4NeEpKD7R
n/PPHrBFybdQ6FZFna4RaM/WfGW5cwB1ZG0uKBMS6BCaLB3IiTcCpamWrupWW01Q
qsigk9JY/BZWIEbTmI1VsOBRB529PbIj3G3yqgUou6PGsAUBDUYX5inW++UWYACX
E+9+AlMIVQft5+ncdQCQgT5LMcCNLQYbmDFMNRkHdnstnZ7X9xDLW+bFgjeMY1eq
ffBtrDI1e1nmdLYeqYLXz+n0p1TqZ9dNK7QgkoPGqaafXFMtx1kTuVjlLc5meUTj
SNMeOFFhLjYlIEcujQXpXyF/rk8ZkKa6lJw0Emitq2n2Glg/y3xFwLh0d6OWVfCY
v7/KsJQcGrKjjVgGBUfCu5/5EuP8LY7RMLD7SWoMzRSnYpPWuMd2Cf42fi1GozL+
5gTZrIC9N98+a8v9WvQyZWH6P7g5/HswRhv0rPLIeXDp8ccorievFm/mPwRukbF2
eu0bnhCM8Lis1C+UMxTl8XptgwAFY/x8wO7fAMvAiVCbeVietBnI7jCWPlVJcdTf
vl5WjsixkfEMFG8niYItvZag5SmBUOlrWEyZ71VRnzDst56T+s6V1RqnTYmlPEAQ
DbpbL9Ml93jHtaHFScw9qX3OQLMb3SApmPDCgr1AE/LX1uZdMxtKupwvdXHtw7Ym
ot6grQazZkL24XaOfjMK3sUb3g==
-----END CERTIFICATE-----`

	const subPEM = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	fmt.Println("Connecting to localhost:8080...")

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok_root := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok_root {
		panic("failed to parse root certificate")
	}
	ok_sub := roots.AppendCertsFromPEM([]byte(subPEM))
	if !ok_sub {
		panic("failed to parse sub certificate")
	}

	conn, err := tls.Dial("tcp", "codemodlabs.com:8080", &tls.Config{
		RootCAs: roots,
	})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}

	err = conn.VerifyHostname("codemodlabs.com")
	if err != nil {
		panic("host is not valid for certificates: " + err.Error())
	}

	net_addr := conn.RemoteAddr()
	if net_addr != nil {
		fmt.Println(net_addr.String())
	}

	local_addr := conn.LocalAddr()
	if local_addr != nil {
		fmt.Println(local_addr.String())
	}

	ocsp_resp := conn.OCSPResponse()
	if ocsp_resp != nil {
		fmt.Print(ocsp_resp)
	}

	fmt.Println("Connected and certs valid")
	conn.Close()

}
