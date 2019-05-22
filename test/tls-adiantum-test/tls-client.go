package main

import (
    "log"
    "crypto/tls"
)

func main() {
    log.SetFlags(log.Lshortfile)

    conf := &tls.Config{
         InsecureSkipVerify: true,
         MaxVersion: tls.VersionTLS12,
         CipherSuites: []uint16{
             tls.TLS_ECDHE_ECDSA_WITH_ADIANTUM_128_SHA256,
         },
    }

    conn, err := tls.Dial("tcp", "127.0.0.1:443", conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    n, err := conn.Write([]byte("hello\n"))
    if err != nil {
        log.Println(n, err)
        return
    }

    buf := make([]byte, 100)
    n, err = conn.Read(buf)
    if err != nil {
        log.Println(n, err)
        return
    }

    println(string(buf[:n]))
}
