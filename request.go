package agollo

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

var ErrorStatusNotOK = errors.New("http resp code not ok")

// this is a static check
var _ requester = (*httpRequester)(nil)
var _ requester = (*httpSignRequester)(nil)

type requester interface {
	request(url string) ([]byte, error)
}

type httpRequester struct {
	client  *http.Client
	retries int
}

func newHTTPRequester(client *http.Client, retries int) requester {
	return &httpRequester{
		client:  client,
		retries: retries,
	}
}

func (r *httpRequester) request(url string) ([]byte, error) {
	return r.requestWithRetry(url, r.retries)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func (r *httpRequester) requestWithRetry(url string, retries int) ([]byte, error) {
	//logger := NewLogger()

	//logger.Infof("httpRequester requestWithRetry %s", url)

	resp, err := r.client.Get(url)
	if err != nil {
		if retries > 0 {
			return r.requestWithRetry(url, retries-1)
		}
		return nil, err
	}
	defer resp.Body.Close()

	// 循环打印 Header
	//for key, values := range resp.Header {
	//	logger.Infof("httpRequester Header: %s: %s", key, strings.Join(values, ", "))
	//}

	// if encrypted, decrypt
	if resp.Header.Get("APOLLO_SECRET_KEY") == "true" || resp.Header.Get("HTX_CRYPTO_ENABLE") == "true" || resp.Header.Get("HEADER_ENCRYPT_FLAG") == "true" {

		//logger.Infof("requestWithRetry CRYPTO ENABLED")

		body, err := io.ReadAll(resp.Body)

		SecretKeyA := os.Getenv("APOLLO_SECRET_KEY")
		SecretKeyB := os.Getenv("ApolloPrivateKey")

		SecretKey := ""
		// Check which secret key is not empty
		if SecretKeyA != "" {
			SecretKey = SecretKeyA
		} else if SecretKeyB != "" {
			SecretKey = SecretKeyB
		} else {
			return nil, errors.New("secretKey are Empty")
		}

		raw, err := base64.RawStdEncoding.DecodeString(SecretKey)
		if err != nil {
			return nil, err
		}

		sk, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, err
		}

		privKey := sk.(*rsa.PrivateKey)
		partLen := privKey.PublicKey.N.BitLen() / 8
		chunks := split(body, partLen)
		buffer := bytes.NewBufferString("")
		for _, chunk := range chunks {
			decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, chunk)
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypted)
		}
		//logger.Infof("requestWithRetry Decode %s", string(buffer.Bytes()))
		return buffer.Bytes(), nil
	} else {
		if resp.StatusCode == http.StatusOK {
			return ioutil.ReadAll(resp.Body)
		}

		// Discard all body if status code is not 200
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		return nil, fmt.Errorf("apollo return http resp code %d", resp.StatusCode)
	}
}

type httpSignRequester struct {
	signature *signature
	client    *http.Client
	retries   int
}

func newHttpSignRequester(signature *signature, client *http.Client, retries int) requester {
	return &httpSignRequester{
		signature: signature,
		client:    client,
		retries:   retries,
	}
}

func (r *httpSignRequester) request(url string) ([]byte, error) {
	return r.requestWithRetry(url, r.retries)
}

func (r *httpSignRequester) requestWithRetry(url string, retries int) ([]byte, error) {
	//logger := NewLogger()
	//logger.Infof("httpSignRequester requestWithRetry %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	timestamp := r.signature.getTimestamp()
	req.Header.Set(signHttpHeaderAuthorization, fmt.Sprintf(
		signAuthorizationFormat,
		r.signature.AppID,
		r.signature.getAuthorization(url, timestamp),
	))
	req.Header.Set(signHttpHeaderTimestamp, timestamp)

	resp, err := r.client.Do(req)
	if err != nil {
		if retries > 0 {
			return r.requestWithRetry(url, retries-1)
		}
		return nil, err
	}
	defer resp.Body.Close()

	// 循环打印 Header
	//for key, values := range resp.Header {
	//	logger.Infof("httpSignRequester Header: %s: %s", key, strings.Join(values, ", "))
	//}

	// if encrypted, decrypt
	if resp.Header.Get("APOLLO_SECRET_KEY") == "true" || resp.Header.Get("HTX_CRYPTO_ENABLE") == "true" || resp.Header.Get("HEADER_ENCRYPT_FLAG") == "true" {

		//logger.Infof("httpSignRequester requestWithRetry CRYPTO ENABLED")

		body, err := io.ReadAll(resp.Body)

		SecretKeyA := os.Getenv("APOLLO_SECRET_KEY")
		SecretKeyB := os.Getenv("ApolloPrivateKey")

		SecretKey := ""
		// Check which secret key is not empty
		if SecretKeyA != "" {
			SecretKey = SecretKeyA
		} else if SecretKeyB != "" {
			SecretKey = SecretKeyB
		} else {
			return nil, errors.New("secretKey are Empty")
		}

		raw, err := base64.RawStdEncoding.DecodeString(SecretKey)
		if err != nil {
			return nil, err
		}

		sk, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return nil, err
		}

		privKey := sk.(*rsa.PrivateKey)
		partLen := privKey.PublicKey.N.BitLen() / 8
		chunks := split(body, partLen)
		buffer := bytes.NewBufferString("")
		for _, chunk := range chunks {
			decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, chunk)
			if err != nil {
				return nil, err
			}
			buffer.Write(decrypted)
		}
		//logger.Infof("httpSignRequester requestWithRetry Decode %s", string(buffer.Bytes()))
		return buffer.Bytes(), nil
	} else {
		if resp.StatusCode == http.StatusOK {
			return ioutil.ReadAll(resp.Body)
		}

		// Discard all body if status code is not 200
		_, _ = io.Copy(ioutil.Discard, resp.Body)
		return nil, fmt.Errorf("apollo return http resp code %d", resp.StatusCode)
	}
}
