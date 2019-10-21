package main

import (
	"log"
	"net"
	"os"
	"io"
	"strings"
	"time"
)

const (
	BUF_SIZE = 1024
	OPEN_FLAG = os.O_CREATE|os.O_APPEND|os.O_WRONLY
	UNIX_SOCK = "/tmp/go-unix.sock"
	LOG_FILE_NAME = "log.out"
)

func logWriter(msgChan <-chan string) {

	file, err := os.OpenFile(LOG_FILE_NAME, OPEN_FLAG, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	getTimeStamp := func() (stamp string) {
		/* https://stackoverflow.com/questions/5885486/how-do-i-get-the-current-timestamp-in-go */
		stamp = time.Now().Format("[2006/01/02 15:04:05]")
		return
	}

	/* Read message channel from clientHandler thread forever.*/
	for msg := range msgChan {

		sentences := strings.Split(msg, "\n");

		for _, sentence := range sentences {
			if len(sentence) == 0 {
				continue
			}
			file.Write([]byte(getTimeStamp() + sentence + "\n"))
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func clientHandler(conn net.Conn, msgChan chan<- string) {

	defer conn.Close()
	bufRecv := make([]byte, BUF_SIZE)

	/* Read message from client until EOF.*/
	for {
		n, err := conn.Read(bufRecv)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Fatal(err);
		}

		/* Send message to logWriter thread. */
		if n > 0 {
			msgChan <- string(bufRecv[:n])
		}
	}
}

func main() {

	/* Delete unix-domain-socket if exists. */
	if err := os.Remove(UNIX_SOCK); err != nil {
		log.Println(err)
	}
	log.Println("Listening ... [", UNIX_SOCK, "]");

	/* Create unix-domain-socket. */
	l, err := net.Listen("unix", UNIX_SOCK)
	if err != nil {
		log.Fatal("Listen() err:", err)
	}
	defer l.Close()

	/* Channel for client's logging message.*/
	msgChan := make(chan string, BUF_SIZE)

	/* Start Writer thread */
	go logWriter(msgChan)

	/* Start accepting clients */
	for {
		log.Println("Accepting ...")
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Accept() err:", err)
		}
		go clientHandler(conn, msgChan)
	}
}
