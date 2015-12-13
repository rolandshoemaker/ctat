package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	ct "github.com/jsha/certificatetransparency"
)

func main() {
	logURL := flag.String("logURL", "https://log.certly.io", "url of remote CT log to use")
	logKey := flag.String("logKey", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==", "base64-encoded CT log key")
	filename := flag.String("cacheFile", "certly.log", "file in which to cache log data.")
	flag.Parse()

	pemPublicKey := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, *logKey)
	ctLog, err := ct.NewLog(*logURL, pemPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create CT log client: %s\n", err)
		os.Exit(1)
	}

	file, err := os.OpenFile(*filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create/read cache file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	entriesFile := ct.EntriesFile{file}

	sth, err := ctLog.GetSignedTreeHead()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get log STH %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Counting entries in local cache...")
	count, err := entriesFile.Count()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to count entries in cache file: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("local entries: %d, remote entries: %d at %s\n", count, sth.Size, sth.Time.Format(time.ANSIC))
	if count < sth.Size {
		fmt.Println("updating local cache...")
		statusChan := make(chan ct.OperationStatus)
		go func() {
			status, ok := <-statusChan
			if !ok {
				return
			}
			started := time.Now()
			for {
				status, ok = <-statusChan
				if !ok {
					return
				}
				fmt.Printf("\x1b[80D\x1b[2K")
				eps := float64(status.Current) / time.Since(started).Seconds()
				remaining := status.Length - status.Current
				fmt.Printf("%.2f%% (%d remaining, eta: %s)", status.Percentage(), remaining, time.Second*time.Duration(float64(remaining)/eps))
				time.Sleep(250 * time.Millisecond)
			}
		}()
		_, err = ctLog.DownloadRange(file, statusChan, count, sth.Size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to downlad new log entries: %s\n", err)
			os.Exit(1)
		}
	}
}
