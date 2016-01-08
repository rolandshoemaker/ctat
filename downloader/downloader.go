package downloader

import (
	"fmt"
	"os"
	"time"

	ct "github.com/rolandshoemaker/certificatetransparency"
)

func Download(logURL, logKey, cacheFilename string) error {
	pemPublicKey := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, logKey)
	ctLog, err := ct.NewLog(logURL, pemPublicKey)
	if err != nil {
		return fmt.Errorf("Failed to create CT log client: %s", err)
	}

	file, err := os.OpenFile(cacheFilename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("Failed to create/read cache file: %s\n", err)
	}
	defer file.Close()

	entriesFile := ct.EntriesFile{File: file}

	sth, err := ctLog.GetSignedTreeHead()
	if err != nil {
		return fmt.Errorf("Failed to get log STH %s\n", err)
	}

	fmt.Println("counting entries in local cache...")
	count, err := entriesFile.Count()
	if err != nil {
		return fmt.Errorf("Failed to count entries in cache file: %s\n", err)
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
			startCount := count
			for {
				status, ok = <-statusChan
				if !ok {
					return
				}
				fmt.Printf("\x1b[80D\x1b[2K")
				eps := float64(status.Current-startCount) / time.Since(started).Seconds()
				remaining := status.Length - status.Current
				fmt.Printf("%.2f%% (%d remaining, eta: %s)", status.Percentage(), remaining, time.Second*time.Duration(float64(remaining)/eps))
				time.Sleep(250 * time.Millisecond)
			}
		}()
		_, err = ctLog.DownloadRange(file, statusChan, count, sth.Size)
		if err != nil {
			return fmt.Errorf("Failed to downlad new log entries: %s\n", err)
		}
	}

	return nil
}
