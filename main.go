package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	DsStore "DsStoreInspector/DsStore"
)

type Scanner struct {
	queue        chan string
	processedURL map[string]bool
	lock         sync.Mutex
	workingCount int
	destDir      string
	wg           sync.WaitGroup
	recursive    bool // Yeni eklenen alan
	done         chan struct{}
}

func NewScanner(startURL string, isRecursive bool) *Scanner {
	s := &Scanner{
		queue:        make(chan string, 1000),
		processedURL: make(map[string]bool),
		destDir:      mustAbs("."),
		recursive:    isRecursive,
		done:         make(chan struct{}),
	}
	s.queue <- startURL
	return s
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("Failed to get abs path: %v", err)
	}
	return abs
}

func (s *Scanner) isValidName(entryName string) bool {
	if strings.Contains(entryName, "..") ||
		strings.HasPrefix(entryName, "/") ||
		strings.HasPrefix(entryName, "\\") ||
		!strings.HasPrefix(mustAbs(entryName), s.destDir) {
		log.Printf("[ERROR] Invalid entry name: %s", entryName)
		return false
	}
	return true
}

func (s *Scanner) process() {
	defer s.wg.Done()
	for {
		select {
		case urlStr, ok := <-s.queue:
			if !ok {
				return
			}

			s.lock.Lock()
			if s.processedURL[urlStr] {
				s.lock.Unlock()
				continue
			}
			s.processedURL[urlStr] = true
			s.workingCount++
			s.lock.Unlock()

			s.handleURL(urlStr)

			s.lock.Lock()
			s.workingCount--
			s.lock.Unlock()

		case <-time.After(2 * time.Second):
			s.lock.Lock()
			if s.workingCount == 0 && len(s.queue) == 0 {
				s.lock.Unlock()
				close(s.done)
				return
			}
			s.lock.Unlock()
		}
	}
}

func (s *Scanner) handleURL(urlStr string) {
	if !strings.HasPrefix(strings.ToLower(urlStr), "http") {
		urlStr = "http://" + urlStr
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("[ERROR] URL parse error: %v", err)
		return
	}

	resp, err := http.Get(urlStr)
	if err != nil {
		log.Printf("[ERROR] HTTP get error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] HTTP status not OK: %d %s", resp.StatusCode, urlStr)
		return
	}

	folderName := strings.ReplaceAll(parsed.Host, ":", "_") + filepath.Dir(parsed.Path)
	if folderName != "" && folderName != "." && *download {
		if err := os.MkdirAll(folderName, 0755); err != nil {
			log.Printf("[ERROR] Cannot create dir: %v", err)
			return
		}
	}

	filePath := strings.ReplaceAll(parsed.Host, ":", "_") + parsed.Path
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] Reading response body: %v", err)
		return
	}
	if *download {
		if err := ioutil.WriteFile(filePath, body, 0644); err != nil {
			log.Printf("[ERROR] Writing file: %v", err)
			return
		}
	}

	log.Printf("[%d] %s", resp.StatusCode, urlStr)

	if strings.HasSuffix(urlStr, ".DS_Store") {
		s.processDSStore(bytes.NewReader(body), parsed)
	}
}

func (s *Scanner) processDSStore(data io.Reader, baseURL *url.URL) {
	b, err := io.ReadAll(data)
	if err != nil {
		log.Printf("[ERROR] Read .DS_Store data: %v", err)
		return
	}

	alloc, err := DsStore.NewAllocator(b)
	if err != nil {
		log.Printf("[ERROR] DS_Store allocator: %v", err)
		return
	}

	filenames, err := alloc.TraverseFromRootNode()
	if err != nil {
		log.Printf("[ERROR] TraverseFromRootNode(): %v", err)
		return
	}

	baseURLPath := strings.TrimSuffix(baseURL.String(), ".DS_Store")

	urls := make([]string, 0, len(filenames))

	for _, name := range filenames {
		if !s.isValidName(name) {
			continue
		}

		fullURL := baseURLPath + name
		urls = append(urls, fullURL)

		isDirectory := len(name) <= 4 || !strings.Contains(name, ".")
		if isDirectory {
			if s.recursive {
				dsStoreURL := fullURL
				if !strings.HasSuffix(dsStoreURL, "/") {
					dsStoreURL += "/"
				}
				dsStoreURL += ".DS_Store"
				urls = append(urls, dsStoreURL)
				log.Printf("[INFO] Adding recursive scan for: %s", dsStoreURL)
			}

			if *download {
				folderPath := strings.ReplaceAll(baseURL.Host, ":", "_") + filepath.Dir(baseURL.Path) + "/" + name
				if err := os.MkdirAll(folderPath, 0755); err != nil {
					log.Printf("[ERROR] Cannot create directory: %s - %v", folderPath, err)
				} else {
					log.Printf("[INFO] Created directory: %s", folderPath)
				}
			}
		}
	}

	go func() {
		for _, u := range urls {
			select {
			case s.queue <- u:
			case <-s.done:
				return
			}
		}
	}()
}

func (s *Scanner) Scan() {
	workers := *threadCount
	s.wg.Add(workers)

	for i := 0; i < workers; i++ {
		go s.process()
	}

	// Wait for completion
	<-s.done
	close(s.queue)
	s.wg.Wait()
}

var (
	uri         = flag.String("url", "", "The URL to start scanning from.\nExample: https://www.example.com/.DS_Store")
	download    = flag.Bool("download", false, "Download files to the current directory")
	recursive   = flag.Bool("recursive", false, "Recursively scan for .DS_Store files")
	threadCount = flag.Int("threads", 10, "Number of threads to use for scanning")
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -url https://www.example.com/.DS_Store [options] <url>\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NFlag() == 0 || uri == nil || *uri == "" {
		flag.Usage()
		os.Exit(1)
	}

	scanner := NewScanner(*uri, *recursive)
	scanner.Scan()
}
