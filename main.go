package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
)

//go:embed index.html
var indexHTML []byte

const maxUpload = 64 << 20 // 64 MB; a network device export is a few hundred KB

// verifyTLS is process-wide because it is an operator decision about the whole
// run, not per request. Off by default: ISE ships a self-signed certificate and
// a first migration happens before anyone has replaced it. The UI says so.
var verifyTLS bool

func main() {
	port := flag.Int("port", 8777, "loopback port to listen on")
	open := flag.Bool("open", true, "open the UI in the system browser")
	flag.BoolVar(&verifyTLS, "verify-tls", false, "verify the ISE TLS certificate (off by default: ISE ships a self-signed cert)")
	flag.Parse()

	// Loopback only, always: this UI is unauthenticated and the files it
	// handles contain plaintext RADIUS, SNMP, TrustSec and enable credentials.
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen on %s: %v", addr, err)
	}

	url := "http://" + addr + "/"
	fmt.Println("ise2ise listening on", url)
	if !verifyTLS {
		fmt.Println("TLS certificate verification is OFF for connections to ISE (-verify-tls turns it on)")
	}
	if *open {
		go openBrowser(url)
	}
	log.Fatal(http.Serve(ln, newMux()))
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/translate", handleTranslate)
	mux.HandleFunc("/api/probe", handleProbe)
	mux.HandleFunc("/api/endpoint-groups", handleEndpointGroups)
	mux.HandleFunc("/api/export", handleExport)
	mux.HandleFunc("/api/import/preflight", handlePreflight)
	mux.HandleFunc("/api/import/apply", handleApply)
	return mux
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func handleTranslate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	// maxMemory == the whole body cap, so multipart never spills to a temp
	// file: uploaded credentials must not touch disk.
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		writeErr(w, http.StatusBadRequest, "could not read the upload (max 64 MB): "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	src, err := formFile(r, "source")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tmpl, err := formFile(r, "template")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	out, rep, err := Translate(src, tmpl, r.FormValue("targetNode"))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"report": rep, "csv": string(out)})
}

func formFile(r *http.Request, field string) ([]byte, error) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return nil, fmt.Errorf("missing %s CSV file", field)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxUpload))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", field, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s CSV is empty", field)
	}
	return b, nil
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("could not open a browser (%v); open %s yourself", err, url)
	}
}
