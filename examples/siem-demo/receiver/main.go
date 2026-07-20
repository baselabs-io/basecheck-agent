package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8787", "HTTP listen address")
	flag.Parse()

	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var events []json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, event := range events {
			var formatted bytes.Buffer
			if err := json.Indent(&formatted, event, "", "  "); err != nil {
				panic(err)
			}
			fmt.Println(formatted.String())
		}
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("Demo receiver listening on http://%s/events\n", *address)
	if err := http.ListenAndServe(*address, nil); err != nil {
		panic(err)
	}
}
