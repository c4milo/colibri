// The Go routers of colibri's router benchmark: httprouter, chi and net/http's ServeMux. Each
// registers the routes of the table file it is given, then matches every route's path, the given number
// of rounds, and prints the nanoseconds of one match.
//
//	go run . <httprouter|chi|servemux> <routes file> <rounds>
package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/julienschmidt/httprouter"
)

type route struct{ method, path string }

func main() {
	rounds, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	routes := load(os.Args[2])
	var match func(route) bool
	switch os.Args[1] {
	case "httprouter":
		match = httprouterMatch(routes)
	case "chi":
		match = chiMatch(routes)
	case "servemux":
		match = servemuxMatch(routes)
	default:
		panic("unknown router")
	}
	for _, r := range routes {
		if !match(r) {
			panic("no route for " + r.method + " " + r.path)
		}
	}
	start := time.Now()
	found := 0
	for i := 0; i < rounds; i++ {
		for _, r := range routes {
			if match(r) {
				found++
			}
		}
	}
	elapsed := time.Since(start)
	matches := rounds * len(routes)
	fmt.Printf("%s matches=%d found=%d ns_per_match=%.1f\n", os.Args[1], matches, found, float64(elapsed.Nanoseconds())/float64(matches))
}

func load(name string) []route {
	file, err := os.Open(name)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	var routes []route
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		routes = append(routes, route{parts[0], parts[1]})
	}
	return routes
}

func nothing(http.ResponseWriter, *http.Request, httprouter.Params) {}

func httprouterMatch(routes []route) func(route) bool {
	router := httprouter.New()
	for _, r := range routes {
		router.Handle(r.method, r.path, nothing)
	}
	return func(r route) bool {
		handle, params, _ := router.Lookup(r.method, r.path)
		_ = params
		return handle != nil
	}
}

// braces writes a pattern's ":name" segments as "{name}", which chi and ServeMux read.
func braces(path string) string {
	segments := strings.Split(path, "/")
	for i, s := range segments {
		if strings.HasPrefix(s, ":") {
			segments[i] = "{" + s[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

func chiMatch(routes []route) func(route) bool {
	mux := chi.NewRouter()
	empty := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, r := range routes {
		mux.Method(r.method, braces(r.path), empty)
	}
	rctx := chi.NewRouteContext()
	return func(r route) bool {
		rctx.Reset()
		return mux.Match(rctx, r.method, r.path)
	}
}

func servemuxMatch(routes []route) func(route) bool {
	mux := http.NewServeMux()
	empty := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	// Each route's request is built once, outside the timed loop, as a server builds it before it
	// routes. The routes come in the order of `routes`, so a counter names the next one.
	requests := make([]*http.Request, len(routes))
	for i, r := range routes {
		mux.Handle(r.method+" "+braces(r.path), empty)
		request, err := http.NewRequestWithContext(context.Background(), r.method, r.path, nil)
		if err != nil {
			panic(err)
		}
		requests[i] = request
	}
	next := 0
	return func(route) bool {
		request := requests[next]
		next = (next + 1) % len(requests)
		_, pattern := mux.Handler(request)
		return pattern != ""
	}
}
