package main

import (
	"fmt"
	"errors"
	"encoding/json"
	"net/http"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
)

var priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}
var store = make(map[string][]clair.Vulnerability)

type Query struct {
	ClairAddress string
  ImageName string
	DockerUser string
	DockerPassword string
	ClairThreshold int
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	query, err := decodeQuery(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	err = run(w, query)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
}

func decodeQuery(w http.ResponseWriter, r* http.Request) (Query, error) {
  var query Query;

	if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
		return query, err
	}

	if len(query.ImageName) == 0 {
		err := errors.New("ImageName has to be provided")
		return query, err
	}

	return query, nil
}

func run(w http.ResponseWriter, query Query) error {
	clairAddr := query.ClairAddress;
	if clairAddr == "" {
		return errors.New("Clair address must be provided")
	}

	dockerUser := query.DockerUser
	dockerPassword := query.DockerPassword

	image, err := docker.NewImage(query.ImageName, dockerUser, dockerPassword)
	if err != nil {
		return errors.New(fmt.Sprintf("Can't parse qname: %s", err))
	}

	imageName := image.Name
	imageTag := image.Tag

	err = image.Pull()
	if err != nil {
		return errors.New(fmt.Sprintf("Can't pull image: %s", err))
	}
	if len(image.FsLayers) == 0 {
		return errors.New(fmt.Sprintf("Can't pull fsLayers"))
	} else {
		fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
	}

	// The following two lines is a workaround for a problem in Google Container 
	// Registry https://issuetracker.google.com/issues/37265047
	image.Name = imageName
	image.Tag = imageTag

	c := clair.NewClair(clairAddr)
	vs := c.Analyse(image)

	json, err := json.Marshal(vs)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)

	return nil
}

func iteratePriorities(f func(sev string)) {
	for _, sev := range priorities {
		if len(store[sev]) != 0 {
			f(sev)
		}
	}

}

func groupBySeverity(vs []clair.Vulnerability) {
	for _, v := range vs {
		sevRow := vulnsBy(v.Severity, store)
		store[v.Severity] = append(sevRow, v)
	}
}

func vulnsBy(sev string, store map[string][]clair.Vulnerability) []clair.Vulnerability {
	items, found := store[sev]
	if !found {
		items = make([]clair.Vulnerability, 0)
		store[sev] = items
	}
	return items
}
