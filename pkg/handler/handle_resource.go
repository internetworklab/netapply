package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	pkgmodels "github.com/internetworklab/netapply/pkg/models"
)

type ResourceHandler struct {
	Mux *http.ServeMux
}

const paramKeyDelete = "delete"

func extractDeleteFromRequest(r *http.Request) bool {
	return r.URL.Query().Get(paramKeyDelete) == "true"
}

func handleApplyResource(ctx context.Context, w http.ResponseWriter, r *http.Request) {

	nodeConfig := new(pkgmodels.NodeConfig)

	contentType := r.Header.Get("Content-Type")
	var err error

	if strings.HasPrefix(contentType, "application/yaml") {
		log.Printf("decoding yaml\n")
		err = yaml.NewDecoder(r.Body).Decode(nodeConfig)
	} else if strings.HasPrefix(contentType, "application/json") {
		log.Printf("decoding json\n")
		err = json.NewDecoder(r.Body).Decode(nodeConfig)
	} else {
		log.Printf("decoding json\n")
		err = json.NewDecoder(r.Body).Decode(nodeConfig)
	}

	if err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	if err := nodeConfig.Up(ctx, extractDeleteFromRequest(r)); err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)

}

func NewResourceHandler(ctx context.Context) *ResourceHandler {
	resourceHandler := new(ResourceHandler)

	resourceHandler.Mux = http.NewServeMux()
	resourceHandler.Mux.HandleFunc("/resources/apply", func(w http.ResponseWriter, r *http.Request) {
		handleApplyResource(ctx, w, r)
	})

	return resourceHandler
}

func (h *ResourceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Mux.ServeHTTP(w, r)
}

type ChangSetSummaryItem struct {
	ResourceName      string `json:"resource_name"`
	ResourceType      string `json:"resource_type"`
	ResourceContainer string `json:"resource_container"`
}

type ChangeSetSummary struct {
	Added   []ChangSetSummaryItem `json:"added"`
	Removed []ChangSetSummaryItem `json:"removed"`
	Updated []ChangSetSummaryItem `json:"updated"`
}
