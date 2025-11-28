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

func getNodeConfigFromRequest(r *http.Request) (*pkgmodels.NodeConfig, error) {
	nodeConfig := new(pkgmodels.NodeConfig)
	contentType := r.Header.Get("Content-Type")
	var err error
	if strings.HasPrefix(contentType, "application/yaml") {
		err = yaml.NewDecoder(r.Body).Decode(nodeConfig)
	} else if strings.HasPrefix(contentType, "application/json") {
		err = json.NewDecoder(r.Body).Decode(nodeConfig)
	} else {
		err = json.NewDecoder(r.Body).Decode(nodeConfig)
	}
	return nodeConfig, err
}

type ReconvergeStatus struct {
	Converged bool   `json:"converged"`
	Error     string `json:"error"`
}

func handleApplyResource(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	nodeConfig, err := getNodeConfigFromRequest(r)
	if err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	converged, err := nodeConfig.Up(ctx, extractDeleteFromRequest(r))
	reconvergeStatus := ReconvergeStatus{
		Converged: converged,
		Error:     err.Error(),
	}
	if err := json.NewEncoder(w).Encode(reconvergeStatus); err != nil {
		log.Println("Failed to encode reconverge status:", err)
	}
}

func handleGetResourceStatus(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	nodeConfig, err := getNodeConfigFromRequest(r)
	if err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	statuses, err := nodeConfig.ToStatus(ctx)
	if err != nil {
		RespondWithError(w, err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(statuses)
}

func NewResourceHandler(ctx context.Context) *ResourceHandler {
	resourceHandler := new(ResourceHandler)

	resourceHandler.Mux = http.NewServeMux()
	resourceHandler.Mux.HandleFunc("/resources/apply", func(w http.ResponseWriter, r *http.Request) {
		handleApplyResource(ctx, w, r)
	})
	resourceHandler.Mux.HandleFunc("/resources/status", func(w http.ResponseWriter, r *http.Request) {
		handleGetResourceStatus(ctx, w, r)
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
