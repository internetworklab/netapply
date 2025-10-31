package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	pkgmodels "github.com/internetworklab/netapply/pkg/models"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
)

type ResourceHandler struct {
	Mux *http.ServeMux
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

	if err := nodeConfig.Up(ctx); err != nil {
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

	resourceHandler.Mux.HandleFunc("/resources/detectchanges", func(w http.ResponseWriter, r *http.Request) {
		handleResourceDetectChanges(ctx, w, r)
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

func handleResourceDetectChanges(ctx context.Context, w http.ResponseWriter, r *http.Request) {
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

	result := new(ChangeSetSummary)

	if nodeConfig.Resources != nil {
		changeSet, err := nodeConfig.Resources.DetectChanges(ctx)
		if err != nil {
			RespondWithError(w, err, http.StatusInternalServerError)
			return
		}

		for _, addedResources := range changeSet.AddedResources {
			for _, addedResource := range addedResources {
				addedItem := ChangSetSummaryItem{
					ResourceName:      addedResource.GetInterfaceName(),
					ResourceType:      addedResource.GetType(),
					ResourceContainer: pkgdocker.GetContainerDisplayName(addedResource.GetContainerName()),
				}
				result.Added = append(result.Added, addedItem)
			}
		}

		for _, removedResources := range changeSet.RemovedResources {
			for _, removedResource := range removedResources {
				removedItem := ChangSetSummaryItem{
					ResourceName:      removedResource.GetInterfaceName(),
					ResourceType:      removedResource.GetType(),
					ResourceContainer: pkgdocker.GetContainerDisplayName(removedResource.GetContainerName()),
				}
				result.Removed = append(result.Removed, removedItem)
			}
		}

		for _, updatedResources := range changeSet.UpdatedResources {
			for _, updatedResource := range updatedResources {
				updatedItem := ChangSetSummaryItem{
					ResourceName:      updatedResource.GetInterfaceName(),
					ResourceType:      updatedResource.GetType(),
					ResourceContainer: pkgdocker.GetContainerDisplayName(updatedResource.GetContainerName()),
				}
				result.Updated = append(result.Updated, updatedItem)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}
