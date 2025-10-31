package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func handleBasicInfo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	basicInfo, err := pkgutils.CollectBasicInfo(ctx)
	if err != nil {
		RespondWithError(w, fmt.Errorf("failed to collect basic info: %w", err), http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(basicInfo)
}

type BasicInfoHandler struct {
	Mux *http.ServeMux
}

func handleVersion(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	versionMetadata, err := pkgutils.VersionMetadataFromCtx(ctx)
	if err != nil {
		RespondWithError(w, fmt.Errorf("failed to get version metadata from context: %w", err), http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(versionMetadata)
}

func NewBasicInfoHandler(ctx context.Context) *BasicInfoHandler {
	basicInfoHandler := new(BasicInfoHandler)

	basicInfoHandler.Mux = http.NewServeMux()

	basicInfoHandler.Mux.HandleFunc("/basicinfo/version", func(w http.ResponseWriter, r *http.Request) {
		handleVersion(ctx, w, r)
	})

	basicInfoHandler.Mux.HandleFunc("/basicinfo/basicinfo", func(w http.ResponseWriter, r *http.Request) {
		handleBasicInfo(ctx, w, r)
	})

	return basicInfoHandler
}

func (h *BasicInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Mux.ServeHTTP(w, r)
}
