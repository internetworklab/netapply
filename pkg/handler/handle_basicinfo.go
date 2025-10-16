package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func HandleBasicInfo(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	basicInfo, err := pkgutils.CollectBasicInfo(ctx)
	if err != nil {
		RespondWithError(w, fmt.Errorf("failed to collect basic info: %w", err), http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(basicInfo)
}
