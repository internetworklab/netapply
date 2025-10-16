package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func HandleVersion(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	versionMetadata, err := pkgutils.VersionMetadataFromCtx(ctx)
	if err != nil {
		RespondWithError(w, fmt.Errorf("failed to get version metadata from context: %w", err), http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(versionMetadata)
}
