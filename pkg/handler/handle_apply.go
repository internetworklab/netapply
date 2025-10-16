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

func HandleApply(ctx context.Context, w http.ResponseWriter, r *http.Request) {

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
