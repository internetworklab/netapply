package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"strings"

	uuid "github.com/google/uuid"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
)

type CollectionHandler struct {
	muxer  *http.ServeMux
	client *mongo.Client
}

const dbName = "netapply"

func extractNodeNameFromRequest(r *http.Request) string {
	parts := strings.Split(r.URL.Path, "/")
	nodeName := ""

	// match the pattern /collections/<collection_name>/nodes/<node_name>
	//                    i           i+1               i+2   i+3

	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "collections" && i+3 < len(parts) && parts[i+2] == "nodes" {
			nodeName = parts[i+3]
			break
		}
	}
	return nodeName
}

func extractCollectionNameFromRequest(r *http.Request) string {
	// match the pattern /collections/<collection_name>
	//                    i           i+1
	parts := strings.Split(r.URL.Path, "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "collections" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func generateResourceId(nodeName string, ifname string) string {
	if nodeName != "" {
		return fmt.Sprintf("%s-%s", nodeName, ifname)
	}
	return uuid.New().String()
}

func (ch *CollectionHandler) handleWriteWgCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var wgConfigs []pkginterfacewireguard.WireGuardConfig
	if err := json.NewDecoder(r.Body).Decode(&wgConfigs); err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	nodeName := extractNodeNameFromRequest(r)
	if nodeName != "" {
		for i := range wgConfigs {
			wgConfigs[i].Node = pkgutils.StringPtr(nodeName)
			if wgConfigs[i].ResourceId == nil || *(wgConfigs[i].ResourceId) == "" {
				wgConfigs[i].ResourceId = pkgutils.StringPtr(generateResourceId(nodeName, wgConfigs[i].Name))
			}
		}

	}

	collectionName := extractCollectionNameFromRequest(r)
	coll := ch.client.Database(dbName).Collection(collectionName)

	result, err := coll.InsertMany(ctx, wgConfigs)
	if err != nil {
		RespondWithError(w, err, http.StatusInternalServerError)
		return
	}

	resIds := make([]string, 0)
	for _, resId := range result.InsertedIDs {
		if resId, ok := resId.(bson.ObjectID); ok {
			resIds = append(resIds, resId.Hex())
		}
	}

	respResult := struct {
		InsertedIDs []string `json:"inserted_ids"`
	}{
		InsertedIDs: resIds,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(respResult)
}

func (ch *CollectionHandler) handleReadWgCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	collectionName := extractCollectionNameFromRequest(r)
	coll := ch.client.Database(dbName).Collection(collectionName)

	nodeName := extractNodeNameFromRequest(r)
	filter := bson.D{}
	if nodeName != "" {
		filter = append(filter, bson.E{Key: "node", Value: nodeName})
	}

	cursor, err := coll.Find(context.TODO(), filter)
	if err != nil {
		RespondWithError(w, err, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	result := make([]pkginterfacewireguard.WireGuardConfig, 0)

	for cursor.Next(context.TODO()) {
		var wg pkginterfacewireguard.WireGuardConfig
		err := cursor.Decode(&wg)
		if err != nil {
			RespondWithError(w, err, http.StatusInternalServerError)
			return
		}
		result = append(result, wg)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (ch *CollectionHandler) handleWgCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		ch.handleWriteWgCollection(ctx, w, r)
	} else if r.Method == http.MethodGet {
		ch.handleReadWgCollection(ctx, w, r)
	} else {
		RespondWithError(w, fmt.Errorf("invalid method: %s", r.Method), http.StatusMethodNotAllowed)
	}
}

func NewCollectionHandler(mongoClient *mongo.Client) *CollectionHandler {
	ch := new(CollectionHandler)

	muxer := http.NewServeMux()

	muxer.HandleFunc("/collections/wg/", func(w http.ResponseWriter, r *http.Request) {
		ch.handleWgCollection(context.Background(), w, r)
	})

	ch.muxer = muxer
	ch.client = mongoClient
	return ch
}

func (ch *CollectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ch.muxer.ServeHTTP(w, r)
}
