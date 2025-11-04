package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	pkgbird "github.com/internetworklab/netapply/pkg/bird"
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

type NodeIdentifiable interface {
	SetNodeAndResourceID(nodeName string) error
	GetResourceID() (string, error)
}

func prepareDocuments(nodeName string, identifiables []NodeIdentifiable) error {
	for i := range identifiables {
		if err := identifiables[i].SetNodeAndResourceID(nodeName); err != nil {
			return err
		}
	}
	return nil
}

func IdentifiablesFromWgConfigs(wgConfigs []pkginterfacewireguard.WireGuardConfig) []NodeIdentifiable {
	identifiables := make([]NodeIdentifiable, 0)
	for i := range wgConfigs {
		identifiables = append(identifiables, &wgConfigs[i])
	}
	return identifiables
}

func IdentifiablesFromBGPConfigs(bgpConfigs []pkgbird.BGPProtocol) []NodeIdentifiable {
	identifiables := make([]NodeIdentifiable, 0)
	for i := range bgpConfigs {
		identifiables = append(identifiables, &bgpConfigs[i])
	}
	return identifiables
}

func (ch *CollectionHandler) handleWriteIdentifiables(ctx context.Context, w http.ResponseWriter, r *http.Request, identifiables []NodeIdentifiable) {
	collectionName := extractCollectionNameFromRequest(r)
	if collectionName == "" {
		RespondWithError(w, fmt.Errorf("collection name is must not be empty"), http.StatusBadRequest)
		return
	}

	nodeName := extractNodeNameFromRequest(r)
	if nodeName == "" {
		RespondWithError(w, fmt.Errorf("node name is must not be empty"), http.StatusBadRequest)
		return
	}

	err := prepareDocuments(nodeName, identifiables)
	if err != nil {
		RespondWithError(w, err, http.StatusBadRequest)
		return
	}

	writeMdls := make([]mongo.WriteModel, 0)
	for i := range identifiables {

		resourceID, err := identifiables[i].GetResourceID()
		if err != nil {
			RespondWithError(w, fmt.Errorf("failed to get resource id: %w", err), http.StatusBadRequest)
			return
		}

		replaceMdl := mongo.NewReplaceOneModel()
		replaceMdl.SetUpsert(true)
		replaceMdl.SetFilter(bson.D{bson.E{Key: "resource_id", Value: resourceID}})
		replaceMdl.SetReplacement(identifiables[i])
		writeMdls = append(writeMdls, replaceMdl)
	}

	coll := ch.client.Database(dbName).Collection(collectionName)
	_, err = coll.BulkWrite(ctx, writeMdls)
	if err != nil {
		RespondWithError(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (ch *CollectionHandler) handleWriteWgCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var wgConfigs []pkginterfacewireguard.WireGuardConfig
	if err := json.NewDecoder(r.Body).Decode(&wgConfigs); err != nil {
		RespondWithError(w, fmt.Errorf("failed to decode request body: %w", err), http.StatusBadRequest)
		return
	}

	ch.handleWriteIdentifiables(ctx, w, r, IdentifiablesFromWgConfigs(wgConfigs))
}

const queryParamIncludeDeleted = "includedeleted"

const keyDeleted = "deleted"
const keyNode = "node"

func applyNodeFilter(filter bson.D, r *http.Request) bson.D {
	nodeName := extractNodeNameFromRequest(r)
	if nodeName != "" {
		return append(filter, bson.E{Key: keyNode, Value: nodeName})
	}
	return filter
}

func applySoftDeletionFilter(filter bson.D, r *http.Request) bson.D {
	if r.URL.Query().Get(queryParamIncludeDeleted) == "" {
		return append(filter, bson.E{
			Key: "$or",
			Value: []bson.M{
				{keyDeleted: false},
				{keyDeleted: bson.M{"$exists": false}},
			},
		})

	}
	return filter
}

func (ch *CollectionHandler) handleReadCollection(ctx context.Context, w http.ResponseWriter, r *http.Request, decoder func(cursor *mongo.Cursor, v interface{}) (interface{}, error)) {
	collectionName := extractCollectionNameFromRequest(r)
	coll := ch.client.Database(dbName).Collection(collectionName)

	filter := bson.D{}

	filter = applyNodeFilter(filter, r)
	filter = applySoftDeletionFilter(filter, r)

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		RespondWithError(w, err, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	result := make([]interface{}, 0)
	for cursor.Next(context.TODO()) {
		elem, err := decoder(cursor, result)
		if err != nil {
			RespondWithError(w, fmt.Errorf("failed to decode element: %w", err), http.StatusBadRequest)
			return
		}
		result = append(result, elem)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func (ch *CollectionHandler) handleReadWireGuardCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ch.handleReadCollection(ctx, w, r, func(cursor *mongo.Cursor, v interface{}) (interface{}, error) {
		var wg pkginterfacewireguard.WireGuardConfig
		err := cursor.Decode(&wg)
		if err != nil {
			return nil, fmt.Errorf("failed to decode wireguard config: %w", err)
		}
		return wg, nil
	})
}

func (ch *CollectionHandler) handleWgCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		ch.handleWriteWgCollection(ctx, w, r)
	} else if r.Method == http.MethodGet {
		ch.handleReadWireGuardCollection(ctx, w, r)
	} else {
		RespondWithError(w, fmt.Errorf("invalid method: %s", r.Method), http.StatusMethodNotAllowed)
	}
}

func (ch *CollectionHandler) handleWriteBGPCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var birdBGPConfigs []pkgbird.BGPProtocol
	if err := json.NewDecoder(r.Body).Decode(&birdBGPConfigs); err != nil {
		RespondWithError(w, fmt.Errorf("failed to decode request body: %w", err), http.StatusBadRequest)
		return
	}

	ch.handleWriteIdentifiables(ctx, w, r, IdentifiablesFromBGPConfigs(birdBGPConfigs))
}

func (ch *CollectionHandler) handleReadBGPCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	ch.handleReadCollection(ctx, w, r, func(cursor *mongo.Cursor, v interface{}) (interface{}, error) {
		var bird pkgbird.BGPProtocol
		err := cursor.Decode(&bird)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bird bgp config: %w", err)
		}
		return bird, nil
	})
}

func (ch *CollectionHandler) handleBirdBGPCollection(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		ch.handleWriteBGPCollection(ctx, w, r)
	} else if r.Method == http.MethodGet {
		ch.handleReadBGPCollection(ctx, w, r)
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
	muxer.HandleFunc("/collections/bgp/", func(w http.ResponseWriter, r *http.Request) {
		ch.handleBirdBGPCollection(context.Background(), w, r)
	})

	ch.muxer = muxer
	ch.client = mongoClient
	return ch
}

func (ch *CollectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ch.muxer.ServeHTTP(w, r)
}
