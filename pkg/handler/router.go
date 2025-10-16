package handler

import (
	"context"
	"net/http"
)

type RouterHandler struct {
	Mux *http.ServeMux
}

func NewRouterHandler(ctx context.Context) *RouterHandler {
	routerHandler := new(RouterHandler)

	routerHandler.Mux = http.NewServeMux()
	routerHandler.Mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		HandleApply(ctx, w, r)
	})

	routerHandler.Mux.HandleFunc("/detectchanges", func(w http.ResponseWriter, r *http.Request) {
		HandleDetectChanges(ctx, w, r)
	})

	return routerHandler
}

func (h *RouterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// todo
}
