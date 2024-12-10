package routes

import "net/http"

const (
	idpSSOPath = "templates/idp_sso.html"
)

func IDPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/idp/sso", ssoHandler)
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, idpSSOPath)
}
