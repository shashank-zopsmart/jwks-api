package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"gofr.dev/pkg/gofr"
	"gofr.dev/pkg/gofr/http/response"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type JWKSService struct {
	ServiceName    string
	ServiceAddress string
	JWKS           []JWK
}

func main() {
	app := gofr.New()

	jwksServices := map[string]*JWKSService{}

	jwksServices["google"] = &JWKSService{ServiceName: "google-jwks-api", ServiceAddress: "https://www.googleapis.com/oauth2/v3/certs", JWKS: make([]JWK, 0)}
	jwksServices["microsoft"] = &JWKSService{ServiceName: "microsoft-jwks-api", ServiceAddress: "https://login.microsoftonline.com/common/discovery/v2.0/keys", JWKS: make([]JWK, 0)}

	for i := range jwksServices {
		app.AddHTTPService(jwksServices[i].ServiceName, jwksServices[i].ServiceAddress)
	}

	jwks := JWKS{}

	app.AddCronJob("* * * * *", "jwks-update", func(ctx *gofr.Context) {
		wg := new(sync.WaitGroup)
		mu := new(sync.Mutex)

		for name, service := range jwksServices {
			wg.Add(1)

			go func(wg *sync.WaitGroup) {
				var err error

				defer wg.Done()

				service.JWKS, err = fetchJWKS(ctx, name, service.ServiceName)
				if err != nil {
					mu.Lock()
					ctx.Logger.Error(err)
					mu.Unlock()
				}
			}(wg)
		}

		wg.Wait()

		jwks.Keys = make([]JWK, 0)

		for _, service := range jwksServices {
			jwks.Keys = append(jwks.Keys, service.JWKS...)
		}
	})

	app.GET("/jwks", func(c *gofr.Context) (interface{}, error) {
		return response.Raw{Data: jwks}, nil
	})

	app.Run()
}

func fetchJWKS(ctx *gofr.Context, jwksServiceName, apiName string) ([]JWK, error) {
	api := ctx.GetHTTPService(apiName)

	resp, err := api.Get(ctx, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s jwks: %v", jwksServiceName, err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response: %v", jwksServiceName, err)
	}

	res := JWKS{}

	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize %s response: %v", jwksServiceName, err)
	}

	return res.Keys, nil
}
