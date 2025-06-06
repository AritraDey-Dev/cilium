// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetwork

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// WebCategoriesClient contains the methods for the WebCategories group.
// Don't use this type directly, use NewWebCategoriesClient() instead.
type WebCategoriesClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewWebCategoriesClient creates a new instance of WebCategoriesClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewWebCategoriesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*WebCategoriesClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &WebCategoriesClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// Get - Gets the specified Azure Web Category.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - name - The name of the azureWebCategory.
//   - options - WebCategoriesClientGetOptions contains the optional parameters for the WebCategoriesClient.Get method.
func (client *WebCategoriesClient) Get(ctx context.Context, name string, options *WebCategoriesClientGetOptions) (WebCategoriesClientGetResponse, error) {
	var err error
	const operationName = "WebCategoriesClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, name, options)
	if err != nil {
		return WebCategoriesClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return WebCategoriesClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return WebCategoriesClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *WebCategoriesClient) getCreateRequest(ctx context.Context, name string, options *WebCategoriesClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Network/azureWebCategories/{name}"
	if name == "" {
		return nil, errors.New("parameter name cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{name}", url.PathEscape(name))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.Expand != nil {
		reqQP.Set("$expand", *options.Expand)
	}
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *WebCategoriesClient) getHandleResponse(resp *http.Response) (WebCategoriesClientGetResponse, error) {
	result := WebCategoriesClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureWebCategory); err != nil {
		return WebCategoriesClientGetResponse{}, err
	}
	return result, nil
}

// NewListBySubscriptionPager - Gets all the Azure Web Categories in a subscription.
//
// Generated from API version 2024-07-01
//   - options - WebCategoriesClientListBySubscriptionOptions contains the optional parameters for the WebCategoriesClient.NewListBySubscriptionPager
//     method.
func (client *WebCategoriesClient) NewListBySubscriptionPager(options *WebCategoriesClientListBySubscriptionOptions) *runtime.Pager[WebCategoriesClientListBySubscriptionResponse] {
	return runtime.NewPager(runtime.PagingHandler[WebCategoriesClientListBySubscriptionResponse]{
		More: func(page WebCategoriesClientListBySubscriptionResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *WebCategoriesClientListBySubscriptionResponse) (WebCategoriesClientListBySubscriptionResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "WebCategoriesClient.NewListBySubscriptionPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listBySubscriptionCreateRequest(ctx, options)
			}, nil)
			if err != nil {
				return WebCategoriesClientListBySubscriptionResponse{}, err
			}
			return client.listBySubscriptionHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listBySubscriptionCreateRequest creates the ListBySubscription request.
func (client *WebCategoriesClient) listBySubscriptionCreateRequest(ctx context.Context, _ *WebCategoriesClientListBySubscriptionOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Network/azureWebCategories"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listBySubscriptionHandleResponse handles the ListBySubscription response.
func (client *WebCategoriesClient) listBySubscriptionHandleResponse(resp *http.Response) (WebCategoriesClientListBySubscriptionResponse, error) {
	result := WebCategoriesClientListBySubscriptionResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureWebCategoryListResult); err != nil {
		return WebCategoriesClientListBySubscriptionResponse{}, err
	}
	return result, nil
}
