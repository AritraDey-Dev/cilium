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

// LoadBalancerFrontendIPConfigurationsClient contains the methods for the LoadBalancerFrontendIPConfigurations group.
// Don't use this type directly, use NewLoadBalancerFrontendIPConfigurationsClient() instead.
type LoadBalancerFrontendIPConfigurationsClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewLoadBalancerFrontendIPConfigurationsClient creates a new instance of LoadBalancerFrontendIPConfigurationsClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewLoadBalancerFrontendIPConfigurationsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*LoadBalancerFrontendIPConfigurationsClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &LoadBalancerFrontendIPConfigurationsClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// Get - Gets load balancer frontend IP configuration.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - loadBalancerName - The name of the load balancer.
//   - frontendIPConfigurationName - The name of the frontend IP configuration.
//   - options - LoadBalancerFrontendIPConfigurationsClientGetOptions contains the optional parameters for the LoadBalancerFrontendIPConfigurationsClient.Get
//     method.
func (client *LoadBalancerFrontendIPConfigurationsClient) Get(ctx context.Context, resourceGroupName string, loadBalancerName string, frontendIPConfigurationName string, options *LoadBalancerFrontendIPConfigurationsClientGetOptions) (LoadBalancerFrontendIPConfigurationsClientGetResponse, error) {
	var err error
	const operationName = "LoadBalancerFrontendIPConfigurationsClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, loadBalancerName, frontendIPConfigurationName, options)
	if err != nil {
		return LoadBalancerFrontendIPConfigurationsClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return LoadBalancerFrontendIPConfigurationsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return LoadBalancerFrontendIPConfigurationsClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *LoadBalancerFrontendIPConfigurationsClient) getCreateRequest(ctx context.Context, resourceGroupName string, loadBalancerName string, frontendIPConfigurationName string, _ *LoadBalancerFrontendIPConfigurationsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/loadBalancers/{loadBalancerName}/frontendIPConfigurations/{frontendIPConfigurationName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if loadBalancerName == "" {
		return nil, errors.New("parameter loadBalancerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{loadBalancerName}", url.PathEscape(loadBalancerName))
	if frontendIPConfigurationName == "" {
		return nil, errors.New("parameter frontendIPConfigurationName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{frontendIPConfigurationName}", url.PathEscape(frontendIPConfigurationName))
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

// getHandleResponse handles the Get response.
func (client *LoadBalancerFrontendIPConfigurationsClient) getHandleResponse(resp *http.Response) (LoadBalancerFrontendIPConfigurationsClientGetResponse, error) {
	result := LoadBalancerFrontendIPConfigurationsClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.FrontendIPConfiguration); err != nil {
		return LoadBalancerFrontendIPConfigurationsClientGetResponse{}, err
	}
	return result, nil
}

// NewListPager - Gets all the load balancer frontend IP configurations.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - loadBalancerName - The name of the load balancer.
//   - options - LoadBalancerFrontendIPConfigurationsClientListOptions contains the optional parameters for the LoadBalancerFrontendIPConfigurationsClient.NewListPager
//     method.
func (client *LoadBalancerFrontendIPConfigurationsClient) NewListPager(resourceGroupName string, loadBalancerName string, options *LoadBalancerFrontendIPConfigurationsClientListOptions) *runtime.Pager[LoadBalancerFrontendIPConfigurationsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[LoadBalancerFrontendIPConfigurationsClientListResponse]{
		More: func(page LoadBalancerFrontendIPConfigurationsClientListResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *LoadBalancerFrontendIPConfigurationsClientListResponse) (LoadBalancerFrontendIPConfigurationsClientListResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "LoadBalancerFrontendIPConfigurationsClient.NewListPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listCreateRequest(ctx, resourceGroupName, loadBalancerName, options)
			}, nil)
			if err != nil {
				return LoadBalancerFrontendIPConfigurationsClientListResponse{}, err
			}
			return client.listHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listCreateRequest creates the List request.
func (client *LoadBalancerFrontendIPConfigurationsClient) listCreateRequest(ctx context.Context, resourceGroupName string, loadBalancerName string, _ *LoadBalancerFrontendIPConfigurationsClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/loadBalancers/{loadBalancerName}/frontendIPConfigurations"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if loadBalancerName == "" {
		return nil, errors.New("parameter loadBalancerName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{loadBalancerName}", url.PathEscape(loadBalancerName))
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

// listHandleResponse handles the List response.
func (client *LoadBalancerFrontendIPConfigurationsClient) listHandleResponse(resp *http.Response) (LoadBalancerFrontendIPConfigurationsClientListResponse, error) {
	result := LoadBalancerFrontendIPConfigurationsClientListResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.LoadBalancerFrontendIPConfigurationListResult); err != nil {
		return LoadBalancerFrontendIPConfigurationsClientListResponse{}, err
	}
	return result, nil
}
