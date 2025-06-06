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

// ConnectionMonitorsClient contains the methods for the ConnectionMonitors group.
// Don't use this type directly, use NewConnectionMonitorsClient() instead.
type ConnectionMonitorsClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewConnectionMonitorsClient creates a new instance of ConnectionMonitorsClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewConnectionMonitorsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*ConnectionMonitorsClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &ConnectionMonitorsClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// BeginCreateOrUpdate - Create or update a connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group containing Network Watcher.
//   - networkWatcherName - The name of the Network Watcher resource.
//   - connectionMonitorName - The name of the connection monitor.
//   - parameters - Parameters that define the operation to create a connection monitor.
//   - options - ConnectionMonitorsClientBeginCreateOrUpdateOptions contains the optional parameters for the ConnectionMonitorsClient.BeginCreateOrUpdate
//     method.
func (client *ConnectionMonitorsClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, parameters ConnectionMonitor, options *ConnectionMonitorsClientBeginCreateOrUpdateOptions) (*runtime.Poller[ConnectionMonitorsClientCreateOrUpdateResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.createOrUpdate(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, parameters, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[ConnectionMonitorsClientCreateOrUpdateResponse]{
			FinalStateVia: runtime.FinalStateViaAzureAsyncOp,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[ConnectionMonitorsClientCreateOrUpdateResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// CreateOrUpdate - Create or update a connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *ConnectionMonitorsClient) createOrUpdate(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, parameters ConnectionMonitor, options *ConnectionMonitorsClientBeginCreateOrUpdateOptions) (*http.Response, error) {
	var err error
	const operationName = "ConnectionMonitorsClient.BeginCreateOrUpdate"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, parameters, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusCreated) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *ConnectionMonitorsClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, parameters ConnectionMonitor, options *ConnectionMonitorsClientBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors/{connectionMonitorName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
	if connectionMonitorName == "" {
		return nil, errors.New("parameter connectionMonitorName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionMonitorName}", url.PathEscape(connectionMonitorName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	if options != nil && options.Migrate != nil {
		reqQP.Set("migrate", *options.Migrate)
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, parameters); err != nil {
		return nil, err
	}
	return req, nil
}

// BeginDelete - Deletes the specified connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group containing Network Watcher.
//   - networkWatcherName - The name of the Network Watcher resource.
//   - connectionMonitorName - The name of the connection monitor.
//   - options - ConnectionMonitorsClientBeginDeleteOptions contains the optional parameters for the ConnectionMonitorsClient.BeginDelete
//     method.
func (client *ConnectionMonitorsClient) BeginDelete(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, options *ConnectionMonitorsClientBeginDeleteOptions) (*runtime.Poller[ConnectionMonitorsClientDeleteResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.deleteOperation(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[ConnectionMonitorsClientDeleteResponse]{
			FinalStateVia: runtime.FinalStateViaLocation,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[ConnectionMonitorsClientDeleteResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Delete - Deletes the specified connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *ConnectionMonitorsClient) deleteOperation(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, options *ConnectionMonitorsClientBeginDeleteOptions) (*http.Response, error) {
	var err error
	const operationName = "ConnectionMonitorsClient.BeginDelete"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusAccepted, http.StatusNoContent) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *ConnectionMonitorsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, _ *ConnectionMonitorsClientBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors/{connectionMonitorName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
	if connectionMonitorName == "" {
		return nil, errors.New("parameter connectionMonitorName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionMonitorName}", url.PathEscape(connectionMonitorName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// Get - Gets a connection monitor by name.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group containing Network Watcher.
//   - networkWatcherName - The name of the Network Watcher resource.
//   - connectionMonitorName - The name of the connection monitor.
//   - options - ConnectionMonitorsClientGetOptions contains the optional parameters for the ConnectionMonitorsClient.Get method.
func (client *ConnectionMonitorsClient) Get(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, options *ConnectionMonitorsClientGetOptions) (ConnectionMonitorsClientGetResponse, error) {
	var err error
	const operationName = "ConnectionMonitorsClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, options)
	if err != nil {
		return ConnectionMonitorsClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return ConnectionMonitorsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return ConnectionMonitorsClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *ConnectionMonitorsClient) getCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, _ *ConnectionMonitorsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors/{connectionMonitorName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
	if connectionMonitorName == "" {
		return nil, errors.New("parameter connectionMonitorName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionMonitorName}", url.PathEscape(connectionMonitorName))
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
func (client *ConnectionMonitorsClient) getHandleResponse(resp *http.Response) (ConnectionMonitorsClientGetResponse, error) {
	result := ConnectionMonitorsClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.ConnectionMonitorResult); err != nil {
		return ConnectionMonitorsClientGetResponse{}, err
	}
	return result, nil
}

// NewListPager - Lists all connection monitors for the specified Network Watcher.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group containing Network Watcher.
//   - networkWatcherName - The name of the Network Watcher resource.
//   - options - ConnectionMonitorsClientListOptions contains the optional parameters for the ConnectionMonitorsClient.NewListPager
//     method.
func (client *ConnectionMonitorsClient) NewListPager(resourceGroupName string, networkWatcherName string, options *ConnectionMonitorsClientListOptions) *runtime.Pager[ConnectionMonitorsClientListResponse] {
	return runtime.NewPager(runtime.PagingHandler[ConnectionMonitorsClientListResponse]{
		More: func(page ConnectionMonitorsClientListResponse) bool {
			return false
		},
		Fetcher: func(ctx context.Context, page *ConnectionMonitorsClientListResponse) (ConnectionMonitorsClientListResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "ConnectionMonitorsClient.NewListPager")
			req, err := client.listCreateRequest(ctx, resourceGroupName, networkWatcherName, options)
			if err != nil {
				return ConnectionMonitorsClientListResponse{}, err
			}
			resp, err := client.internal.Pipeline().Do(req)
			if err != nil {
				return ConnectionMonitorsClientListResponse{}, err
			}
			if !runtime.HasStatusCode(resp, http.StatusOK) {
				return ConnectionMonitorsClientListResponse{}, runtime.NewResponseError(resp)
			}
			return client.listHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listCreateRequest creates the List request.
func (client *ConnectionMonitorsClient) listCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, _ *ConnectionMonitorsClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
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
func (client *ConnectionMonitorsClient) listHandleResponse(resp *http.Response) (ConnectionMonitorsClientListResponse, error) {
	result := ConnectionMonitorsClientListResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.ConnectionMonitorListResult); err != nil {
		return ConnectionMonitorsClientListResponse{}, err
	}
	return result, nil
}

// BeginStop - Stops the specified connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group containing Network Watcher.
//   - networkWatcherName - The name of the Network Watcher resource.
//   - connectionMonitorName - The name of the connection monitor.
//   - options - ConnectionMonitorsClientBeginStopOptions contains the optional parameters for the ConnectionMonitorsClient.BeginStop
//     method.
func (client *ConnectionMonitorsClient) BeginStop(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, options *ConnectionMonitorsClientBeginStopOptions) (*runtime.Poller[ConnectionMonitorsClientStopResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.stop(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[ConnectionMonitorsClientStopResponse]{
			FinalStateVia: runtime.FinalStateViaLocation,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[ConnectionMonitorsClientStopResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Stop - Stops the specified connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *ConnectionMonitorsClient) stop(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, options *ConnectionMonitorsClientBeginStopOptions) (*http.Response, error) {
	var err error
	const operationName = "ConnectionMonitorsClient.BeginStop"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.stopCreateRequest(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusAccepted) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// stopCreateRequest creates the Stop request.
func (client *ConnectionMonitorsClient) stopCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, _ *ConnectionMonitorsClientBeginStopOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors/{connectionMonitorName}/stop"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
	if connectionMonitorName == "" {
		return nil, errors.New("parameter connectionMonitorName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionMonitorName}", url.PathEscape(connectionMonitorName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// UpdateTags - Update tags of the specified connection monitor.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The name of the resource group.
//   - networkWatcherName - The name of the network watcher.
//   - connectionMonitorName - The name of the connection monitor.
//   - parameters - Parameters supplied to update connection monitor tags.
//   - options - ConnectionMonitorsClientUpdateTagsOptions contains the optional parameters for the ConnectionMonitorsClient.UpdateTags
//     method.
func (client *ConnectionMonitorsClient) UpdateTags(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, parameters TagsObject, options *ConnectionMonitorsClientUpdateTagsOptions) (ConnectionMonitorsClientUpdateTagsResponse, error) {
	var err error
	const operationName = "ConnectionMonitorsClient.UpdateTags"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.updateTagsCreateRequest(ctx, resourceGroupName, networkWatcherName, connectionMonitorName, parameters, options)
	if err != nil {
		return ConnectionMonitorsClientUpdateTagsResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return ConnectionMonitorsClientUpdateTagsResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return ConnectionMonitorsClientUpdateTagsResponse{}, err
	}
	resp, err := client.updateTagsHandleResponse(httpResp)
	return resp, err
}

// updateTagsCreateRequest creates the UpdateTags request.
func (client *ConnectionMonitorsClient) updateTagsCreateRequest(ctx context.Context, resourceGroupName string, networkWatcherName string, connectionMonitorName string, parameters TagsObject, _ *ConnectionMonitorsClientUpdateTagsOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/networkWatchers/{networkWatcherName}/connectionMonitors/{connectionMonitorName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if networkWatcherName == "" {
		return nil, errors.New("parameter networkWatcherName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{networkWatcherName}", url.PathEscape(networkWatcherName))
	if connectionMonitorName == "" {
		return nil, errors.New("parameter connectionMonitorName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{connectionMonitorName}", url.PathEscape(connectionMonitorName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, parameters); err != nil {
		return nil, err
	}
	return req, nil
}

// updateTagsHandleResponse handles the UpdateTags response.
func (client *ConnectionMonitorsClient) updateTagsHandleResponse(resp *http.Response) (ConnectionMonitorsClientUpdateTagsResponse, error) {
	result := ConnectionMonitorsClientUpdateTagsResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.ConnectionMonitorResult); err != nil {
		return ConnectionMonitorsClientUpdateTagsResponse{}, err
	}
	return result, nil
}
