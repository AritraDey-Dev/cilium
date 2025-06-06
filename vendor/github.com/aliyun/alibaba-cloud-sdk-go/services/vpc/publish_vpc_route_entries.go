package vpc

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// PublishVpcRouteEntries invokes the vpc.PublishVpcRouteEntries API synchronously
func (client *Client) PublishVpcRouteEntries(request *PublishVpcRouteEntriesRequest) (response *PublishVpcRouteEntriesResponse, err error) {
	response = CreatePublishVpcRouteEntriesResponse()
	err = client.DoAction(request, response)
	return
}

// PublishVpcRouteEntriesWithChan invokes the vpc.PublishVpcRouteEntries API asynchronously
func (client *Client) PublishVpcRouteEntriesWithChan(request *PublishVpcRouteEntriesRequest) (<-chan *PublishVpcRouteEntriesResponse, <-chan error) {
	responseChan := make(chan *PublishVpcRouteEntriesResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.PublishVpcRouteEntries(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// PublishVpcRouteEntriesWithCallback invokes the vpc.PublishVpcRouteEntries API asynchronously
func (client *Client) PublishVpcRouteEntriesWithCallback(request *PublishVpcRouteEntriesRequest, callback func(response *PublishVpcRouteEntriesResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *PublishVpcRouteEntriesResponse
		var err error
		defer close(result)
		response, err = client.PublishVpcRouteEntries(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// PublishVpcRouteEntriesRequest is the request struct for api PublishVpcRouteEntries
type PublishVpcRouteEntriesRequest struct {
	*requests.RpcRequest
	ResourceOwnerId      requests.Integer                      `position:"Query" name:"ResourceOwnerId"`
	TargetType           string                                `position:"Query" name:"TargetType"`
	DryRun               requests.Boolean                      `position:"Query" name:"DryRun"`
	ResourceOwnerAccount string                                `position:"Query" name:"ResourceOwnerAccount"`
	OwnerAccount         string                                `position:"Query" name:"OwnerAccount"`
	OwnerId              requests.Integer                      `position:"Query" name:"OwnerId"`
	TargetInstanceId     string                                `position:"Query" name:"TargetInstanceId"`
	RouteEntries         *[]PublishVpcRouteEntriesRouteEntries `position:"Query" name:"RouteEntries"  type:"Repeated"`
}

// PublishVpcRouteEntriesRouteEntries is a repeated param struct in PublishVpcRouteEntriesRequest
type PublishVpcRouteEntriesRouteEntries struct {
	RouteTableId         string `name:"RouteTableId"`
	DestinationCidrBlock string `name:"DestinationCidrBlock"`
}

// PublishVpcRouteEntriesResponse is the response struct for api PublishVpcRouteEntries
type PublishVpcRouteEntriesResponse struct {
	*responses.BaseResponse
	RequestId string `json:"RequestId" xml:"RequestId"`
}

// CreatePublishVpcRouteEntriesRequest creates a request to invoke PublishVpcRouteEntries API
func CreatePublishVpcRouteEntriesRequest() (request *PublishVpcRouteEntriesRequest) {
	request = &PublishVpcRouteEntriesRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Vpc", "2016-04-28", "PublishVpcRouteEntries", "vpc", "openAPI")
	request.Method = requests.POST
	return
}

// CreatePublishVpcRouteEntriesResponse creates a response to parse from PublishVpcRouteEntries response
func CreatePublishVpcRouteEntriesResponse() (response *PublishVpcRouteEntriesResponse) {
	response = &PublishVpcRouteEntriesResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
