package ecs

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

// ModifyPrepayInstanceSpec invokes the ecs.ModifyPrepayInstanceSpec API synchronously
func (client *Client) ModifyPrepayInstanceSpec(request *ModifyPrepayInstanceSpecRequest) (response *ModifyPrepayInstanceSpecResponse, err error) {
	response = CreateModifyPrepayInstanceSpecResponse()
	err = client.DoAction(request, response)
	return
}

// ModifyPrepayInstanceSpecWithChan invokes the ecs.ModifyPrepayInstanceSpec API asynchronously
func (client *Client) ModifyPrepayInstanceSpecWithChan(request *ModifyPrepayInstanceSpecRequest) (<-chan *ModifyPrepayInstanceSpecResponse, <-chan error) {
	responseChan := make(chan *ModifyPrepayInstanceSpecResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.ModifyPrepayInstanceSpec(request)
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

// ModifyPrepayInstanceSpecWithCallback invokes the ecs.ModifyPrepayInstanceSpec API asynchronously
func (client *Client) ModifyPrepayInstanceSpecWithCallback(request *ModifyPrepayInstanceSpecRequest, callback func(response *ModifyPrepayInstanceSpecResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *ModifyPrepayInstanceSpecResponse
		var err error
		defer close(result)
		response, err = client.ModifyPrepayInstanceSpec(request)
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

// ModifyPrepayInstanceSpecRequest is the request struct for api ModifyPrepayInstanceSpec
type ModifyPrepayInstanceSpecRequest struct {
	*requests.RpcRequest
	ResourceOwnerId      requests.Integer                         `position:"Query" name:"ResourceOwnerId"`
	ClientToken          string                                   `position:"Query" name:"ClientToken"`
	CouponNo             string                                   `position:"Query" name:"CouponNo"`
	OperatorType         string                                   `position:"Query" name:"OperatorType"`
	SystemDiskCategory   string                                   `position:"Query" name:"SystemDisk.Category"`
	RebootTime           string                                   `position:"Query" name:"RebootTime"`
	MigrateAcrossZone    requests.Boolean                         `position:"Query" name:"MigrateAcrossZone"`
	InstanceType         string                                   `position:"Query" name:"InstanceType"`
	ModifyMode           string                                   `position:"Query" name:"ModifyMode"`
	AutoPay              requests.Boolean                         `position:"Query" name:"AutoPay"`
	RebootWhenFinished   requests.Boolean                         `position:"Query" name:"RebootWhenFinished"`
	ResourceOwnerAccount string                                   `position:"Query" name:"ResourceOwnerAccount"`
	OwnerAccount         string                                   `position:"Query" name:"OwnerAccount"`
	EndTime              string                                   `position:"Query" name:"EndTime"`
	OwnerId              requests.Integer                         `position:"Query" name:"OwnerId"`
	PromotionOptions     ModifyPrepayInstanceSpecPromotionOptions `position:"Query" name:"PromotionOptions"  type:"Struct"`
	Disk                 *[]ModifyPrepayInstanceSpecDisk          `position:"Query" name:"Disk"  type:"Repeated"`
	InstanceId           string                                   `position:"Query" name:"InstanceId"`
}

// ModifyPrepayInstanceSpecPromotionOptions is a repeated param struct in ModifyPrepayInstanceSpecRequest
type ModifyPrepayInstanceSpecPromotionOptions struct {
	CouponNo string `name:"CouponNo"`
}

// ModifyPrepayInstanceSpecDisk is a repeated param struct in ModifyPrepayInstanceSpecRequest
type ModifyPrepayInstanceSpecDisk struct {
	PerformanceLevel string `name:"PerformanceLevel"`
	DiskId           string `name:"DiskId"`
	Category         string `name:"Category"`
}

// ModifyPrepayInstanceSpecResponse is the response struct for api ModifyPrepayInstanceSpec
type ModifyPrepayInstanceSpecResponse struct {
	*responses.BaseResponse
	OrderId   string `json:"OrderId" xml:"OrderId"`
	RequestId string `json:"RequestId" xml:"RequestId"`
}

// CreateModifyPrepayInstanceSpecRequest creates a request to invoke ModifyPrepayInstanceSpec API
func CreateModifyPrepayInstanceSpecRequest() (request *ModifyPrepayInstanceSpecRequest) {
	request = &ModifyPrepayInstanceSpecRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Ecs", "2014-05-26", "ModifyPrepayInstanceSpec", "ecs", "openAPI")
	request.Method = requests.POST
	return
}

// CreateModifyPrepayInstanceSpecResponse creates a response to parse from ModifyPrepayInstanceSpec response
func CreateModifyPrepayInstanceSpecResponse() (response *ModifyPrepayInstanceSpecResponse) {
	response = &ModifyPrepayInstanceSpecResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
