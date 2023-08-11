# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [aggregation.proto](#aggregation-proto)
    - [Aggregation](#isovalent-flow-aggregation-Aggregation)
    - [Aggregator](#isovalent-flow-aggregation-Aggregator)
    - [DirectionStatistics](#isovalent-flow-aggregation-DirectionStatistics)
    - [FlowStatistics](#isovalent-flow-aggregation-FlowStatistics)
  
    - [AggregatorType](#isovalent-flow-aggregation-AggregatorType)
    - [StateChange](#isovalent-flow-aggregation-StateChange)
  
- [Scalar Value Types](#scalar-value-types)



<a name="aggregation-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## aggregation.proto



<a name="isovalent-flow-aggregation-Aggregation"></a>

### Aggregation
Aggregation is a filter to define flow aggregation behavior


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aggregators | [Aggregator](#isovalent-flow-aggregation-Aggregator) | repeated | aggregators is a list of aggregators to apply on flows before returning them. If multiple aggregator are defined, all of them are applied in a row. |
| state_change_filter | [StateChange](#isovalent-flow-aggregation-StateChange) |  | state_change_filter lists the state changes to consider when determing to return an updated flow while aggregating |






<a name="isovalent-flow-aggregation-Aggregator"></a>

### Aggregator
Aggregator is an aggregator configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [AggregatorType](#isovalent-flow-aggregation-AggregatorType) |  |  |
| ignore_source_port | [bool](#bool) |  | Ignore source port during aggregation. |
| ttl | [google.protobuf.Duration](#google-protobuf-Duration) |  | Specify the flow TTL for this aggregator. Defaults to 30 seconds. |
| renew_ttl | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | By default, the flow TTL gets renewed when there is an activity on a given aggregation target (connection or identity). This means that flows do not expire unless they remain inactive for the duration specified in the ttl field. Set this flag to false to expire flows after their initial TTLs regardless of whether there have been subsequent flows on their aggregation targets. |






<a name="isovalent-flow-aggregation-DirectionStatistics"></a>

### DirectionStatistics
DirectionStatistics are flow statistics in a particular direction


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| first_activity | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | first_activity is the timestamp of first activity on the flow |
| last_activity | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | last_activity is the timestamp when activity was last observed |
| num_flows | [uint64](#uint64) |  | num_flows is the number of flows aggregated together |
| bytes | [uint64](#uint64) |  | bytes is the number of bytes observed on the flow |
| errors | [uint64](#uint64) |  | errors is the number of errors observed on the flow, e.g. RSTs or HTTP 4xx 5xx status returns |
| ack_seen | [bool](#bool) |  | ack_seen is true once a TCP ACK has been seen in this direction |
| connection_attempts | [uint64](#uint64) |  | connect_requests is the number of requests for new connections, i.e. the number of SYNs seen |
| close_requests | [uint64](#uint64) |  | close_requests is the number of connection closure requests received, i.e. the number of FINs seen |






<a name="isovalent-flow-aggregation-FlowStatistics"></a>

### FlowStatistics
FlowStatistics includes the statistics for a flow in both directions


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| forward | [DirectionStatistics](#isovalent-flow-aggregation-DirectionStatistics) |  | forward represents flow statistics in the forward direction |
| reply | [DirectionStatistics](#isovalent-flow-aggregation-DirectionStatistics) |  | reply represents flow statistics in the reply direction |
| established | [bool](#bool) |  | established is set to true once the connection/flow is established |





 


<a name="isovalent-flow-aggregation-AggregatorType"></a>

### AggregatorType
AggregatorType are all aggregator types

| Name | Number | Description |
| ---- | ------ | ----------- |
| unknown | 0 |  |
| connection | 1 |  |
| identity | 2 |  |



<a name="isovalent-flow-aggregation-StateChange"></a>

### StateChange


| Name | Number | Description |
| ---- | ------ | ----------- |
| unspec | 0 | unspec represents no change in state |
| new | 1 | new indicates that the flow has been observed for the first time, e.g. for connection aggregation, the first time a 5-tuple &#43; verdict &#43; drop-reason has been observed. |
| established | 2 | established indicates that the connection handshake has been successful, i.e. for TCP this means that the 3-way handshake has been successful. For any non-TCP protocol, the first flow in any direction triggers established state. |
| first_error | 4 | first_error indicates that an error has been observed on the flow for the first time |
| error | 8 | error indicates that the latest flow reported an error condition. For TCP, this indicates that an RST has been observed. For HTTP, this indicates that a 4xx or 5xx status code has been observed. |
| closed | 16 | closed indicates closure of the connection, e.g. a TCP FIN has been seen in both direction. For non-TCP, this state is never triggered. This state is never reached for non-connection aggregation. |
| first_reply | 32 | first_reply indicates that a flow with is_reply set to true has been observed on the flow for the first time. |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

