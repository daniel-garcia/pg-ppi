package plugin

import (
	"context"

	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/common"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/decoder"
	"github.com/cloudnative-pg/cnpg-i/pkg/identity"
	"github.com/cloudnative-pg/cnpg-i/pkg/operator"
)

// Identity implements the CNPG-I identity service.
type Identity struct {
	identity.UnimplementedIdentityServer
}

// GetPluginMetadata implements identity.IdentityServer.
func (Identity) GetPluginMetadata(context.Context, *identity.GetPluginMetadataRequest) (*identity.GetPluginMetadataResponse, error) {
	return &Metadata, nil
}

// GetPluginCapabilities implements identity.IdentityServer.
func (Identity) GetPluginCapabilities(context.Context, *identity.GetPluginCapabilitiesRequest) (*identity.GetPluginCapabilitiesResponse, error) {
	svc := func(t identity.PluginCapability_Service_Type) *identity.PluginCapability {
		return &identity.PluginCapability{Type: &identity.PluginCapability_Service_{
			Service: &identity.PluginCapability_Service{Type: t},
		}}
	}
	return &identity.GetPluginCapabilitiesResponse{Capabilities: []*identity.PluginCapability{
		svc(identity.PluginCapability_Service_TYPE_LIFECYCLE_SERVICE),
		svc(identity.PluginCapability_Service_TYPE_OPERATOR_SERVICE),
	}}, nil
}

// Probe implements identity.IdentityServer.
func (Identity) Probe(context.Context, *identity.ProbeRequest) (*identity.ProbeResponse, error) {
	return &identity.ProbeResponse{Ready: true}, nil
}

// Operator implements the CNPG-I operator service (Cluster validation).
type Operator struct {
	operator.UnimplementedOperatorServer
}

// GetCapabilities implements operator.OperatorServer.
func (Operator) GetCapabilities(context.Context, *operator.OperatorCapabilitiesRequest) (*operator.OperatorCapabilitiesResult, error) {
	rpc := func(t operator.OperatorCapability_RPC_Type) *operator.OperatorCapability {
		return &operator.OperatorCapability{Type: &operator.OperatorCapability_Rpc{
			Rpc: &operator.OperatorCapability_RPC{Type: t},
		}}
	}
	return &operator.OperatorCapabilitiesResult{Capabilities: []*operator.OperatorCapability{
		rpc(operator.OperatorCapability_RPC_TYPE_VALIDATE_CLUSTER_CREATE),
		rpc(operator.OperatorCapability_RPC_TYPE_VALIDATE_CLUSTER_CHANGE),
	}}, nil
}

// ValidateClusterCreate implements operator.OperatorServer.
func (Operator) ValidateClusterCreate(_ context.Context, req *operator.OperatorValidateClusterCreateRequest) (*operator.OperatorValidateClusterCreateResult, error) {
	cluster, err := decoder.DecodeClusterLenient(req.GetDefinition())
	if err != nil {
		return nil, err
	}
	_, errs := FromCluster(common.NewPlugin(*cluster, Name))
	return &operator.OperatorValidateClusterCreateResult{ValidationErrors: errs}, nil
}

// ValidateClusterChange implements operator.OperatorServer.
func (Operator) ValidateClusterChange(_ context.Context, req *operator.OperatorValidateClusterChangeRequest) (*operator.OperatorValidateClusterChangeResult, error) {
	cluster, err := decoder.DecodeClusterLenient(req.GetNewCluster())
	if err != nil {
		return nil, err
	}
	_, errs := FromCluster(common.NewPlugin(*cluster, Name))
	return &operator.OperatorValidateClusterChangeResult{ValidationErrors: errs}, nil
}
