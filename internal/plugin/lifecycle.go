package plugin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	apiv1 "github.com/cloudnative-pg/api/pkg/api/v1"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/common"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/decoder"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/object"
	"github.com/cloudnative-pg/cnpg-i/pkg/lifecycle"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
)

// Linkerd annotations applied to instance pods.
const (
	annotationInject      = "linkerd.io/inject"
	annotationOpaquePorts = "config.linkerd.io/opaque-ports"
	// Added by linkerd/linkerd2#15676.
	annotationProxyProtocolV2 = "config.linkerd.io/proxy-protocol-v2-inbound-ports"
)

// ContainerName is the name of the injected sidecar container.
const ContainerName = "pgppi"

const (
	clientCAVolume = "pgppi-client-ca"
	serverCAVolume = "pgppi-server-ca"
	clientCAPath   = "/etc/pgppi/client-ca"
	serverCAPath   = "/etc/pgppi/server-ca"
)

// Lifecycle implements the CNPG-I operator lifecycle service: it patches
// instance Pods before the operator creates them.
type Lifecycle struct {
	lifecycle.UnimplementedOperatorLifecycleServer
}

// GetCapabilities implements lifecycle.OperatorLifecycleServer.
func (Lifecycle) GetCapabilities(context.Context, *lifecycle.OperatorLifecycleCapabilitiesRequest) (*lifecycle.OperatorLifecycleCapabilitiesResponse, error) {
	return &lifecycle.OperatorLifecycleCapabilitiesResponse{
		LifecycleCapabilities: []*lifecycle.OperatorLifecycleCapabilities{{
			Group: "",
			Kind:  "Pod",
			OperationTypes: []*lifecycle.OperatorOperationType{
				{Type: lifecycle.OperatorOperationType_TYPE_CREATE},
				// EVALUATE lets the operator compute the expected spec so
				// that it does not see the injected sidecar as drift.
				{Type: lifecycle.OperatorOperationType_TYPE_EVALUATE},
			},
		}},
	}, nil
}

// LifecycleHook implements lifecycle.OperatorLifecycleServer.
func (Lifecycle) LifecycleHook(_ context.Context, req *lifecycle.OperatorLifecycleRequest) (*lifecycle.OperatorLifecycleResponse, error) {
	kind, err := object.GetKind(req.GetObjectDefinition())
	if err != nil {
		return nil, err
	}
	op := req.GetOperationType().GetType()
	if kind != "Pod" || (op != lifecycle.OperatorOperationType_TYPE_CREATE && op != lifecycle.OperatorOperationType_TYPE_EVALUATE) {
		return &lifecycle.OperatorLifecycleResponse{}, nil
	}

	cluster, err := decoder.DecodeClusterLenient(req.GetClusterDefinition())
	if err != nil {
		return nil, err
	}
	helper := common.NewPlugin(*cluster, Name)
	cfg, verrs := FromCluster(helper)
	if len(verrs) > 0 {
		return nil, errors.New(verrs[0].GetMessage())
	}

	pod, err := decoder.DecodePodJSON(req.GetObjectDefinition())
	if err != nil {
		return nil, err
	}
	mutated, err := MutatePod(cluster, pod, cfg)
	if err != nil {
		return nil, err
	}
	patch, err := object.CreatePatch(mutated, pod)
	if err != nil {
		return nil, err
	}
	return &lifecycle.OperatorLifecycleResponse{JsonPatch: patch}, nil
}

// MutatePod returns a copy of pod with the pgppi sidecar, its CA volumes and
// (optionally) the Linkerd annotations added.
func MutatePod(cluster *apiv1.Cluster, pod *corev1.Pod, cfg *Config) (*corev1.Pod, error) {
	out := pod.DeepCopy()

	port := strconv.Itoa(int(cfg.Port))
	sidecar := &corev1.Container{
		Name:  ContainerName,
		Image: cfg.Image,
		Args: []string{
			"proxy",
			"--listen-host=$(POD_IP)",
			"--listen-port=" + port,
			"--backend=127.0.0.1:5432",
			"--backend-server-name=" + cluster.Name + "-rw",
			"--backend-ca=" + serverCAPath + "/ca.crt",
			"--client-ca-cert=" + clientCAPath + "/ca.crt",
			"--client-ca-key=" + clientCAPath + "/ca.key",
			"--user-mode=" + string(cfg.UserMode),
			"--allow-replication=" + string(cfg.Replication),
			"--log-level=" + cfg.LogLevel,
		},
		Env: []corev1.EnvVar{{
			Name: "POD_IP",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"},
			},
		}},
		Ports: []corev1.ContainerPort{{Name: "pgppi", ContainerPort: cfg.Port, Protocol: corev1.ProtocolTCP}},
		VolumeMounts: []corev1.VolumeMount{
			{Name: clientCAVolume, MountPath: clientCAPath, ReadOnly: true},
			{Name: serverCAVolume, MountPath: serverCAPath, ReadOnly: true},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("10m"),
				corev1.ResourceMemory: resource.MustParse("32Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
		// The pod-level securityContext set by CloudNativePG supplies the
		// (non-root) UID and the fsGroup that makes the CA files readable.
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr.To(false),
			ReadOnlyRootFilesystem:   ptr.To(true),
			RunAsNonRoot:             ptr.To(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}
	if err := object.InjectPluginSidecarSpec(&out.Spec, sidecar, false); err != nil {
		return nil, fmt.Errorf("injecting sidecar: %w", err)
	}

	addVolume(&out.Spec, corev1.Volume{
		Name: clientCAVolume,
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  clientCASecret(cluster),
			DefaultMode: ptr.To[int32](0o440),
			Items: []corev1.KeyToPath{
				{Key: "ca.crt", Path: "ca.crt"},
				{Key: "ca.key", Path: "ca.key"},
			},
		}},
	})
	addVolume(&out.Spec, corev1.Volume{
		Name: serverCAVolume,
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName:  serverCASecret(cluster),
			DefaultMode: ptr.To[int32](0o440),
			Items:       []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}},
		}},
	})

	if cfg.Linkerd {
		if out.Annotations == nil {
			out.Annotations = map[string]string{}
		}
		if _, ok := out.Annotations[annotationInject]; !ok {
			out.Annotations[annotationInject] = "enabled"
		}
		// Setting opaque-ports replaces Linkerd's default list, which
		// includes 5432, so keep PostgreSQL's port opaque as well.
		out.Annotations[annotationOpaquePorts] = mergePorts(out.Annotations[annotationOpaquePorts], "5432", port)
		out.Annotations[annotationProxyProtocolV2] = mergePorts(out.Annotations[annotationProxyProtocolV2], port)
	}
	return out, nil
}

func addVolume(spec *corev1.PodSpec, v corev1.Volume) {
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == v.Name {
			spec.Volumes[i] = v
			return
		}
	}
	spec.Volumes = append(spec.Volumes, v)
}

// mergePorts adds ports to a comma-separated Linkerd port list.
func mergePorts(existing string, ports ...string) string {
	var list []string
	for p := range strings.SplitSeq(existing, ",") {
		if p = strings.TrimSpace(p); p != "" {
			list = append(list, p)
		}
	}
	for _, p := range ports {
		if !slices.Contains(list, p) {
			list = append(list, p)
		}
	}
	return strings.Join(list, ",")
}
