package plugin

import (
	"slices"
	"testing"

	apiv1 "github.com/cloudnative-pg/api/pkg/api/v1"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cluster(params map[string]string) *apiv1.Cluster {
	return &apiv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{Name: "pg", Namespace: "db"},
		Spec: apiv1.ClusterSpec{
			Plugins: []apiv1.PluginConfiguration{{Name: Name, Parameters: params}},
		},
	}
}

func TestFromClusterDefaults(t *testing.T) {
	t.Setenv(SidecarImageEnv, "pgppi:dev")
	cfg, errs := FromCluster(common.NewPlugin(*cluster(nil), Name))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if cfg.Image != "pgppi:dev" || cfg.Port != 15432 || cfg.UserMode != "client" || cfg.Replication != "none" || !cfg.Linkerd {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestFromClusterValidation(t *testing.T) {
	t.Setenv(SidecarImageEnv, "")
	for name, params := range map[string]map[string]string{
		"no image":      {},
		"bad port":      {"image": "x", "port": "abc"},
		"postgres port": {"image": "x", "port": "5432"},
		"linkerd port":  {"image": "x", "port": "4143"},
		"bad user mode": {"image": "x", "userMode": "superuser"},
		"bad linkerd":   {"image": "x", "linkerd": "maybe"},
		"bad repl":      {"image": "x", "allowReplication": "physical"},
		"bad log level": {"image": "x", "logLevel": "trace"},
	} {
		if _, errs := FromCluster(common.NewPlugin(*cluster(params), Name)); len(errs) == 0 {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestMutatePod(t *testing.T) {
	c := cluster(map[string]string{"image": "pgppi:dev", "port": "16000", "allowReplication": "logical"})
	c.Status.Certificates.ClientCASecret = "custom-client-ca"
	cfg, errs := FromCluster(common.NewPlugin(*c, Name))
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "pg-1",
			Annotations: map[string]string{annotationOpaquePorts: "6379"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "postgres"}}},
	}

	out, err := MutatePod(c, pod, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Error("input pod was mutated")
	}

	idx := slices.IndexFunc(out.Spec.Containers, func(c corev1.Container) bool { return c.Name == ContainerName })
	if idx < 0 {
		t.Fatal("sidecar not injected")
	}
	sc := out.Spec.Containers[idx]
	for _, want := range []string{"--listen-port=16000", "--backend-server-name=pg-rw", "--user-mode=client", "--allow-replication=logical"} {
		if !slices.Contains(sc.Args, want) {
			t.Errorf("sidecar args %v missing %q", sc.Args, want)
		}
	}

	secrets := map[string]string{}
	for _, v := range out.Spec.Volumes {
		if v.Secret != nil {
			secrets[v.Name] = v.Secret.SecretName
		}
	}
	if secrets[clientCAVolume] != "custom-client-ca" || secrets[serverCAVolume] != "pg-ca" {
		t.Errorf("CA volumes = %v", secrets)
	}

	for k, want := range map[string]string{
		annotationInject:          "enabled",
		annotationOpaquePorts:     "6379,5432,16000",
		annotationProxyProtocolV2: "16000",
	} {
		if got := out.Annotations[k]; got != want {
			t.Errorf("annotation %s = %q, want %q", k, got, want)
		}
	}

	// Mutation must be idempotent (EVALUATE is called on existing pods).
	again, err := MutatePod(c, out, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Spec.Containers) != len(out.Spec.Containers) || len(again.Spec.Volumes) != len(out.Spec.Volumes) {
		t.Error("mutation is not idempotent")
	}
	if again.Annotations[annotationOpaquePorts] != "6379,5432,16000" {
		t.Errorf("opaque ports not idempotent: %q", again.Annotations[annotationOpaquePorts])
	}
}

func TestMutatePodWithoutLinkerd(t *testing.T) {
	c := cluster(map[string]string{"image": "pgppi:dev", "linkerd": "false"})
	cfg, _ := FromCluster(common.NewPlugin(*c, Name))
	out, err := MutatePod(c, &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "postgres"}}}}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Annotations) != 0 {
		t.Errorf("unexpected annotations %v", out.Annotations)
	}
}
