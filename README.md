[![Build Status](https://travis-ci.org/ocadotechnology/mirror-operator.svg?branch=master)](https://travis-ci.org/ocadotechnology/mirror-operator)

# mirror-operator
A python module + resulting docker image which listens for registry mirror requests and creates resources for that mirror.
If you're confused what an operator is, [this blog post][operators] will give you a short introduction, but please note it's a little old.

## General info
This operator acts upon `RegistryMirror` CRDs. The goal is to reduce the time needed to download a large amount
of identical images during deploys. It is done by operator with following steps:
1. Create a caching registry proxy inside the cluster
2. Direct a node's Docker daemon to this proxy.

More details follow.
### Creating a cache registry
For each `RegistryMirror` a separate StatefulSet is created. It installs Nginx-based caching
HTTP proxies with an upstream configured from `upstreamUrl`, `masqueradeUrl` and optional `credentialsSecret`
fields. Also, for each RegistryMirror the Service is created, providing an access to the registry
proxy.

If `masqueradeUrl` is not provided explicitly, it is constructed from `upstreamUrl` by
prepending it with `mirror-` prefix.

### Directing a node's Docker daemon
This can be done in two different ways: by modifying node's `/etc/hosts` file ("hostess" mode)
and by modifying the pod's `image:` field with the help of the mutating webhook ("services" mode).

To perform required for the Docker operation manipulations with the nodes DaemonSet is created for
each RegistryMirror.

In "hostess" mode the special `mirror-hostess` container modifies node's `/etc/hosts` and substitutes
each `masqueradeUrl` with the cache service's ClusterIP like this:
```
172.x.y.z mirror-registry.my.org
172.x.y.t mirror-registry1.my.org
```

In "services" mode an accompanion mutating webhook is modifying the `image` fields for pods being created,
prepending it with the cache service's name, thus effectively directing the Docker daemon inside the cluster
to corresponding caching proxies. Currently the (ImageSwap)[https://github.com/phenixblue/imageswap-webhook]
mutating webhook is supported. It should be installed and operate in the cluster by other means. This operator
does not install it, and just alters ImageSwap's ConfigMap to set the `upstreamUrl` - service's IP correspondence
like this:
```
...
kind: ConfigMap
data:
  maps: |
    default:
    mirror-registry.my.org:172.x.y.z/mirror-registry.my.org
    mirror-registry1.my.org:172.x.y.t/mirror-registry1.my.org
...
```
See [ImageSwap README.md](https://github.com/phenixblue/imageswap-webhook/blob/v1.4.2/README.md)
for details.

In either mode the certificate for Docker daemon to trust the caching proxy should be provided. Caching
proxies use self-signed certificates, so DaemonSet's `certificate-installation` container copies the
corresponding certificate into node's `/etc/docker/certs.d` directory. In "hostess" mode the certificate
is installed into `/etc/docker/certs.d/<masqueradeUrl>/` directory. In "services" mode the certificate
is installed into `/etc/docker/certs.d/<clusterIp>/`, where `<clusterIp>` is the IP address of the caching
proxy service.

### Detecting the unexpected `imageswap-map` changes

There is a possibility that, while operating in the 'services' mode, config map for ImageSwap,
`imageswap-maps`, is modified by hands or by another deployment. With this, mirror-operator
will not detect these changes, and would not update the config map.
With the use of the `--map-check` command-line switch it is possible to discover such a situation.
For this, aadd the livenessProbe like this:
```
        livenessProbe:
          exec:
            command:
            - /usr/local/bin/python
            - /app/mirroroperator/operator.py
            - --map-check
```
Having this configured, the unexpected change in the Config Map is detected and
the container is restarted.

## Configuration
The following environment variables can be set:

Name | description | default
--- | --- | ---
`DOCKER_CERTIFICATE_SECRET` | (Required) You **must** provide a certificate to enable TLS between the docker daemon and the registry and create a secret from it, this variable is the name of the secret | None
`NAMESPACE` | (Optional) The namespace in which the resources should be created. This should be the same namespace as where the container is running | default
`SECONDS_BETWEEN_STREAMS` | (Optional) Time to sleep between calls to the API. The operator will occasionally lose connection or else fail to run if the Custom Resource Definition does not exist. | 30
`DOCKER_REGISTRY` | (Optional) The docker registry where Docker images for all containers are to be pulled from. Set it if you have cache/proxy for accessing DockerHub. Overrides HOSTESS_DOCKER_REGISTRY if set to non-default value. | docker.io
`HOSTESS_DOCKER_REGISTRY` | (Optional) Deprecated, will be removed in version 1.0.0. The docker registry where mirror-hostess and alpine are to be pulled from. | docker.io
`HOSTESS_DOCKER_IMAGE` | (Optional) The name of the docker image for mirror-hostess. | ocadotechnology/mirror-hostess
`HOSTESS_DOCKER_TAG` | (Optional) The tag for the mirror-hostess docker image. | 1.1.0
`ADDRESSING_SCHEME` | (Optional) Select supported addressing scheme | hostess
`IMAGESWAP_NAMESPACE` | (Optional) The namespace for `imageswap-maps` ConfigMap | the same as `NAMESPACE`
`SS_DS_LABELS` | (Optional) StatefulSet and DaemonSet labels | None
`SS_DS_TEMPLATE_LABELS` | (Optional) StatefulSet and DaemonSet pod labels | None
`SS_DS_TOLERATIONS` | (Optional) StatefulSet and DaemonSet pod tolerations | None
`IMAGE_PULL_SECRETS` | (Optional) Secret to pull images from the upstream registry | None
`CA_CERTIFICATE_BUNDLE` | (Optional) Certificate bundle for the registry host  | None

## Usage
In order to have the operator deploy a new mirror, the cluster needs to have the custom resource defined:
```
apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  # name must match the spec fields below, and be in the form: <plural>.<group>
  name: registrymirrors.k8s.osp.tech
spec:
  # group name to use for REST API: /apis/<group>/<version>
  group: k8s.osp.tech
  # version name to use for REST API: /apis/<group>/<version>
  version: v1
  # either Namespaced or Cluster
  scope: Cluster
  names:
    # plural name to be used in the URL: /apis/<group>/<version>/<plural>
    plural: registrymirrors
    # singular name to be used as an alias on the CLI and for display
    singular: registrymirror
    # kind is normally the CamelCased singular type. Your resource manifests use this.
    kind: RegistryMirror
    # shortNames allow shorter string to match your resource on the CLI
    shortNames:
    - rm

```

You can then create new mirrors by providing at minimum an `upstreamUrl` in the spec:
```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: docker
spec:
  upstreamUrl: hub.docker.io
```

You can, optionally, specify a masqueradeUrl in the RegistryMirror object spec. If you do this then the daemonsets that run the [mirror-hostess][mirror-hostess] docker image will add a hosts entry to each node that points the service associated with a RegistryMirror to the hostname in the masqueradeUrl. This allows you to masquerade one hostname for a mirror to another. In the following example local.docker.io would point to the service IP:

```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: docker
spec:
  upstreamUrl: hub.docker.io
  masqueradeUrl: local.docker.io
```

If you have a username/password which must be used to access the upstream mirror, you can add a `credentialsSecret` key to the spec, who's value should
be the name of the secret, e.g:
```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: internal
spec:
  upstreamUrl: hub.docker.io
  credentialsSecret: internal-mirror
```

If you want to adjust the amount of storage allocated, you can add a `volumeClaimTemplate` key to the spec. The value should be the same as a [PersistentVolumeClaim]https://v1-8.docs.kubernetes.io/docs/api-reference/v1.8/#persistentvolumeclaim-v1-core) object. e.g:
```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: internal
spec:
  upstreamUrl: hub.docker.io
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 20Gi
```

The operator will then deploy a daemonset, statefulset, service and headless service in whichever namespace is configured. We generally expect this to be default. These will all be named `registry-mirror-<name>`, with the exception of the headless service which will be named `registry-mirror-<name>-headless` and the statefulset and daemonset which will both be named `registry-mirror-<name>-utils`.
You can get all the elements of your mirror using - `kubectl get ds,statefulset,svc,registrymirror -l mirror=<name> -n default`.

If you wish to update the secret or URL, all you need to do is change it in the `RegistryMirror` manifest and the operator will handle updates.

[operators]: https://coreos.com/blog/introducing-operators.html
[mirror-hostess]: https://github.com/ocadotechnology/mirror-hostess
