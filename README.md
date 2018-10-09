[![Build Status](https://travis-ci.org/ocadotechnology/mirror-operator.svg?branch=master)](https://travis-ci.org/ocadotechnology/mirror-operator)

# mirror-operator
A python module + resulting docker image which listens for registry mirror requests and creates resources for that mirror. 
If you're confused what an operator is, [this blog post][operators] will give you a short introduction, but please note it's a little old.

## Configuration
The following environment variables can be set:

Name | description | default 
--- | --- | --- 
DOCKER_CERTIFICATE_SECRET | You **must** provide a certificate to enable TLS between the docker daemon and the registry and create a secret from it, this variable is the name of the secret | None
NAMESPACE | The namespace in which the resources should be created. This should be the same namespace as where the container is running | default 
SECONDS_BETWEEN_STREAMS | Time to sleep between calls to the API. The operator will occasionally lose connection or else fail to run if the Custom Resource Definition does not exist. | 30
HOSTESS_DOCKER_REGISTRY | The docker registry where mirror-hostess is to be pulled from. | docker.io 
HOSTESS_DOCKER_IMAGE | The name of the docker image for mirror-hostess. | ocadotechnology/mirror-hostess
HOSTESS_DOCKER_TAG | The tag for the mirror-hostess docker image. | 1.1.0
IMAGE_PULL_SECRETS | (Optional) Secret to pull images from the upstream registry | None
CA_CERTIFICATE_BUNDLE | (Optional) Certificate bundle for the registry host  | None

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

The operator will then deploy a daemonset, statefulset, service and headless service in whichever namespace is configured. We generally expect this to be default. These will all be named `registry-mirror-<name>`, with the exception of the headless service which will be named `registry-mirror-<name>-headless`.
You can get all the elements of your mirror using - `kubectl get ds,statefulset,svc,registrymirror -l mirror=<name> -n default`.

If you wish to update the secret or URL, all you need to do is change it in the `RegistryMirror` manifest and the operator will handle updates. 

[operators]: https://coreos.com/blog/introducing-operators.html
[mirror-hostess]: https://github.com/ocadotechnology/mirror-hostess
