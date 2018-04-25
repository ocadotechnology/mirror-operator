# mirror-operator
A python module + resulting docker image which listens for registry mirror requests and creates resources for that mirror. 
If you're confused what an operator is, [this blog post][operators] will give you a short introduction, but please note it's a little old.

## Configuration
The following environment variables can be set:

Name | description | default 
--- | --- | --- 
NAMESPACE | The namespace in which the resources should be created. This should be the same namespace as where the container is running | kube-extra 
SECONDS_BETWEEN_STREAMS | Time to sleep between calls to the API. The operator will occasionally lose connection or else fail to run if the Custom Resource Definition does not exist. | 30

## Usage
In order to have the operator deploy a new mirror, the cluster needs to have the custom resource defined. The current version of this can be found in [kube-extra].

You can then create new mirrors by providing at minimum an `upstreamUrl` in the spec:
```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: quay
spec:
  upstreamUrl: quay.docker.tech.lastmile.com
```

If you have a username/password which must be used to access the upstream mirror, you can add a `credentialsSecret` key to the spec, who's value should
be the name of the secret, e.g:
```yaml
apiVersion: k8s.osp.tech/v1
kind: RegistryMirror
metadata:
  name: internal
spec:
  upstreamUrl: internal.docker.tech.lastmile.com
  credentialsSecret: internal-mirror
```

The secret should then be encrypted and put in the appropriate @kubernetes-deployments repository as normal.

The operator will then deploy a daemon set, stateful set, service and headless service in whichever namespace is configured. We generally expect this to be kube-extra. These will all be named `registry-mirror-<name>`, with the exception of the headless service which will be named `registry-mirror-<name>-headless`.
You can get all the elements of your mirror using - `kubectl get ds,statefulset,svc,registrymirror -l mirror=<name> -n kube-extra`.

If you wish to update the secret or URL, all you need to do is change it in the `RegistryMirror` manifest and the operator will handle updates. 
 
## Deployment
This operator is deployed as part of the [kube-extra] manifest bundle and therefore included in all of our Kubernetes clusters. **You should not need to create a new deployment of this operator in order to use it**.


[kube-extra]: https://gitlab.tech.lastmile.com/kubernetes/kube-extra
[operators]: https://coreos.com/blog/introducing-operators.html
