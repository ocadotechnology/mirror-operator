from mirroroperator.operator import MirrorOperator
from mirroroperator.exceptions import NoCRDException
from tests.kubernetes_test_case import KubernetesTestCase
from tests.kubernetes_mock_responses import *
import kubernetes
from unittest.mock import patch, Mock
from urllib3_mock import Responses
from kubernetes.client.rest import ApiException

TEST_DATA = [
    {
        "type": "CREATED",
        "object": {
            "apiVersion": "k8s.osp.tech/v1",
            "kind": "RegistryMirror",
            "metadata": {
                "name": "hub",
                "uid": "db3c1f82-97c2-11e7-a6e5-08aa276be3ff",
            },
            "spec": {
                "upstreamUrl": "hubtest",
                "credentialsSecret": "internal-mirror"
            }
        }
    },
    {
        "type": "MODIFIED",
        "object": {
            "apiVersion": "k8s.osp.tech/v1",
            "kind": "RegistryMirror",
            "metadata": {
                "name": "hub",
                "uid": "db3c1f82-97c2-11e7-a6e5-08aa276be3ff",
            },
            "spec": {
                "upstreamUrl": "hubtest",
                "credentialsSecret": "internal-mirror"
            }
        }
    }
]



def stream_mock():
    for elem in TEST_DATA:
        yield elem

responses = Responses('urllib3')


class OperatorTestCase(KubernetesTestCase):
    def setUp(self):
        super().setUp()
        env_var_dict = {
            "namespace": "default",
            "docker_registry": "docker.io",
            "hostess_docker_registry": "docker.io",
            "hostess_docker_image": "ocadotechnology/mirror-hostess",
            "hostess_docker_tag": None,
            "ss_ds_labels": {"test":"test_labels"},
            "ss_ds_template_labels": {"test":"test_pod_labels"},
            "ss_ds_tolerations": [{"key": "some.tol.era/tion", "operator": "Exists"}],
            "image_pull_secrets": None,
            "docker_certificate_secret": 'aaa',
            "ca_certificate_bundle": 'bbb',
        }
        self.operator = MirrorOperator(env_var_dict)

    @responses.activate
    def test_will_read_crds_blanks_already_exist(self):
        '''Should listen to CRDs being streamed + call apis appropriately. In this case the objects already exist'''
        stream_generator = stream_mock()
        responses.add('GET', '/api/v1/namespaces/default/services/registry-mirror-hub', EMPTY_SERVICE)
        responses.add('GET', '/api/v1/namespaces/default/services/registry-mirror-hub-headless', EMPTY_SERVICE)
        responses.add('GET', '/apis/apps/v1/namespaces/default/daemonsets/registry-mirror-hub-utils',
                      EMPTY_DAEMON_SET)
        responses.add('GET', '/apis/apps/v1/namespaces/default/statefulsets/registry-mirror-hub',
                      EMPTY_STATEFUL_SET)
        responses.add('GET', '/api/v1/namespaces/default/secrets/registry-mirror-hub-secret',
                      '{}')
        responses.add('GET', '/api/v1/namespaces/default/secrets/internal-mirror',
                      VALID_SECRET)
        responses.add('PUT', '/api/v1/namespaces/default/services/registry-mirror-hub', '')
        responses.add('PUT', '/api/v1/namespaces/default/services/registry-mirror-hub', '')
        responses.add('PUT', '/apis/apps/v1/namespaces/default/daemonsets/registry-mirror-hub-utils', '')
        responses.add('PUT', '/apis/apps/v1/namespaces/default/statefulsets/registry-mirror-hub', '')
        responses.add('PUT', '/api/v1/namespaces/default/secrets/registry-mirror-hub-secret', '')
        with patch('kubernetes.watch.watch.Watch.stream', return_value=stream_generator):
            self.operator.watch_registry_mirrors()
            # all the objects exist, so only 4 gets followed by 4 updates
        methods = ('GET', 'GET', 'GET', 'GET', 'GET',
                   'PUT', 'PUT', 'PUT', 'PUT', 'GET', 'PUT',
                   'GET', 'GET', 'GET', 'GET', 'GET',
                   'PUT', 'PUT', 'PUT', 'PUT', 'GET', 'PUT')
        self.check_calls(methods,
                         responses.calls,
                         kubernetes.client.V1ObjectMeta(
                             name="hub",
                             labels={"app": "docker-registry",
                                    "mirror": "hub"},
                             owner_references=[kubernetes.client.V1OwnerReference(
                                api_version="k8s.osp.tech/v1",
                                name="hub",
                                kind="RegistryMirror",
                                uid="not-none",
                             )]
                            )
                         )

    @responses.activate
    def test_will_read_crds_blanks_dont_exist(self):
        '''Should listen to CRDs being streamed and call apis appropriately. In this case the objects don't already exist'''
        stream_generator = stream_mock()
        responses.add(
            'GET',
            '/api/v1/namespaces/default/services/registry-mirror-hub',
            status=404,
            body='{"kind":"Status","apiVersion":"v1","metadata":{},'
            '"status":"Failure","message":"services \\"registry-mirror-'
            'internal\\" not found","reason":"NotFound","details":'
            '{"name":"registry-mirror-internal","kind":"services"},"code":404}'
        )
        responses.add('GET', '/api/v1/namespaces/default/services/registry-mirror-hub-headless', status=404)
        responses.add('GET', '/apis/apps/v1/namespaces/default/statefulsets/registry-mirror-hub',
                      status=404)
        responses.add('GET', '/apis/apps/v1/namespaces/default/daemonsets/registry-mirror-hub-utils',
                      status=404)
        responses.add('GET', '/api/v1/namespaces/default/secrets/registry-mirror-hub-secret',
                      status=404)
        responses.add('GET', '/api/v1/namespaces/default/secrets/internal-mirror',
                      VALID_SECRET)
        responses.add('POST', '/api/v1/namespaces/default/services', EMPTY_SERVICE)
        responses.add('POST', '/api/v1/namespaces/default/services', EMPTY_SERVICE)
        responses.add('POST', '/apis/apps/v1/namespaces/default/statefulsets',
                      EMPTY_STATEFUL_SET)
        responses.add('POST', '/apis/apps/v1/namespaces/default/daemonsets',
                      EMPTY_DAEMON_SET)
        responses.add('POST', '/api/v1/namespaces/default/secrets', '')
        with patch('kubernetes.watch.watch.Watch.stream', return_value=stream_generator):
            self.operator.watch_registry_mirrors()
        # none of the objects exist, so 4 gets, followed by 2 service posts,
        # followed by 2 service puts, followed by post/put/post/put for daemon
        # set/stateful set
        methods = ('GET', 'GET', 'GET', 'GET', 'GET',
                   'POST', 'POST',
                   'POST', 'POST', 'GET', 'POST',
                   'GET', 'GET', 'GET', 'GET', 'GET',
                   'POST', 'POST',
                   'POST', 'POST', 'GET', 'POST')
        self.check_calls(methods,
                         responses.calls,
                         kubernetes.client.V1ObjectMeta(
                             name="hub",
                             labels={"app": "docker-registry",
                                    "mirror": "hub"},
                             owner_references=[kubernetes.client.V1OwnerReference(
                                api_version="k8s.osp.tech/v1",
                                name="hub",
                                kind="RegistryMirror",
                                uid="not-none",
                             )]
                            )
                         )

    def test_exception_handling(self):
        '''Should report the CRD doesn't exist'''
        kubernetes.watch.Watch.stream = Mock(side_effect=ApiException(status=404))
        with self.assertRaises(NoCRDException):
            self.operator.watch_registry_mirrors()

    def test_exception_handling_other(self):
        '''Should report there was some other error'''
        kubernetes.watch.Watch.stream = Mock(side_effect=ApiException(status=500))
        self.operator.watch_registry_mirrors()
