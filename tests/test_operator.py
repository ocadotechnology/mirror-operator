from mirroroperator.operator import MirrorOperator
from tests.kubernetes_test_case import KubernetesTestCase
from tests.kubernetes_mock_responses import *
import kubernetes
from unittest.mock import patch, Mock
from urllib3_mock import Responses
from kubernetes.client.rest import ApiException

TEST_DATA = [{"type": "CREATED", "object": {"metadata": {"name": "hub"},
                                      "spec": {"upstreamUrl": "hubtest"}}},
             {"type": "MODIFIED", "object": {"metadata": {"name": "hub"},
                                      "spec": {"upstreamUrl": "hubtest"}}}]



def stream_mock():
    for elem in TEST_DATA:
        yield elem

responses = Responses('urllib3')


class OperatorTestCase(KubernetesTestCase):
    def setUp(self):
        super().setUp()
        env_var_dict = {
            "namespace": "kube-extra",
            "mirror_hostess_image": "some-public-mirror-hostess-image",
            "image_pull_secrets": None,
            "secret_name": None,
            "cert_name": None,
        }
        self.operator = MirrorOperator(env_var_dict)

    @responses.activate
    def test_will_read_crds_blanks_already_exist(self):
        '''Should listen to CRDs being streamed + call apis appropriately. In this case the objects already exist'''
        stream_generator = stream_mock()
        responses.add('GET', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub', EMPTY_SERVICE)
        responses.add('GET', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub-headless', EMPTY_SERVICE)
        responses.add('GET', '/apis/extensions/v1beta1/namespaces/kube-extra/daemonsets/registry-mirror-hub-utils',
                      EMPTY_DAEMON_SET)
        responses.add('GET', '/apis/apps/v1beta1/namespaces/kube-extra/statefulsets/registry-mirror-hub',
                      EMPTY_STATEFUL_SET)
        responses.add('PUT', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub', '')
        responses.add('PUT', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub', '')
        responses.add('PUT', '/apis/extensions/v1beta1/namespaces/kube-extra/daemonsets/registry-mirror-hub-utils', '')
        responses.add('PUT', '/apis/apps/v1beta1/namespaces/kube-extra/statefulsets/registry-mirror-hub', '')
        with patch('kubernetes.watch.watch.Watch.stream', return_value=stream_generator):
            self.operator.watch_registry_mirrors()
            # all the objects exist, so only 4 gets followed by 4 updates
        methods = ('GET', 'GET', 'GET', 'GET',
                   'PUT', 'PUT', 'PUT', 'PUT',
                   'GET', 'GET', 'GET', 'GET',
                   'PUT', 'PUT', 'PUT', 'PUT')
        self.check_calls(methods,
                         responses.calls,
                         kubernetes.client.V1ObjectMeta(
                             name="hub",
                             labels={"app": "docker-registry",
                                    "mirror": "hub"},
                             owner_references=[kubernetes.client.V1OwnerReference(
                                api_version=None,
                                name="hub",
                                kind=None,
                                uid=None,
                             )]
                            )
                         )

    @responses.activate
    def test_will_read_crds_blanks_dont_exist(self):
        '''Should listen to CRDs being streamed + call apis appropriately. In this case the objects don't alreadu exist'''
        stream_generator = stream_mock()
        responses.add('GET', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub', status=404, body='{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"services \\"registry-mirror-internal\\" not found","reason":"NotFound","details":{"name":"registry-mirror-internal","kind":"services"},"code":404}')
        responses.add('GET', '/api/v1/namespaces/kube-extra/services/registry-mirror-hub-headless', status=404)
        responses.add('GET', '/apis/apps/v1beta1/namespaces/kube-extra/statefulsets/registry-mirror-hub',
                      status=404)
        responses.add('GET', '/apis/extensions/v1beta1/namespaces/kube-extra/daemonsets/registry-mirror-hub-utils',
                      status=404)
        responses.add('POST', '/api/v1/namespaces/kube-extra/services', EMPTY_SERVICE)
        responses.add('POST', '/api/v1/namespaces/kube-extra/services', EMPTY_SERVICE)
        responses.add('POST', '/apis/apps/v1beta1/namespaces/kube-extra/statefulsets',
                      EMPTY_STATEFUL_SET)
        responses.add('POST', '/apis/extensions/v1beta1/namespaces/kube-extra/daemonsets',
                      EMPTY_DAEMON_SET)
        with patch('kubernetes.watch.watch.Watch.stream', return_value=stream_generator):
            self.operator.watch_registry_mirrors()
        # none of the objects exist, so 4 gets, followed by 2 service posts, followed by 2 service puts,
        # followed by post/put/post/put for daemon set/stateful set
        methods = ('GET', 'GET', 'GET', 'GET',
                   'POST', 'POST',
                   'POST', 'POST',
                   'GET', 'GET', 'GET', 'GET',
                   'POST', 'POST',
                   'POST', 'POST')
        self.check_calls(methods,
                         responses.calls,
                         kubernetes.client.V1ObjectMeta(
                             name="hub",
                             labels={"app": "docker-registry",
                                    "mirror": "hub"},
                             owner_references=[kubernetes.client.V1OwnerReference(
                                api_version=None,
                                name="hub",
                                kind=None,
                                uid=None,
                             )]
                            )
                         )

    def test_exception_handling(self):
        '''Should report the CRD doesn't exist'''
        kubernetes.watch.Watch.stream = Mock(side_effect=ApiException(status=404))
        self.operator.watch_registry_mirrors()

    def test_exception_handling_other(self):
        '''Should report there was some other error'''
        kubernetes.watch.Watch.stream = Mock(side_effect=ApiException(status=500))
        self.operator.watch_registry_mirrors()
