from unittest import TestCase
from kubernetes.config.incluster_config import SERVICE_HOST_ENV_NAME, SERVICE_PORT_ENV_NAME
import os
import kubernetes
import json


class KubernetesTestCase(TestCase):
    def setUp(self):
        os.environ.setdefault(SERVICE_HOST_ENV_NAME, "localhost")
        os.environ.setdefault(SERVICE_PORT_ENV_NAME, "8080")
        kubernetes.config.incluster_config.SERVICE_CERT_FILENAME = "blip"
        kubernetes.config.incluster_config.SERVICE_TOKEN_FILENAME = "blip"
        with open("blip", 'w') as tokencertfile:
            tokencertfile.write("rubbish")

    def check_calls(self, methods, calls, exp_metadata):
        self.assertEqual(len(calls), len(methods))
        for exp_call, (request, response) in zip(methods, calls):
            self.assertEqual(request.method, exp_call)
            if exp_call != "GET":
                body = json.loads(request.body)
                self.assertIn(exp_metadata.name, body['metadata']['name'])
                self.assertDictContainsSubset(exp_metadata.labels, body['metadata']['labels'])
                self.assertEqual(body['metadata']['ownerReferences'][0]['name'], exp_metadata.owner_references[0].name)

    def tearDown(self):
        os.remove("blip")
