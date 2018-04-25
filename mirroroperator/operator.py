import kubernetes
import logging
import time
import os

from http import HTTPStatus
from kubernetes.client.rest import ApiException
from mirroroperator.registrymirror import RegistryMirror


LOGGER = logging.getLogger(__name__)

CRD_GROUP = "k8s.osp.tech"
CRD_VERSION = "v1"
CRD_PLURAL = "registrymirrors"


class MirrorOperator(object):
    def __init__(self, namespace):
        self.namespace = namespace
        kubernetes.config.load_incluster_config()
        self.crd_api = kubernetes.client.ExtensionsV1beta1Api()
        self.object_api = kubernetes.client.CustomObjectsApi()

    def watch_registry_mirrors(self):
        watcher = kubernetes.watch.Watch()
        try:
            for event in watcher.stream(self.object_api.list_cluster_custom_object, CRD_GROUP, CRD_VERSION, CRD_PLURAL):
                mirror = RegistryMirror(namespace=self.namespace, event_type=event['type'], **event['object'])
                mirror.apply()
        except ApiException as e:
            status = HTTPStatus(e.status)
            if status == HTTPStatus.NOT_FOUND:
                LOGGER.error("CRD not found. Please ensure you create a CRD with group - %s,"
                             "version - %s and plural - %s before this operator can run.",
                             CRD_GROUP, CRD_VERSION, CRD_PLURAL)
            else:
                LOGGER.exception("Error watching custom object events", exc_info=True)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    namespace = os.environ.get("NAMESPACE", "kube-extra")
    sleep_time = os.environ.get("SECONDS_BETWEEN_STREAMS", 30)
    operator = MirrorOperator(namespace)
    while True:
        operator.watch_registry_mirrors()
        LOGGER.info("API closed connection or CRD does not exist, sleeping for %i seconds", sleep_time)
        time.sleep(sleep_time)
