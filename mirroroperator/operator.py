import kubernetes
import logging
import time
import os

from http import HTTPStatus
from kubernetes.client.rest import ApiException
from mirroroperator.registrymirror import RegistryMirror
from mirroroperator.exceptions import NoCRDException


LOGGER = logging.getLogger(__name__)

CRD_GROUP = "k8s.osp.tech"
CRD_VERSION = "v1"
CRD_PLURAL = "registrymirrors"


class MirrorOperator(object):
    def __init__(self, env_vars):
        """
        :param env_vars: dictionary includes namespace,
            hostess_docker_registry (used in RegistryMirror),
            hostess_docker_image (used in RegistryMirror),
            hostess_docker_tag (used in RegistryMirror),
            image_pull_secrets(used in RegistryMirror, optional),
            secret_name(optional),
            cert_name(optional)
        """
        self.registry_mirror_vars = env_vars
        kubernetes.config.load_incluster_config()
        self.crd_api = kubernetes.client.ExtensionsV1beta1Api()
        self.object_api = kubernetes.client.CustomObjectsApi()

    def watch_registry_mirrors(self):
        watcher = kubernetes.watch.Watch()
        try:
            for event in watcher.stream(self.object_api.list_cluster_custom_object, CRD_GROUP, CRD_VERSION, CRD_PLURAL):
                registry_mirror_kwargs = event['object'].copy()
                registry_mirror_kwargs.update(self.registry_mirror_vars)
                mirror = RegistryMirror(event_type=event['type'], **registry_mirror_kwargs)
                mirror.apply()
        except ApiException as e:
            status = HTTPStatus(e.status)
            if status == HTTPStatus.NOT_FOUND:
                raise NoCRDException("CRD not found. Please ensure you create a CRD with group - %s,"
                             "version - %s and plural - %s before this operator can run.",
                             CRD_GROUP, CRD_VERSION, CRD_PLURAL)
            else:
                LOGGER.exception("Error watching custom object events", exc_info=True)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    # Get organization specific variables from env
    env_vars = dict(
        namespace=os.environ.get("NAMESPACE", "default"),
        # optional to allow for image to be pulled from elsewhere
        hostess_docker_registry=os.environ.get("HOSTESS_DOCKER_REGISTRY", "docker.io"),
        hostess_docker_image=os.environ.get("HOSTESS_DOCKER_IMAGE",
                                            "ocadotechnology/mirror-hostess"),
        hostess_docker_tag=os.environ.get("HOSTESS_DOCKER_TAG", "1.1.0"),
        # optional in V1PodSpec secrets split with comma
        image_pull_secrets=os.environ.get("IMAGE_PULL_SECRETS"),
        # get secret name:
        secret_name=os.environ.get("SECRET_NAME"),
        # cert_name - needed in clusters
        cert_name=os.environ.get("CERT_NAME"),
    )
    operator = MirrorOperator(env_vars)

    sleep_time = os.environ.get("SECONDS_BETWEEN_STREAMS", 30)
    while True:
        operator.watch_registry_mirrors()
        LOGGER.info("API closed connection, sleeping for %i seconds", sleep_time)
        time.sleep(sleep_time)
