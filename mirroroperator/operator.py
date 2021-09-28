import ast
import argparse
import json
import logging
import time
import os
import sys
from http import HTTPStatus
import fasteners
import kubernetes

from kubernetes.client.rest import ApiException
from mirroroperator.registrymirror import RegistryMirror
from mirroroperator.exceptions import NoCRDException


LOGGER = logging.getLogger(__name__)

CRD_GROUP = "k8s.osp.tech"
CRD_VERSION = "v1"
CRD_PLURAL = "registrymirrors"

VERSION_FILE="/var/run/imageswap_configmap_version"


# pylint: disable=too-few-public-methods
class MirrorOperator:
    def __init__(self, env_vars):
        """
        :param env_vars: dictionary includes namespace,
            docker_registry (used in RegistryMirror),
            hostess_docker_registry (used in RegistryMirror, deprecated),
            ss_ds_labels (used in RegistryMirror, optional),
            ss_ds_template_lables (used in RegistryMirror, optional)
            ss_ds_tolerations (used in RegistryMirror, optional)
            addressing_scheme ('hostess' or 'services', defaults to 'hostess', optional)
            imageswap_namespace (used in MirrorOperator,
                                 default to the operator namespace, optional)
            hostess_docker_image (used in RegistryMirror),
            hostess_docker_tag (used in RegistryMirror),
            image_pull_secrets(used in RegistryMirror, optional),
            docker_certificate_secret(used in RegistryMirror),
            ca_certificate_bundle(optional)
        """
        if not env_vars.get("docker_certificate_secret"):
            raise TypeError("Missing docker certificate secret")
        self.registry_mirror_vars = env_vars
        kubernetes.config.load_incluster_config()
        self.object_api = kubernetes.client.CustomObjectsApi()
        self.core_api = kubernetes.client.CoreV1Api()
        self.cm_lock = fasteners.InterProcessLock(VERSION_FILE + ".lck")

    def watch_registry_mirrors(self):
        watcher = kubernetes.watch.Watch()
        try:
            for event in watcher.stream(
                self.object_api.list_cluster_custom_object,
                CRD_GROUP,
                CRD_VERSION,
                CRD_PLURAL
            ):
                registry_mirror_kwargs = event['object'].copy()
                registry_mirror_kwargs.update(self.registry_mirror_vars)
                LOGGER.debug("RM kwargs: %s", registry_mirror_kwargs)
                mirror = RegistryMirror(
                    event_type=event['type'], **registry_mirror_kwargs
                )
                mirror.apply()
                if self.registry_mirror_vars['addressing_scheme'] == 'services':
                    self.update_imageswap_config()
        except ApiException as e:
            status = HTTPStatus(e.status)
            if status == HTTPStatus.NOT_FOUND:
                raise NoCRDException(
                    "CRD not found. Please ensure you create a CRD with group"
                    " - {}, version - {} and plural - {} before this operator"
                    " can run.".format(CRD_GROUP, CRD_VERSION, CRD_PLURAL)) from e
            LOGGER.exception(
                "Error watching custom object events",
                exc_info=True
            )

    def update_imageswap_config(self):
        registrymirrors = self.object_api.list_cluster_custom_object(
                              CRD_GROUP, CRD_VERSION, CRD_PLURAL)
        imageswap_config = "default:\n"
        for mirror in registrymirrors['items']:
            service_name = "registry-mirror-" + mirror['metadata']['name']
            service_namespace = self.registry_mirror_vars['namespace']
            try:
                mirror_service = self.core_api.read_namespaced_service(
                                     service_name, service_namespace)
            except ApiException as api_exception:
                json_error = json.loads(api_exception.body)
                code = HTTPStatus(int(json_error['code']))
                if code == HTTPStatus.NOT_FOUND:
                    LOGGER.info("Serfice %s not (yet) configured", service_name)
                else:
                    LOGGER.error("API returned status: %s, msg: %s",
                        code, json_error['message'])
                continue
            service_ip = mirror_service.spec.cluster_ip
            if 'masqueradeUrl' in mirror['spec']:
                masqueraded_name = mirror['spec']['masqueradeUrl']
            else:
                masqueraded_name = "mirror-" + mirror['spec']['upstreamUrl']
            imageswap_config += "{0}:{1}/{0}\n".format(masqueraded_name, service_ip)
        LOGGER.info("Imageswap config: %s", imageswap_config)
        imageswap_namespace = self.registry_mirror_vars['imageswap_namespace']

        self.cm_lock.acquire()

        configmap = self.core_api.patch_namespaced_config_map(
                "imageswap-maps",
                imageswap_namespace,
                {"data": {"maps": imageswap_config}}
        )

        with open(VERSION_FILE, "w", encoding='utf-8') as store:
            store.write(configmap.metadata.resource_version)

        self.cm_lock.release()

    def is_imageswap_config_current(self):
        imageswap_namespace = self.registry_mirror_vars['imageswap_namespace']

        self.cm_lock.acquire()
        configmap = self.core_api.read_namespaced_config_map(
                "imageswap-maps",
                imageswap_namespace
        )
        self.cm_lock.release()

        with open(VERSION_FILE, "r", encoding='utf-8') as store:
            stored_cm_version = store.read()
            if stored_cm_version == configmap.metadata.resource_version:
                sys.exit()
            else:
                LOGGER.error("Configmap has been modified not by the mirror operator")
                sys.exit(1)


        return False

def safely_eval_env(env_var):
    return ast.literal_eval(os.environ.get(env_var)
                            ) if os.environ.get(env_var) is not None else None
def main():
    logging.basicConfig(level=logging.INFO)

    # Get organization specific variables from env
    env_namespace=os.environ.get("NAMESPACE", "default")
    env_vars = dict(
        namespace=env_namespace,
        # optional to allow for image to be pulled from elsewhere
        docker_registry=os.environ.get(
            "DOCKER_REGISTRY", "docker.io"),
        # pylint: disable=fixme
        # TODO: remove 'hostess_docker_registry' in 1.0.0
        hostess_docker_registry=os.environ.get(
            "HOSTESS_DOCKER_REGISTRY", "docker.io"),
        addressing_scheme=os.environ.get("ADDRESSING_SCHEME", "hostess"),
        imageswap_namespace=os.environ.get("IMAGESWAP_NAMESPACE", env_namespace),
        hostess_docker_image=os.environ.get("HOSTESS_DOCKER_IMAGE",
                                            "ocadotechnology/mirror-hostess"),
        hostess_docker_tag=os.environ.get("HOSTESS_DOCKER_TAG", "1.1.0"),
        # optional labels to be added to daemonsets and statefulsets
        ss_ds_labels=safely_eval_env("SS_DS_LABELS"),
        ss_ds_template_labels=safely_eval_env("SS_DS_TEMPLATE_LABELS"),
        # optional tolerations to be added to daemonsets and statefulsets
        ss_ds_tolerations=safely_eval_env("SS_DS_TOLERATIONS"),
        # optional in V1PodSpec secrets split with comma
        image_pull_secrets=os.environ.get("IMAGE_PULL_SECRETS"),
        # get the docker certificate:
        docker_certificate_secret=os.environ.get("DOCKER_CERTIFICATE_SECRET"),
        # get ca certificate
        ca_certificate_bundle=os.environ.get("CA_CERTIFICATE_BUNDLE"),
    )
    # HOSTESS_DOCKER_REGISTRY is deprecated in favor of DOCKER_REGISTRY
    if env_vars["docker_registry"] != "docker.io":
        env_vars["hostess_docker_registry"] = env_vars["docker_registry"]

    operator = MirrorOperator(env_vars)

    parser = argparse.ArgumentParser()
    parser.add_argument("--map-update",
                        help="Update the imageswap-maps Config Map",
                        action='store_true')
    parser.add_argument("--map-check",
                        help="Check the version of the imageswap-maps Config Map",
                        action='store_true')
    args = parser.parse_args()

    if ( args.map_update or args.map_check ) and env_vars["addressing_scheme"] != "services":
        LOGGER.error(
            "ERROR: --map-update or --map-check with the '%s' addressing scheme is invalid",
            env_vars["addressing_scheme"]
        )
        sys.exit(1)

    if args.map_update:
        operator.update_imageswap_config()
        sys.exit()

    if args.map_check:
        map_current = operator.is_imageswap_config_current()
        if map_current:
            sys.exit()
        else:
            sys.exit(1)

    sleep_time = os.environ.get("SECONDS_BETWEEN_STREAMS", 30)
    while True:
        operator.watch_registry_mirrors()
        LOGGER.info("API closed connection, sleeping for %i seconds", sleep_time)
        time.sleep(sleep_time)

if __name__ == '__main__':
    main()
