import base64
import json

EMPTY_SERVICE = """{"api_version": "v1",
     "kind": "Service",
     "metadata": {
                  "creation_timestamp": "2017-09-12T13:23:47Z",
                  "labels": {"app": "docker-registry", "mirror": "hub"},
                  "name": "registry-mirror-hub",
                  "namespace": "default",
                  "ownerReferences": [{"api_version": "k8s.osp.tech/v1",
                                        "kind": "RegistryMirror",
                                        "name": "hub",
                                        "uid": "c7137776-97b7-11e7-a6e5-0800276be3ff"}],
                  "resource_version": "13288",
                  "self_link": "/api/v1/namespaces/default/services/registry-mirror-hub",
                  "uid": "79fb4790-97bd-11e7-a6e5-0800276be3ff"},
     "spec": {"cluster_ip": "10.0.0.81",
              "ports": [{"name": "https",
                         "port": 443,
                         "protocol": "TCP",
                         "target_port": "https"}],
              "session_affinity": "None",
              "type": "ClusterIP"}
     }"""


EMPTY_DAEMON_SET = """{
    "kind":"DaemonSet",
    "apiVersion":"extensions/v1beta1",
    "metadata": {
                "name":"registry-mirror-hub-utils",
                "namespace":"default",
                "selfLink":"/apis/extensions/v1beta1/namespaces/default/daemonsets/registry-mirror-hub-utils",
                "uid":"dff71ac8-97c2-11e7-a6e5-0800276be3ff",
                "resourceVersion":"18519",
                "generation":1,
                "creationTimestamp":"2017-09-12T14:01:29Z",
                "labels": {
                    "app":"docker-registry",
                    "mirror":"hub"
                    },
                "ownerReferences": [
                    {
                    "apiVersion":"k8s.osp.tech/v1",
                    "kind":"RegistryMirror",
                    "name":"hub",
                    "uid":"db3c1f82-97c2-11e7-a6e5-0800276be3ff"
                    }
                ]
                },
    "spec": {
        "selector": {
            "matchLabels": {
                "app":"docker-registry",
                "mirror":"hub"
                }
            },
        "template": {
            "metadata": {
                "creationTimestamp":null,
                "labels": {
                    "app":"docker-registry",
                    "mirror":"hub"
                    }
                },
            "spec": {
                "containers": [
                    {
                    "name":"replaceme",
                    "image":"alpine",
                    "resources":{},
                    "terminationMessagePath":"/dev/termination-log",
                    "terminationMessagePolicy":"File",
                    "imagePullPolicy":"Always"
                    }
                ],
                "restartPolicy":"Always",
                "terminationGracePeriodSeconds":30,
                "dnsPolicy":"ClusterFirst",
                "securityContext":{},
                "schedulerName":"default-scheduler"
                }
            },
        "updateStrategy": {
            "type":"OnDelete"
            },
        "templateGeneration":1,
        "revisionHistoryLimit":10
        },
    "status": {
        "currentNumberScheduled":0,
        "numberMisscheduled":0,
        "desiredNumberScheduled":0,
        "numberReady":0
        }
    }
"""

EMPTY_STATEFUL_SET = """{
    "kind":"StatefulSet",
    "apiVersion":"apps/v1beta1",
    "metadata": {
        "name":"registry-mirror-hub",
        "namespace":"default",
        "selfLink":"/apis/apps/v1beta1/namespaces/default/statefulsets/registry-mirror-hub",
        "uid":"512e7799-97c4-11e7-a6e5-0800276be3ff",
        "resourceVersion":"20254",
        "generation":1,
        "creationTimestamp":"2017-09-12T14:11:48Z",
        "labels": {
            "app":"docker-registry",
            "mirror":"hub"
            },
        "ownerReferences": [
            {
            "apiVersion":"k8s.osp.tech/v1",
            "kind":"RegistryMirror",
            "name":"hub",
            "uid":"db3c1f82-97c2-11e7-a6e5-0800276be3ff"
            }]
        },
    "spec": {
        "replicas":1,
        "selector": {
            "matchLabels": {
                "app":"docker-registry",
                "mirror":"hub"
                }
            },
        "template": {
            "metadata": {
                "creationTimestamp":null,
                "labels": {
                    "app":"docker-registry",
                    "mirror":"hub"
                    }
                },
            "spec": {
                "containers": [
                    {
                        "name":"",
                        "image":"",
                        "resources":{},
                        "terminationMessagePath":"/dev/termination-log",
                        "terminationMessagePolicy":"File",
                        "imagePullPolicy":"IfNotPresent"
                    }],
                "restartPolicy":"Always",
                "terminationGracePeriodSeconds":30,
                "dnsPolicy":"ClusterFirst",
                "securityContext":{},
                "schedulerName":"default-scheduler"
                }
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {
                        "name":"image-store",
                        "creationTimestamp":null
                        },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage":"20Gi"
                                }
                            }
                        },
                    "status": {
                        "phase":"Pending"
                        }
                }],
            "serviceName":"registry-mirror-hub-headless",
            "podManagementPolicy":"Parallel",
            "updateStrategy": {
                "type":"OnDelete"
                },
            "revisionHistoryLimit":10
            },
    "status": {
        "replicas":0
        }
    }"""

username = "somebase64thing"
password = "supersecretpassword"
valid_secret = {
    "apiVersion": "v1",
    "data": {
        "username": base64.b64encode(username.encode('utf-8')).decode('utf-8'),
        "password": base64.b64encode(password.encode('utf-8')).decode('utf-8')
    },
    "kind": "Secret",
    "metadata": {
        "creationTimestamp": "2017-09-13T10:20:26Z",
        "name": "internal-mirror",
        "namespace": "default",
        "resourceVersion": "7889",
        "selfLink": "/api/v1/namespaces/default/secrets/internal-mirror",
        "uid": "294e16e7-986d-11e7-9c1f-0800275e72fe"
    },
    "type": "Opaque"
}

VALID_SECRET = json.dumps(valid_secret)

INVALID_SECRET = """
    {
        "apiVersion": "v1",
        "data": {
            "somekey": "somevalue"
        },
        "kind": "Secret",
        "metadata": {
            "creationTimestamp": "2017-09-13T10:20:26Z",
            "name": "internal-mirror",
            "namespace": "default",
            "resourceVersion": "7889",
            "selfLink": "/api/v1/namespaces/default/secrets/internal-mirror",
            "uid": "294e16e7-986d-11e7-9c1f-0800275e72fe"
        },
        "type": "Opaque"
    }"""
