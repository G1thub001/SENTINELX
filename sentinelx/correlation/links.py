from enum import Enum


class LinkType(str, Enum):
    SAME_USER = "same_user"
    SAME_HOST = "same_host"
    SAME_SOURCE_IP = "same_source_ip"
    TEMPORAL = "temporal"
    HOST_TRANSITION = "host_transition"