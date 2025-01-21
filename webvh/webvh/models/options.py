"""Attested Resource Options model for WebVH."""

from typing import Any, Dict, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields



class ResourceMetadata(BaseRecord):
    """ResourceMetadata."""

    RECORD_TYPE = "attested-resource-metadata"
    RECORD_ID_NAME = "resource_id"

    class Meta:
        """ResourceMetadata Metadata."""

        schema_class = "ResourceMetadataSchema"