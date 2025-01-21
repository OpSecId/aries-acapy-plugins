"""DID Webvh Registry."""

import re
from typing import Optional, Pattern, Sequence

from acapy_agent.anoncreds.base import AnonCredsRegistrationError, BaseAnonCredsRegistrar, BaseAnonCredsResolver
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState
)
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from ..models.resources import AttestedResource, ResourceMetadata


class DIDWebvhRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDWebvhRegistry."""

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self._supported_identifiers_regex = re.compile(
            r"^did:webvh:[a-z0-9]+(?:\.[a-z0-9]+)*(?::\d+)?(?:\/[^#\s]*)?(?:#.*)?\s*$"
        )
        self._di_proof_options = {}

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers Regular Expression."""
        return self._supported_identifiers_regex

    @property
    def _digest_multibase(self, resource_content) -> str:
        """Supported Identifiers Regular Expression."""
        resource_digest = ''
        return resource_digest
    
    @staticmethod
    def publish_attested_resource(self, secured_resource) -> AttestedResource:
        """Derive attested resource object from content."""
        resource_id = ''
        return resource_id
    
    @staticmethod
    def sign_attested_resource(self, resource, options) -> AttestedResource:
        """Derive attested resource object from content."""
        secured_resource = {}
        return secured_resource
    
    @staticmethod
    def create_attested_resource(self, issuer_id, resource_type, resource_content, related_resource=None, proof_options=None) -> AttestedResource:
        """Derive attested resource object from content."""
        content_digest = self._digest_multibase(resource_content)
        attested_resource = AttestedResource(
                id=f'{issuer_id}/resources/{content_digest}.json',
                resourceContent=resource_content,
                resourceMetadata=ResourceMetadata(
                    resourceId=content_digest,
                    resourceType=resource_type
                ),
                relatedResource=related_resource if related_resource else []
            )
        secured_resource = self.sign_attested_resource(
            attested_resource,
            proof_options
        )
        resource_id = self.publish_attested_resource(secured_resource)
        
        if resource_id != secured_resource.get('id'):
            pass
        
        return secured_resource
    

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered DIDWebvhRegistry")

    async def get_schema(self, profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        resource = await self.resolver.resolve_resource(schema_id)
        schema = resource.resourceContent
        metadata = resource.resourceMetadata

        anoncreds_schema = AnonCredsSchema(
            issuer_id=schema["issuerId"],
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=metadata,
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        
        resource_type = 'anonCredsSchema'
        resource_name = schema.name
        
        attested_resource = self.create_attested_resource(
            schema.issuer_id, 
            resource_type, 
            schema,
            self._di_proof_options | {'verificationMethod': options.get('verificationMethod')}
        )
        resource_id = attested_resource.resourceMetadata.resourceId
        schema_id = attested_resource.id
        try:
            await self._create_and_publish_resource(
                profile,
                self.registrar.DID_REGISTRAR_BASE_URL,
                self.resolver.DID_RESOLVER_BASE_URL,
                schema.issuer_id,
                attested_resource,
            )
        except Exception as err:
            raise AnonCredsRegistrationError(f"{err}")
        
        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        raise NotImplementedError()

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        raise NotImplementedError()

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        raise NotImplementedError()

    async def get_revocation_list(
        self, profile: Profile, revocation_registry_id: str, timestamp: int
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        raise NotImplementedError()

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        raise NotImplementedError()

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        raise NotImplementedError()

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get a schema info from the registry."""
        return await super().get_schema_info_by_id(schema_id)