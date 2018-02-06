import pecan

from barbican import api
from barbican.api import controllers
from barbican.common import config
from barbican.common import quota
from barbican.common import resources as res
from barbican.common import utils
from barbican import i18n as u
from barbican.model import repositories as repo
from barbican.plugin import resources as plugin

LOG = utils.getLogger(__name__)

CONF = config.CONF

def _quote_not_found():
    """Throw exception indicating quote not found."""
    pecan.abort(404, u._("The quote you requested wasn't found"))

class AttestationController(controllers.ACLMixin):
    """Root controller for the attestation API"""

    def __init__(self):
        LOG.debug('=== Creating AttestationController ===')
        self.secret_repo = repo.get_secret_repository()
        self.quota_enforcer = quota.QuotaEnforcer('secrets', self.secret_repo)

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Attestation'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id):
        ctxt = controllers._get_barbican_context(pecan.request)
        data = api.load_body(pecan.request)
        project = res.get_or_create_project(external_project_id)
        self.quota_enforcer.enforce(project)
        response = None
        response = plugin.do_attestation(data, external_project_id, False, ctxt)
        if response is None:
            _quote_not_found()
        return response

class ProvisionKEKController(controllers.ACLMixin):
    """Root controller for the provisioning KEK API inside enclave"""

    def __init__(self):
        LOG.debug('=== Creating ProvisionKEKController ===')

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Provision KEK'))
    @controllers.enforce_rbac('kek:get')
    @controllers.enforce_content_types(['application/json'])
    def on_get(self, external_project_id):
        response = plugin.do_provision_kek(external_project_id)
        return response

class MutualAttestationController(controllers.ACLMixin):
    """Root controller for the mutual attestation API"""

    def __init__(self):
        LOG.debug('=== Creating MutualAttestationController ===')
        self.secret_repo = repo.get_secret_repository()
        self.quota_enforcer = quota.QuotaEnforcer('secrets', self.secret_repo)

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('MutualAttestation'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id):
        data = api.load_body(pecan.request)
        project = res.get_or_create_project(external_project_id)
        self.quota_enforcer.enforce(project)
        response = None
        response = plugin.do_attestation(data, external_project_id, True)
        if response is None:
            _quote_not_found()
        return response

class ProvisionProjectPolicyController(controllers.ACLMixin):
    """Root controller for the provisioning policy for a particular project"""

    def __init__(self):
        LOG.debug('=== Creating ProvisionPolicyController ===')

    @pecan.expose(generic=True)
    def index(self):
        pecan.abort(405)  # HTTP 405 Method Not Allowed as default

    @index.when(method='POST', template='json')
    @controllers.handle_exceptions(u._('Provision Project Policy'))
    @controllers.enforce_rbac('secrets:post')
    @controllers.enforce_content_types(['application/json'])
    def on_post(self, external_project_id):
        data = api.load_body(pecan.request)
        response = plugin.update_policy(data, external_project_id)
        return response

    @index.when(method='GET', template='json')
    @controllers.handle_exceptions(u._('Policy retrieval'))
    @controllers.enforce_rbac('secrets:get')
    @controllers.enforce_content_types(['application/json'])
    #@utils.allow_all_content_types
    def on_get(self, external_project_id):
        response = plugin.get_policy(external_project_id)
        return response
