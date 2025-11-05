import hashlib
import logging
import urllib.parse
import uuid
import json

from djagger.decorators import schema
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.forms.utils import ErrorList
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseRedirect
)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views import View
from spid_cie_oidc.entity.exceptions import InvalidEntityConfiguration
from spid_cie_oidc.provider.forms import AuthLoginForm, AuthzHiddenForm
from spid_cie_oidc.provider.models import OidcSession
from spid_cie_oidc.provider.exceptions import AuthzRequestReplay, InvalidRefreshRequestException, ValidationException
from spid_cie_oidc.provider.settings import (
    OIDCFED_DEFAULT_PROVIDER_PROFILE,
    OIDCFED_PROVIDER_PROFILES,
)
from . import OpBase
logger = logging.getLogger(__name__)


schema_profile = OIDCFED_PROVIDER_PROFILES[OIDCFED_DEFAULT_PROVIDER_PROFILE]


@schema(
    summary="OIDC Provider Authorization endpoint",
    methods=['GET', 'POST'],
    get_request_schema = {
        "application/x-www-form-urlencoded": schema_profile["authorization_request_doc"],
        "request object - jwt payload": schema_profile["authorization_request"]
    },
    post_response_schema= {
            "302":schema_profile["authorization_response"],
            "403": schema_profile["authorization_error_response"]
    },
    external_docs = {
        "alt_text": "AgID SPID OIDC Guidelines",
        "url": (
            "https://www.agid.gov.it/it/agenzia/stampa-e-comunicazione/"
            "notizie/2021/12/06/openid-connect-spid-adottate-linee-guida"
        ),
    },
    tags = ['Provider']
)
class AuthzRequestView(OpBase, View):
    """
        View which processes the actual Authz request and
        returns a Http Redirect
    """

    template = "op_user_login.html"

    def string_to_list(self, payload, must_list):
        for i in must_list:
            if isinstance(payload.get(i, None), str):
                if ' ' in payload[i]:
                    payload[i] = payload[i].split(' ')
                else:
                    payload[i] = [payload[i]]
        return payload

    def validate_authz(self, payload: dict):
        logger.debug(f"=== INÍCIO VALIDAÇÃO AUTHZ ===")
        logger.debug(f"Payload completo: {json.dumps(payload, indent=2)}")
        
        # Log dos valores específicos que serão validados
        logger.debug(f"client_id: {payload.get('client_id')}")
        logger.debug(f"redirect_uri: {payload.get('redirect_uri')}")
        logger.debug(f"scope: {payload.get('scope')}")
        logger.debug(f"prompt: {payload.get('prompt')}")
        logger.debug(f"nonce: {payload.get('nonce')}")
        logger.debug(f"state: {payload.get('state')}")

        must_list = ("scope") 
        logger.debug(f"Convertendo para lista: {must_list}")

        payload = self.string_to_list(payload, must_list)
        logger.debug(f"Payload após conversão: {json.dumps(payload, indent=2)}")

        logger.debug("Verificando offline_access scope")

        if (
            'offline_access' in payload['scope'] and
            'consent' not in payload['prompt']
        ):
            logger.error("❌ offline_access sem prompt=consent")
            raise InvalidRefreshRequestException(
                "scope with offline_access without prompt = consent"
            )
        
        p_redirect = urllib.parse.urlparse(payload.get("redirect_uri", ""))
        p_client = urllib.parse.urlparse(payload.get("client_id", ""))

        scheme_fqdn_redirect = f"{p_redirect.scheme}://{p_redirect.netloc}"
        scheme_fqdn_client = f"{p_client.scheme}://{p_client.netloc}"

        logger.debug(f"client_id: {payload.get('client_id')}")
        logger.debug(f"scheme_fqdn_client: {scheme_fqdn_client}")
        logger.debug(f"scheme_fqdn_redirect: {scheme_fqdn_redirect}")

        if not scheme_fqdn_client == scheme_fqdn_redirect:
            logger.error(f"❌ client_id não está em redirect_uri")
            logger.error(f"   client_id: {payload.get('client_id')}")
            logger.error(f"   redirect_uri: {payload.get('redirect_uri')}")
            raise ValidationException("client_id not in redirect_uri")

        logger.debug("✅ client_id vs redirect_uri - OK")
        
        try:
            self.validate_json_schema(
                payload,
                "authorization_request",
                "Authn request object validation failed"
            )
            logger.debug("✅ Schema JSON validado com sucesso")
        except Exception as e:
            logger.error(f"❌ Falha na validação do schema JSON: {e}")
            raise

        logger.debug("=== VALIDAÇÃO AUTHZ CONCLUÍDA COM SUCESSO ===")

    def get_url_consent(self, user):
        url = reverse("oidc_provider_consent")
        if (
                user.is_staff and
                'spid_cie_oidc.relying_party_test' in settings.INSTALLED_APPS
        ):
            try:
                url = reverse("oidc_provider_staff_testing")
            except Exception as e:  # pragma: no cover
                logger.error(f"testigng page url reverse failed: {e}")
        return url

    def get_login_form(self):
        return AuthLoginForm

    def get(self, request, *args, **kwargs):
        """
        The Authorization request of a RPs is validated and a login prompt is rendered to the user
        """
        req = request.GET.get("request", None)
        if not req:
            logger.error(
                f"Missing Authz request object in {dict(request.GET)} "
                f"error=invalid_request"
            )
            return HttpResponseBadRequest()
        
        tc = None
        try:
            tc = self.validate_authz_request_object(req)
        except InvalidEntityConfiguration as e:
            logger.error(f"Invalid Entity Configuration: {e}")
            return self.redirect_response_data(
                self.payload["redirect_uri"],
                error = "invalid_request",
                error_description =_("Failed to establish the Trust"),
                state = self.payload.get("state", "")
            )
        except AuthzRequestReplay as e:
            logger.error(
                "Replay on authz request detected for "
                f"{request.GET.get('client_id', 'unknow')}: {e}"
            )
            return self.redirect_response_data(
                self.payload["redirect_uri"],
                error = "invalid_request",
                error_description =_(
                    "An Unknown error raised during validation of "
                    f" authz request object: {e}"
                ),
                state = self.payload.get("state", "")
            )
        except Exception as e:
            logger.error(
                "Error during authz request validation for "
                f"{request.GET.get('client_id', 'unknown')}: {e}"
            )
            return self.redirect_response_data(
                self.payload["redirect_uri"],
                error="invalid_request",
                error_description=_("Authorization request not valid"),
                state = self.payload.get("state", "")
            )
        
        try:
            self.validate_authz(self.payload)
        except ValidationException:
            return self.redirect_response_data(
                self.payload["redirect_uri"],
                error="invalid_request",
                error_description=_("Authorization request validation error"),
                state = self.payload.get("state", "")
            )
        except InvalidRefreshRequestException as e:
            logger.warning(f"Invalid session: {e}")
            return HttpResponseForbidden()
        
        prompt = self.payload.get("prompt", "login")
        
        if request.user:
            if request.user.is_authenticated and "login" not in prompt:
                try:
                    session = self.check_session(request)
                    url = self.get_url_consent(request.user)
                    return HttpResponseRedirect(url)
                except Exception:
                    logger.warning(f"Failed SSO check session for {request.user}")
                    logout(request)
                    return self.get(request)

        # stores the authz request in a hidden field in the form
        form = self.get_login_form()()
        context = {
            "client_organization_name": self.get_client_organization_name(tc),
            "hidden_form": AuthzHiddenForm(dict(authz_request_object=req)),
            "form": form,
            "redirect_uri": self.payload["redirect_uri"],
            "obj_request": json.dumps(self.payload, indent=2),
            "state": self.payload["state"],
            "acr_value": "N/A",
        }
        return render(request, self.template, context)

    def post(self, request, *args, **kwargs):
        """
            When the User prompts his credentials
            TODO: REFACTOR this method doesn't support PAR!
        """
        form = self.get_login_form()(request.POST)
        if not form.is_valid():
            return render(
                request,
                self.template,
                {
                    "form": form,
                    "hidden_form": AuthzHiddenForm(request.POST),
                }
            )

        authz_form = AuthzHiddenForm(request.POST)
        authz_form.is_valid()
        authz_request = authz_form.cleaned_data.get("authz_request_object")
        try:
            self.validate_authz_request_object(authz_request)
        except Exception as e:
            logger.error(
                "Authz request object validation failed "
                f"for {authz_request}: {e} "
            )
            return HttpResponseForbidden()

        # autenticate the user
        username = form.cleaned_data.get("username")
        password = form.cleaned_data.get("password")
        user = authenticate(username=username, password=password)

        if not user:
            errors = form._errors.setdefault("username", ErrorList())
            errors.append(_("invalid username or password"))
            return render(
                request,
                self.template,
                {
                    "form": form,
                    "hidden_form": AuthzHiddenForm(request.POST),
                    "redirect_uri": self.payload["redirect_uri"],
                    "state": self.payload["state"]
                }
            )
        else:
            login(request, user)

        # create auth_code
        auth_code = hashlib.sha512(
            '-'.join(
                (
                    f'{uuid.uuid4()}',
                    f'{self.payload["client_id"]}',
                    f'{self.payload["nonce"]}'
                )
            ).encode()
        ).hexdigest()
        
        # put the auth_code in the user web session
        request.session["oidc"] = {"auth_code": auth_code}
        
        session = OidcSession.objects.create(
            user=user,
            user_uid=user.username,
            nonce=self.payload["nonce"],
            authz_request=self.payload,
            client_id=self.payload["client_id"],
            auth_code=auth_code,
            acr=""
        )
        
        session.set_sid(request)
        url = self.get_url_consent(user)
        return HttpResponseRedirect(url)