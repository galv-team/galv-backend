from rest_framework import exceptions, HTTP_HEADER_ENCODING
from rest_framework.authentication import get_authorization_header, BaseAuthentication
from django.utils.translation import gettext_lazy as _

from .models import Harvester, HarvesterUser


class HarvesterAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Harvester ".  For example:

        Authorization: Harvester 401f7ac837da42b97f613d789819ff93537bee6a
    """

    keyword = 'Harvester'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode(encoding=HTTP_HEADER_ENCODING):
            return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode(encoding=HTTP_HEADER_ENCODING)
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        try:
            harvester = Harvester.objects.get(api_key=key)
        except Harvester.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        user = HarvesterUser(harvester)
        if not user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (user, key)

    def authenticate_header(self, request):
        return self.keyword


class UserAuthDetails:
    """
    A simple class to hold user authentication details.
    """
    def __init__(
            self,
            is_authenticated: bool = False,
            is_approved: bool = False,
            is_harvester: bool = False,
            is_lab_admin: bool = False,
            lab_ids=None,
            writeable_lab_ids=None,
            team_ids=None,
            writeable_team_ids=None
    ):
        if lab_ids is None:
            lab_ids = set()
        if writeable_lab_ids is None:
            writeable_lab_ids = set()
        if team_ids is None:
            team_ids = set()
        if writeable_team_ids is None:
            writeable_team_ids = set()

        self.is_authenticated = is_authenticated
        self.is_approved = is_approved
        self.is_harvester = is_harvester
        self.is_lab_admin = is_lab_admin
        self.lab_ids = lab_ids|writeable_lab_ids
        self.writeable_lab_ids = writeable_lab_ids
        self.team_ids = team_ids|writeable_team_ids
        self.writeable_team_ids = writeable_team_ids


def perform_authentication_with_side_effects(request):
    """
    Overwrite DRF ViewSet.perform_authentication to add user authentication details to the request object.

    This saves us from having to query the database for this information in every view,
    which was previously done in the `get_permissions` method of the viewsets.

    This cannot be middleware because DRF doesn't authenticate users until after middleware is run.
    """
    # Code to be executed for each request before
    # the view (and later middleware) are called.
    if getattr(request, "user_auth_details", None) is not None:
        return

    is_harvester = isinstance(request.user, HarvesterUser)

    # Team membership is always explicitly set
    team_ids = set()
    write_team_ids = set()
    # Lab membership inherits from team membership,
    # but lab admin rights are explicity declared.
    lab_ids = set()
    write_lab_ids = set()

    if request.user is not None:
        if is_harvester:
            # Harvesters only ever have read access, and belong to any team that owns a monitored path
            for values in request.user.harvester.monitored_paths.values('team__pk', 'team__lab__pk'):
                team_ids.add(values['team__pk'])
                lab_ids.add(values['team__lab__pk'])
        else:
            for g in request.user.groups.values(
                'editable_team__pk', 'readable_team__pk', 'editable_lab__pk',
                'editable_team__lab__pk', 'readable_team__lab__pk'
            ):
                if g['editable_team__pk'] is not None:
                    write_team_ids.add(g['editable_team__pk'])
                    lab_ids.add(g['editable_team__lab__pk'])
                elif g['readable_team__pk'] is not None:
                    team_ids.add(g['readable_team__pk'])
                    lab_ids.add(g['readable_team__lab__pk'])
                elif g['editable_lab__pk'] is not None:
                    write_lab_ids.add(g['editable_lab__pk'])

    request.user_auth_details = UserAuthDetails(
        is_authenticated=request.user.is_authenticated,
        is_approved=len(lab_ids|write_lab_ids) > 0,
        is_harvester=is_harvester,
        is_lab_admin=len(write_lab_ids) > 0,
        lab_ids=lab_ids,
        writeable_lab_ids=write_lab_ids,
        team_ids=team_ids,
        writeable_team_ids=write_team_ids,
    )
