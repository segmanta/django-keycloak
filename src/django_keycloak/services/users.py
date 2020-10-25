import base64

from django_keycloak.tests import settings
from django.utils.module_loading import import_string
from django.core.exceptions import ImproperlyConfigured


def credential_representation_from_hash(hash_, temporary=False):
    algorithm, hashIterations, salt, hashedSaltedValue = hash_.split('$')

    return {
        'type': 'password',
        'hashedSaltedValue': hashedSaltedValue,
        'algorithm': algorithm.replace('_', '-'),
        'hashIterations': int(hashIterations),
        'salt': base64.b64encode(salt.encode()).decode('ascii').strip(),
        'temporary': temporary
    }


def add_user(client, user):
    """
    Create user in Keycloak based on a local user including password.

    :param django_keycloak.models.Client client:
    :param django.contrib.auth.models.User user:
    :rtype response
    """
    credentials = []

    if user.password != "":
        new_credential = credential_representation_from_hash(hash_=user.password)
        credentials.append(new_credential)

    return client.admin_api_client.realms.by_name(client.realm.name).users.create(
        username=user.username,
        credentials=credentials,
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        enabled=user.is_active
    )

def get_email_model():
    """
    Return the Email model that is active in this project.
    """
    if not hasattr(settings, 'EXTERNAL_EMAIL_MODEL'):
        # By default return None
        return None

    try:
        return import_string(settings.EXTERNAL_EMAIL_MODEL)
    except ImportError:
        raise ImproperlyConfigured(
            "EXTERNAL_EMAIL_MODEL refers to non-existing class"
        )
