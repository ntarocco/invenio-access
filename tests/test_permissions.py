# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2015-2019 CERN.
#
# Invenio is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Tests for Permission class."""

import pytest
from flask_principal import ActionNeed, RoleNeed, UserNeed
from invenio_accounts.models import Role, User
from invenio_db import db

from invenio_access.models import ActionRoles, ActionSystemRoles, ActionUsers
from invenio_access.permissions import (
    Permission,
    any_user,
    authenticated_user,
    superuser_access,
    ParameterizedActionNeed)


# UserNeed
# RoleNeed
# ActionNeed
# ParameterizedActionNeed
# SystemRoleNeed

# 1. allow UserNeed
# 2. deny UserNeed
# 3. allow RoleNeed
# 4. deny RoleNeed
# 5. allow UserNeed, RoleNeed
# 6. deny UserNeed, RoleNeed
# 7. allow ActionNeed -> UserNeed
# 8. allow ActionNeed -> RoleNeed
# 9. deny ActionNeed -> UserNeed
# 10. deny ActionNeed -> RoleNeed
# 11. allow ActionNeed -> UserNeed, RoleNeed
# 12. deny ActionNeed -> UserNeed, RoleNeed
# 13. allow/deny ParameterizedActionNeed
# 14. test SystemRoleNeed
# 15. allow_by_default = True/False


def _tolist(obj):
    """Return the param as a list if it is not a list."""
    return obj if isinstance(obj, list) else [obj]


class WithUserIdentity(object):
    """Helper class to mock Flask identity and provide needs."""

    def __init__(self, user, *provides):
        self.user = user
        self.id = user.id
        self.provides = set(provides)
        self.provides.add(UserNeed(user.id))
        assert ActionNeed not in self.provides


class UserHelper(object):
    @staticmethod
    def create_users(total=1):
        """Helper to create users."""
        users = []
        for i in range(total):
            user = User(email="{}@inveniosoftware.org".format(i))
            db.session.add(user)
            users.append(user)
        db.session.commit()
        return [WithUserIdentity(user) for user in users]

    @staticmethod
    def create_roles(names):
        """Helper to create roles."""
        roles = []
        for name in _tolist(names):
            role = Role(name=name)
            db.session.add(role)
            roles.append(role)
        db.session.commit()
        return roles

    @staticmethod
    def assign_roles_to_user(roles, user):
        for role in _tolist(roles):
            user.provides.add(RoleNeed(role.name))

    @staticmethod
    def set_superuser(user):
        ActionHelper.allow_users(superuser_access, user)
        return user


class ActionHelper(object):
    @staticmethod
    def allow_users(action_need, users, argument=None):
        for user in _tolist(users):
            au = ActionUsers.allow(
                action=action_need, user=user.user, argument=argument
            )
            db.session.add(au)
        db.session.commit()

    @staticmethod
    def deny_users(action_need, users, argument=None):
        for user in _tolist(users):
            au = ActionUsers.deny(
                action=action_need, user=user.user, argument=argument
            )
            db.session.add(au)
        db.session.commit()

    @staticmethod
    def to_allowed_roles(action_need, roles, argument=None):
        for role in _tolist(roles):
            ar = ActionRoles.allow(
                action=action_need, role=role, argument=argument
            )
            db.session.add(ar)
        db.session.commit()

    @staticmethod
    def to_denied_roles(action_need, roles, argument=None):
        for role in _tolist(roles):
            ar = ActionRoles.deny(
                action=action_need, role=role, argument=argument
            )
            db.session.add(ar)
        db.session.commit()


class PermissionHelper(object):
    @staticmethod
    def deny_users(permission, users):
        for user in _tolist(users):
            permission.explicit_excludes.add(UserNeed(user.id))

    @staticmethod
    def deny_roles(permission, roles):
        for role in _tolist(roles):
            permission.explicit_excludes.add(RoleNeed(role.name))

    @staticmethod
    def deny_actions(permission, action_needs):
        for action_need in _tolist(action_needs):
            permission.explicit_excludes.add(action_need)


def test_allow_by_user_id(access_app):
    """Ensure allow permission by user id."""
    allowed_user, denied_user = UserHelper.create_users(2)

    permission = Permission(UserNeed(allowed_user.id))

    assert permission.allows(allowed_user)
    assert not permission.allows(denied_user)


def test_deny_by_user_id(access_app):
    """Ensure deny permission when same user is allowed and denied."""
    denied_user1, denied_user2 = UserHelper.create_users(2)

    permission = Permission(UserNeed(denied_user1.id))
    PermissionHelper.deny_users(permission, [denied_user1, denied_user2])

    assert not permission.allows(denied_user1)
    assert not permission.allows(denied_user2)


def test_permission_needs_excludes_action_expanded_to_user_id(
    access_app, dynamic_permission
):
    """."""
    action_access_backoffice = ActionNeed("access-backoffice")
    action_access_admin_panel = ActionNeed("access-admin-panel")

    user1, user2, user3, user4 = UserHelper.create_users(4)

    perm_access_backoffice = Permission(action_access_backoffice)
    PermissionHelper.deny_users(perm_access_backoffice, user2)
    PermissionHelper.deny_actions(perm_access_backoffice, action_access_admin_panel)

    # action expands to nothing, no one allowed
    assert not perm_access_backoffice.allows(user1)
    assert not perm_access_backoffice.allows(user2)
    assert not perm_access_backoffice.allows(user3)
    assert not perm_access_backoffice.allows(user4)

    dyn_perm_access_backoffice = dynamic_permission(action_access_backoffice)
    PermissionHelper.deny_users(dyn_perm_access_backoffice, user2)
    PermissionHelper.deny_actions(
        dyn_perm_access_backoffice, action_access_admin_panel
    )
    # with `allow_by_default=True` and action expands to nothing,
    # everyone allowed, but UserNeed excludes
    # import ipdb;ipdb.set_trace()
    assert dyn_perm_access_backoffice.allows(user1)
    assert not dyn_perm_access_backoffice.allows(user2)
    assert dyn_perm_access_backoffice.allows(user3)
    assert dyn_perm_access_backoffice.allows(user4)

    # set one user as superuser
    superuser = UserHelper.set_superuser(user4)
    # assign users to the action
    ActionHelper.allow_users(action_access_admin_panel, user1)
    ActionHelper.deny_users(action_access_admin_panel, user3)

    for p in perm_access_backoffice, dyn_perm_access_backoffice:
        assert p.allows(user1)
        assert not p.allows(user2)
        assert not p.allows(user3)
        assert p.allows(superuser)


def test_permission_needs_excludes_action_expanded_to_role(
    access_app, dynamic_permission
):
    """."""
    user1, user2, user3, user4, user5 = UserHelper.create_users(5)
    action_access_backoffice = ActionNeed("access-backoffice")
    action_open = ActionNeed("access")
    action_access_admin_panel = ActionNeed("edit")
    action_get_apis = ActionNeed("api-only")

    permission = Permission(action_access_backoffice)
    permission2 = Permission(action_open)
    permission2.explicit_excludes.add(action_access_admin_panel)
    # action expands to nothing, no one allowed
    for p in permission, permission2:
        assert not p.allows(user1)
        assert not p.allows(user2)
        assert not p.allows(user3)
        assert not p.allows(user4)
        assert not p.allows(user5)

    dyn_permission = dynamic_permission(action_access_backoffice)
    # with `allow_by_default=True` everyone allowed
    assert dyn_permission.allows(user1)
    assert dyn_permission.allows(user2)
    assert dyn_permission.allows(user3)
    assert dyn_permission.allows(user4)
    assert dyn_permission.allows(user5)

    # set one user as superuser
    superuser = UserHelper.set_superuser(user5)

    # create roles
    _roles = ["admins", "no-access-confidential-data", "api-only"]
    role_admins, role_no_access_confidential_data, role_api_only = \
        UserHelper.create_roles(_roles)
    # actions to roles
    ActionHelper.to_allowed_roles(action_access_backoffice, role_admins)
    ActionHelper.to_allowed_roles(action_open, role_admins)
    ActionHelper.to_denied_roles(
        action_access_admin_panel, role_no_access_confidential_data
    )
    ActionHelper.to_allowed_roles(action_get_apis, role_api_only)

    # user1 and user2 have role `admins`
    UserHelper.assign_roles_to_user(role_admins, user1)
    UserHelper.assign_roles_to_user(role_admins, user2)
    # user3 har role `admins` and `no-access-confidential-data`
    UserHelper.assign_roles_to_user(
        [role_admins, role_no_access_confidential_data], user3
    )
    # user4 har role `api-only` only
    UserHelper.assign_roles_to_user(role_api_only, user4)

    # add exclusions for specific users to permissions
    PermissionHelper.deny_users(permission, user2)
    PermissionHelper.deny_users(dyn_permission, user2)

    for p in permission, dyn_permission:
        assert p.allows(user1)
        assert not p.allows(user2)
        assert p.allows(user3)
        assert not p.allows(user4)
        assert p.allows(superuser)

    assert permission2.allows(user1)
    assert permission2.allows(user2)
    assert not permission2.allows(user3)
    assert not permission2.allows(user4)
    assert permission2.allows(superuser)


def test_permission_needs_user_id_and_action_expanded_to_user_id(
    access_app, dynamic_permission
):
    """."""
    user1, user2, user3, user4 = UserHelper.create_users(4)
    action_access_backoffice = ActionNeed("access-backoffice")

    permission = Permission(UserNeed(3), action_access_backoffice)

    # action expands to nothing, no one allowed
    assert not permission.allows(user1)
    assert not permission.allows(user2)
    # user 3 is allowed by explicit user id
    assert permission.allows(user3)
    assert not permission.allows(user4)

    dyn_permission = dynamic_permission(UserNeed(3), action_access_backoffice)
    assert not dyn_permission.allows(user1)
    assert not dyn_permission.allows(user2)
    assert dyn_permission.allows(user3)
    assert not dyn_permission.allows(user4)

    # set one user as superuser
    superuser = UserHelper.set_superuser(user4)

    # assign the user to the action to allow permission
    ActionHelper.allow_users(action_access_backoffice, user1)

    # permissions action `access-backoffice` expands to user `1`
    for p in permission, dyn_permission:
        assert p.allows(user1)
        assert not p.allows(user2)
        assert p.allows(user3)
        assert p.allows(superuser)


def test_system_role_name(access_app):
    """Test that ActionSystemRoles fails when created with undeclared names."""
    state = access_app.extensions["invenio-access"]
    db.session.begin(nested=True)
    # Declare a system role.
    state.system_roles = {"any_user": any_user}
    # Create with a declared name.
    ActionSystemRoles(action="read", role_name="any_user")
    # Create with an undeclared name.
    with pytest.raises(AssertionError):
        ActionSystemRoles(action="read", role_name="unknown")


def test_permission_for_system_roles(access_app, dynamic_permission):
    """User can access to an action allowed/denied to their system roles."""
    permission_open = dynamic_permission(ActionNeed("open-restricted"))
    permission_write = dynamic_permission(ActionNeed("write"))
    dyn_permission_open = dynamic_permission(ActionNeed("open-restricted"))
    dyn_permission_write = dynamic_permission(ActionNeed("write"))

    anonym_user, auth_user = UserHelper.create_users(2)

    db.session.add(
        ActionSystemRoles.allow(
            action=ActionNeed("open-restricted"), role=authenticated_user
        )
    )
    db.session.add(
        ActionSystemRoles.allow(action=ActionNeed("write"), role=any_user)
    )
    db.session.commit()

    anonym_user.provides.add(any_user)
    auth_user.provides.add(authenticated_user)
    auth_user.provides.add(any_user)

    for p in permission_open, dyn_permission_open:
        assert not p.allows(anonym_user)
        assert p.allows(auth_user)

    for p in permission_write, dyn_permission_write:
        assert p.allows(anonym_user)
        assert p.allows(auth_user)


def test_permission_needs_excludes_action_expanded_to_user_id_argument(
    access_app, dynamic_permission
):
    """."""
    user1, user2, user3 = UserHelper.create_users(3)
    action_access_backoffice = ActionNeed("access-backoffice")
    action_access_backoffice_arg1 = ParameterizedActionNeed("access-backoffice",
                                                          "arg1")

    permission_no_arg = Permission(action_access_backoffice)
    dyn_permission_no_arg = dynamic_permission(action_access_backoffice)
    permission_with_arg = Permission(action_access_backoffice_arg1)
    dyn_permission_with_arg = dynamic_permission(action_access_backoffice_arg1)

    # set one user as superuser
    superuser = UserHelper.set_superuser(user3)
    # assign users to the action
    ActionHelper.allow_users(action_access_backoffice, user1)
    ActionHelper.allow_users(action_access_backoffice_arg1, user2)

    for p in permission_no_arg, dyn_permission_no_arg:
        assert p.allows(user1)
        assert not p.allows(user2)
        assert p.allows(superuser)

    for p in permission_with_arg, dyn_permission_with_arg:
        assert p.allows(user1)
        assert p.allows(user2)
        assert p.allows(superuser)
