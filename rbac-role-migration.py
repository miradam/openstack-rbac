#!/usr/bin/python

import os

import argparse

import keystoneclient


ADMIN_ROLE = 'admin'
MEMBER_ROLE = 'Member'
DOMAIN_ADMIN_ROLE = 'domain_admin'
DOMAIN_MEMBER_ROLE = 'domain_member'
PROJECT_ADMIN_ROLE = 'project_admin'
PROJECT_MEMBER_ROLE = 'project_member'
ALL_VALID_ROLES = [ADMIN_ROLE, MEMBER_ROLE,
                   DOMAIN_ADMIN_ROLE, DOMAIN_MEMBER_ROLE,
                   PROJECT_ADMIN_ROLE, PROJECT_MEMBER_ROLE]

DOMAIN_SCOPE = 'domain'
PROJECT_SCOPE = 'project'
ALL_VALID_SCOPES = [DOMAIN_SCOPE, PROJECT_SCOPE]


class RoleMigrationClass():
    def __init__(self, args):
        self.os_auth_url = os.getenv('OS_AUTH_URL')
        self.os_domain_name = os.getenv('OS_DOMAIN_NAME')
        self.os_password = os.getenv('OS_PASSWORD')
        self.os_user_domain_name = os.getenv('OS_USER_DOMAIN_NAME')
        self.os_region_name = os.getenv('OS_REGION_NAME')
        self.os_username = os.getenv('OS_USERNAME')

        if args.os_auth_url:
            self.os_auth_url = args.os_auth_url
        if args.os_domain_name:
            self.os_domain_name = args.os_domain_name
        if args.os_password:
            self.os_password = args.os_password
        if args.os_user_domain_name:
            self.os_user_domain_name = args.os_user_domain_name
        if args.os_region_name:
            self.os_region_name = args.os_region_name
        if args.os_username:
            self.os_username = args.os_usersname

        # Only scream about things that are absolutely necessary
        if not self.os_auth_url:
            raise ValueError(
                'Required \'auth-url\' not specified. Please set OS_AUTH_URL '
                'env var or set --os-auth-url via cmdline.')
        if not self.os_domain_name:
            raise ValueError(
                'Required \'domain name\' not specified. Please set '
                'OS_DOMAIN_NAME env var or set --os-domain-name via cmdline.')
        if not self.os_password:
            raise ValueError(
                'Required \'password\' not specified. Please set OS_PASSWORD '
                'env var or set --os-password via cmdline.')
        if not self.os_username:
            raise ValueError(
                'Required \'username\' not specified. Please set OS_USERNAME '
                'env var or set --os-username via cmdline.')

        self.ks_client = keystoneclient.v3.client.Client(
            auth_url=self.os_auth_url,
            domain_name=self.os_domain_name,
            password=self.os_password,
            user_domain_name=self.os_user_domain_name,
            username=self.os_username,
            region_name=self.os_region_name)

        try:
            self.role_ids = {}
            for role in self.ks_client.roles.list():
                self.role_ids[role.name] = role.id
        except:
            raise ValueError(
                'Failed to retrieve list of roles. Please verify your '
                'credentials and role assignments and try again.')

        for required_role in ALL_VALID_ROLES:
            if not required_role in self.role_ids:
                raise ValueError(
                    'Required role \'' + required_role + '\' doesn\'t appear '
                    'to be defined.')
        self.__get_preexisting_role_assignments()

    def __get_scoped_assignments(self, scope, rolename):
        assert scope in ALL_VALID_SCOPES
        assert rolename in ALL_VALID_ROLES
        ret = []
        for this_role in self.ks_client.role_assignments.list():
            if scope not in this_role.scope:
                continue
            if this_role.role['id'] == self.role_ids[rolename]:
                if hasattr(this_role, 'user'):
                    ret.append(
                        (this_role.user['id'], this_role.scope[scope]['id']))
        return ret

    def __populate_preexisting_role(self, scope, rolename):
        self.preexisting_roles[scope][rolename] = \
            self.__get_scoped_assignments(scope, rolename)

    def __get_preexisting_role_assignments(self):
        self.preexisting_roles = {DOMAIN_SCOPE: {}, PROJECT_SCOPE: {}}

        self.__populate_preexisting_role(DOMAIN_SCOPE, ADMIN_ROLE)
        self.__populate_preexisting_role(DOMAIN_SCOPE, MEMBER_ROLE)
        self.__populate_preexisting_role(DOMAIN_SCOPE, DOMAIN_ADMIN_ROLE)
        self.__populate_preexisting_role(DOMAIN_SCOPE, DOMAIN_MEMBER_ROLE)

        self.__populate_preexisting_role(PROJECT_SCOPE, ADMIN_ROLE)
        self.__populate_preexisting_role(PROJECT_SCOPE, MEMBER_ROLE)
        self.__populate_preexisting_role(PROJECT_SCOPE, PROJECT_ADMIN_ROLE)
        self.__populate_preexisting_role(PROJECT_SCOPE, PROJECT_MEMBER_ROLE)

    def __get_assignment_differences(self, scope, master_role, comp_role):
        assert scope in ALL_VALID_SCOPES
        assert master_role in ALL_VALID_ROLES
        assert comp_role in ALL_VALID_ROLES
        ret = []
        for role in self.preexisting_roles[scope][master_role]:
            if not role in self.preexisting_roles[scope][comp_role]:
                ret.append(role)

        return ret

    def handle_migration(self, scope, master_role, comp_role, do_grant):
        assert scope in ALL_VALID_SCOPES
        assert master_role in ALL_VALID_ROLES
        assert comp_role in ALL_VALID_ROLES
        roles_diff = self.__get_assignment_differences(
            scope, master_role, comp_role)
        pretty_desc = '\'' + scope + ' ' + master_role + '\''
        if len(roles_diff) == 0:
            print 'NO differences detected for ' + pretty_desc
            print ''
            return
        else:
            print 'Differences detected for ' + pretty_desc
            print 'user_id\t\t\t\t\t' + scope + '_id'
            for role in roles_diff:
                print str(role[0]) + '\t' + str(role[1])
            print ''

        if do_grant:
            for role in roles_diff:
                try:
                    if DOMAIN_SCOPE == scope:
                        self.ks_client.roles.grant(
                            role=self.role_ids[comp_role],
                            domain=role[1],
                            user=role[0])
                    else:
                        assert PROJECT_SCOPE == scope
                        self.ks_client.roles.grant(
                            role=self.role_ids[comp_role],
                            project=role[1],
                            user=role[0])
                except:
                    print 'FAILED assignment ' + comp_role + ' user_id ' \
                        + str(role[0]) + ' ' + scope + '_id ' + str(role[1])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Migrate Roles')
    parser.add_argument('--os-auth-url', help='Keystone Auth URL')
    parser.add_argument('--os-domain-name', help='Domain Name')
    parser.add_argument('--os-password', help='Password')
    parser.add_argument('--os-region-name', help='Region Name')
    parser.add_argument('--os-user-domain-name', help='User Domain Name')
    parser.add_argument('--os-username', help='Username')
    parser.add_argument(
        '--do-grants', action='store_true',
        help='Grant equivalent domain_* and project_* role assignments to '
        'those with admin or member roles')

    args = parser.parse_args()

    migrator = RoleMigrationClass(args)

    migrator.handle_migration(
        DOMAIN_SCOPE, ADMIN_ROLE, DOMAIN_ADMIN_ROLE, args.do_grants)
    migrator.handle_migration(
        DOMAIN_SCOPE, MEMBER_ROLE, DOMAIN_MEMBER_ROLE, args.do_grants)
    migrator.handle_migration(
        PROJECT_SCOPE, ADMIN_ROLE, PROJECT_ADMIN_ROLE, args.do_grants)
    migrator.handle_migration(
        PROJECT_SCOPE, MEMBER_ROLE, PROJECT_MEMBER_ROLE, args.do_grants)
