#!/usr/bin/env python
import argparse
import logging

import os_client_config
from tabulate import tabulate

import parser
from utils import *  # noqa


logging.basicConfig(level=logging.ERROR)


def make_keystone_client():
    return os_client_config.make_client('identity')


def get_projects(x):
    return ','.join([v[0] for v in x])


def get_domains(x):
    return ','.join([v[1] for v in x])


# TODO(doublek): Need to check attribute access as well.
class UserData(object):
    def __init__(self, ks_client, username):
        self.ks_client = ks_client
        self.username = username
        self.id_ = None
        self.roles = {}
        self.projects = {}
        self._populate()

    def _get_user_id(self):
        for user in self.ks_client.users.list(domain='default'):
            if user.name == self.username:
                return user.id
        raise Exception('User {0} not found'.format(self.username))

    def _populate(self):
        self.id_ = self._get_user_id()
        _projects = self.ks_client.projects.list(user=self.id_)
        self.projects = {proj.id: proj.name for proj in _projects}

        user_role_assignments = self.ks_client.role_assignments.list(
            user=self.id_)
        for assignment in user_role_assignments:
            role = self.ks_client.roles.get(assignment.role['id'])

            project_id = '-'
            domain_id = '-'
            if 'project' in assignment.scope:
                project_id = assignment.scope['project']['id']
            if 'domain' in assignment.scope:
                domain_id = assignment.scope['domain']['id']

            self.roles.setdefault(role.name, []).append(
                (project_id, domain_id))

    def show_roles(self):
        print_info("Current user roles for user {}:".format(self.username))
        print tabulate([(k, get_projects(v), get_domains(v))
                        for k, v in self.roles.items()],
                       headers=['Role Name', 'Project Ids', 'Domain Ids'],
                       tablefmt='psql')


def _print_granular_info(access_info):
    all_allowed = []
    all_denied = []
    msg = '\t{}: "{}" using role "{}" in projects "{}" domains "{}"'
    for api, info in access_info.items():
        allowed, denied = info
        for role, ids in allowed:
            all_allowed.append(msg.format("OK", api, role,
                                          ', '.join(ids), '-'))
        for role, ids in denied:
            all_denied.append(msg.format("NO", api, role,
                                         ', '.join(ids), '-'))

    print_green("Allowed APIs:")
    for msg in all_allowed:
        print_green(msg)
    print_fail("APIs Not Allowed:")
    for msg in all_denied:
        print_fail(msg)


def _print_by_project(access_info):
    access_by_project = {}
    for api, info in access_info.items():
        allowed, denied = info
        for role, ids in allowed:
            for p_id in ids:
                # Yuck.
                access_by_project\
                    .setdefault(p_id, {})\
                    .setdefault('allowed', {})\
                    .setdefault(role, [])\
                    .append(api)
        for role, ids in denied:
            for p_id in ids:
                # Copy-paste yuck.
                access_by_project\
                    .setdefault(p_id, {})\
                    .setdefault('denied', {})\
                    .setdefault(role, [])\
                    .append(api)
    for project, access in access_by_project.items():
        print_info('Project {0}'.format(project))
        try:
            print_green('\t {0}'.format(', '.join(access['allowed'])))
        except KeyError:
            pass
        try:
            print_fail('\t {0}'.format(', '.join(access['denied'])))
        except KeyError:
            pass


def check(keystone_client, policy, username, api_method=None,
          target_project_id=None, group_by_project=False, show_roles=False):
    data = UserData(keystone_client, username)

    try:
        access_info = policy.check_access(data.roles,
                                          api_method=api_method,
                                          target_project_id=target_project_id)
    except KeyError as ke:
        print_fail('Unknown API "{0}"'.format(ke.message))
        return

    if show_roles:
        data.show_roles()

    if group_by_project:
        _print_by_project(access_info)
    else:
        _print_granular_info(access_info)


if __name__ == '__main__':
    opts = argparse.ArgumentParser()
    opts.add_argument('--target-username')
    opts.add_argument('--path',
                      required=True,
                      default='/etc/neutron/policy.json')
    opts.add_argument('--api-method')
    opts.add_argument('--target-project-id')
    opts.add_argument('--group-by-project', action='store_true')
    opts.add_argument('--show-roles', action='store_true')
    args = opts.parse_args()

    policy = parser.Policy(args.path)
    keystone_client = make_keystone_client()

    check(keystone_client, policy, args.target_username, args.api_method,
          args.target_project_id, args.group_by_project, args.show_roles)
