import collections
import json
from pprint import pprint as pp

from tabulate import tabulate

MAX_DEPTH = 10000

_AND = 'and'
_OR = 'or'
_NOT = 'not'
_SPECIAL = "%"

_ROLE = "role:"
_RULE = "rule:"


def is_api(value):
    return bool(value.startswith('create_') or
                value.startswith('get_') or
                value.startswith('update_') or
                value.startswith('delete_') or
                value.startswith('subnets:') or
                value.startswith('add_router_') or
                value.startswith('remove_router_'))


class Policy(object):

    def __init__(self, file_path):
        self._policy = self._read_policy(file_path)
        self.roles = []
        self.definition_mappings = {}
        self.defined_rules = []
        self.api_rules = {}
        self.unused_rules = []
        self.used_api_rules = {}
        self.used_def_rules = {}
        self._parse()

    @staticmethod
    def _read_policy(file_path):
        with open(file_path) as f:
            data = f.read()
        policies = json.loads(data)
        return policies

    @staticmethod
    def _split_rule(rule):
        elem = []
        roles = []
        for word in rule.split():
            target = None
            if _SPECIAL in word or word in [_AND, _OR, _NOT]:
                # TODO(doublek): Need to validate special ones.
                continue
            if _ROLE in word:
                target = roles
            else:
                target = elem
            word = word.strip('()')
            target.append(word)
        return elem, roles

    def _extract(self):
        extracted_roles = []
        for key, value in self._policy.items():
            elem, role = self._split_rule(value)
            if is_api(key):
                self.api_rules[key] = elem + role
                continue
            extracted_roles.extend(role)
            self.definition_mappings[key] = elem + role
            self.defined_rules.append(key)
        self.roles = set(extracted_roles)

    def _process_rules(self):
        for defined_rule in self.defined_rules:
            used_in_api = []
            used_in_definition = []
            for api, rule in self._policy.items():
                if defined_rule in rule:
                    if is_api(api):
                        used_in_api.append(api)
                    else:
                        used_in_definition.append(api)
            if not used_in_definition and not used_in_api:
                self.unused_rules.append(defined_rule)
            else:
                self.used_api_rules[defined_rule] = used_in_api
                self.used_def_rules[defined_rule] = used_in_definition

    def _expand_definition(self, item):
        contained_roles = []
        depth = 0
        next_item = item
        next_up = collections.deque()
        while depth < MAX_DEPTH:
            if next_item.startswith(_ROLE):
                contained_roles.append(next_item.replace(_ROLE, ''))
            else:
                next_item = next_item.replace(_RULE, '')
                try:
                    next_items = self.definition_mappings[next_item]
                except KeyError:
                    break
                else:
                    next_up.extend(next_items)
            try:
                next_item = next_up.popleft()
            except IndexError:
                break
            depth += 1
        return contained_roles

    def _expand_rule(self, rule):
        role_rule = []
        for item in rule:
            if item.startswith(_ROLE):
                role_rule.append(item.replace(_ROLE, ''))
                continue
            expanded_items = self._expand_definition(item)
            role_rule.extend(expanded_items)
        return role_rule

    def _expand_api_rules(self):
        for api, rule in dict(self.api_rules).items():
            self.api_rules[api] = set(self._expand_rule(rule))

    def _parse(self):
        self._extract()
        self._process_rules()
        self._expand_api_rules()
        return self.api_rules

    def _check_access(self, roles, roles_for_api, target_project_id=None):
        allowed = []
        denied = []
        for role, project_id_and_domain_ids in roles.items():
            project_ids = [p_id for p_id, _ in project_id_and_domain_ids]
            if target_project_id:
                if target_project_id not in project_ids:
                    continue
                if role in roles_for_api:
                    allowed.append((role, [target_project_id]))
                else:
                    denied.append((role, [target_project_id]))
                continue
            if role in roles_for_api:
                allowed.append((role, project_ids))
            else:
                denied.append((role, project_ids))
        return allowed, denied

    def check_access(self, roles, api_method=None, target_project_id=None):
        access_info = {}
        if api_method:
            roles_for_api = self.api_rules[api_method]
            allowed, denied = self._check_access(
                roles, roles_for_api, target_project_id=target_project_id)
            access_info[api_method] = (allowed, denied)
        else:
            for api_method, roles_for_api in self.api_rules.items():
                allowed, denied = self._check_access(
                    roles, roles_for_api, target_project_id=target_project_id)
                access_info[api_method] = (allowed, denied)
        return access_info

    def show_api_rules(self, in_table=True):
        print "-----------"
        print "Used API rules:"
        print "-----------"
        if in_table:
            print tabulate([(k, v)for k, v in self.api_rules.items()],
                           headers=['APIS', 'Rule'],
                           tablefmt='psql')
        else:
            pp(self.api_rules)

    def show_definitions(self, in_table=True, expand=True):
        print "------------------------"
        print "All definitions mappings"
        print "------------------------"
        if expand:
            x = {d: set(self._expand_rule(r))
                 for d, r in dict(self.definition_mappings).items()}
        else:
            x = self.definition_mappings
        if in_table:
            print tabulate(x.items(), headers=['Definition', 'Included Roles'],
                           tablefmt='psql')
        else:
            pp(x)

    def show_intermediates(self):
        print "-----------"
        print "Used API rules:"
        print "-----------"
        print tabulate([(k, v)for k, v in self.used_api_rules.items()],
                       headers=['Definitions', 'APIS'],
                       tablefmt='psql')

        print "-----------"
        print "Used Definition rules:"
        print "-----------"
        print tabulate([(k, v)for k, v in self.used_def_rules.items()],
                       headers=['Definitions', 'Included in definitions'],
                       tablefmt='psql')

        print "-------------"
        print "Unused rules:"
        print "-------------"
        pp(self.unused_rules)

        print "----------------------------"
        print "All defined roles in policy:"
        print "----------------------------"
        pp(self.roles)
