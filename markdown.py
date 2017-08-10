#!/usr/bin/env python3
from pfsense import PfSenseFlag, PfSenseRuleAlias, PfSenseRuleInterface, PfSenseRuleLocation
from util import dict_to_list, obj_to_dict, obj_to_list, hasattr_r


def format_rule_interface(rule_interface):
    if isinstance(rule_interface, list):
        rule_interface = ', '.join(map(format_rule_interface, rule_interface))
    elif isinstance(rule_interface, dict):
        if 'descr' in rule_interface['interface']:
            rule_interface = '[{name}](#interfaces "{descr}")'.format(**rule_interface['interface'])
        else:
            rule_interface = rule_interface['interface']['name']
    return str(rule_interface)

def format_rule_alias(rule_alias):
    if isinstance(rule_alias, dict):
        if 'alias' in rule_alias:
            if 'address' in rule_alias['alias']:
                rule_alias = '[{name}](#aliases "{address}")'.format(**rule_alias['alias'])
            else:
                rule_alias = rule_alias['alias']['name']
        elif 'interface' in rule_alias:
            if 'descr' in rule_alias['interface']:
                rule_alias = '[{name}](#interfaces "{descr}")'.format(**rule_alias['interface'])
            else:
                rule_alias = rule_alias['interface']['name']
    return str(rule_alias)

def format_rule_location(rule_location):
    if isinstance(rule_location, PfSenseRuleAlias):
        rule_location = format_rule_alias(rule_location.data)
    return str(rule_location)

def format_markdown_cell(cell):
    if cell is True or isinstance(cell, PfSenseFlag):
        cell = 'x'
    elif isinstance(cell, PfSenseRuleAlias):
        cell = format_rule_alias(cell.data)
    elif isinstance(cell, PfSenseRuleInterface):
        cell = format_rule_interface(cell.data)
    elif isinstance(cell, PfSenseRuleLocation):
        data = ''
        if hasattr(cell, 'any'):
            data += 'any'
        elif hasattr(cell, 'address'):
            data += format_rule_location(cell.address)
        elif hasattr(cell, 'network'):
            data += format_rule_location(cell.network)
        if hasattr(cell, 'port'):
            data += ':'
            data += str(cell.port)
        cell = data
    return str(cell).replace('|', '\\|')

def output_markdown_table(stream, header, rows):
    # Header
    stream.write("| ")
    stream.write(" | ".join(header))
    stream.write(" |\n")
    # Seperator
    stream.write("| ")
    stream.write(" | ".join(map(lambda x: '-'*len(x), header)))
    stream.write(" |\n")
    # Rows
    for row in rows:
        stream.write("| ")
        stream.write(" | ".join(map(format_markdown_cell, row)))
        stream.write(" |\n")

def output_markdown(doc, stream):
    stream.write("# pfSense\n")
    stream.write("Version {}\n".format(doc.pfsense.version))
    stream.write("\n")

    stream.write("## System\n")
    info = obj_to_dict(doc.pfsense.system, ('hostname', 'domain', 'timeservers', 'timezone', 'language', 'dnsserver'))
    output_markdown_table(stream, ('Option', 'Value'), info.items())
    stream.write("\n")

    if hasattr_r(doc.pfsense, 'interfaces'):
        stream.write("## Interfaces\n")
        interfaces = sorted(doc.pfsense.interfaces.data.items(), key=lambda interface: interface[0])
        interfaces = [[interface_name]+dict_to_list(interface_data, ('enable', 'descr', 'if', 'ipaddr', 'subnet')) for interface_name, interface_data in interfaces]
        output_markdown_table(stream, ('Name', 'Enabled', 'Description', 'Interface', 'Address', 'Subnet'), interfaces)
        stream.write("\n")

    if hasattr_r(doc.pfsense, 'aliases.alias'):
        stream.write("## Aliases\n")
        aliases = [obj_to_list(alias, ('name', 'type', 'address', 'descr', 'detail')) for alias in doc.pfsense.aliases.alias]
        output_markdown_table(stream, ('Name', 'Type', 'Address', 'Description', 'Detail'), aliases)
        stream.write("\n")

    if hasattr_r(doc.pfsense, 'nat.rule'):
        stream.write("## NAT rules\n")
        rules = [obj_to_list(rule, ('disabled', 'interface', 'source', 'destination', 'protocol', 'target', 'local_port', 'descr')) for rule in doc.pfsense.nat.rule]
        output_markdown_table(stream, ('Disabled', 'Interface', 'Source', 'Destination', 'Protocol', 'Target', 'Local port', 'Description'), rules)
        stream.write("\n")

    if hasattr_r(doc.pfsense, 'nat.outbound.rule'):
        stream.write("## Outbound NAT rules\n")
        rules = [obj_to_list(rule, ('disabled', 'interface', 'source', 'destination', 'dstport', 'protocol', 'target', 'descr')) for rule in doc.pfsense.nat.outbound.rule]
        output_markdown_table(stream, ('Disabled', 'Interface', 'Source', 'Destination', 'Destination port', 'Protocol', 'Target', 'Description'), rules)
        stream.write("\n")

    if hasattr_r(doc.pfsense, 'filter.rule'):
        stream.write("## Filter rules\n")
        rules = [obj_to_list(rule, ('disabled', 'interface', 'type', 'ipprotocol', 'protocol', 'source', 'destination', 'descr')) for rule in doc.pfsense.filter.rule]
        output_markdown_table(stream, ('Disabled', 'Interface', 'Type', 'IP', 'Protocol', 'Source', 'Destination', 'Description'), rules)
        stream.write("\n")
