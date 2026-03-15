#!/usr/bin/env python

import xml.etree.ElementTree as ET
import argparse
import sys


def build_markdown_report(root):
    """Builds a Markdown report from a parsed Nmap XML root element."""
    markdown_report = "# Nmap Scan Report\n\n"

    # Iterate over each host in the XML
    for host in root.findall('host'):
        addresses = host.findall('address')
        ip_addr = ""
        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                ip_addr = addr.get('addr')

        if not ip_addr:
            continue

        markdown_report += f"## Host: {ip_addr}\n"

        # Fetch hostname if available
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                markdown_report += f"**Hostname:** {hostname.get('name')}\n\n"

        # Fetch status
        status = host.find('status')
        if status is not None:
            markdown_report += f"**Status:** {status.get('state')}\n\n"

        ports = host.find('ports')
        if ports is not None:
            port_entries = ports.findall('port')
            if port_entries:
                markdown_report += "### Open Ports\n\n"
                markdown_report += "| Port | Protocol | Service | State | Version |\n"
                markdown_report += "|------|----------|---------|-------|---------|\n"
                for port in port_entries:
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'Unknown'
                    version = service.get('version') if service is not None else None
                    version = version if version else "N/A"

                    markdown_report += f"| {port_id} | {protocol} | {service_name} | {state} | {version} |\n"
            else:
                markdown_report += "### Port Summary\n\n"
                extraports = ports.findall('extraports')
                if extraports:
                    markdown_report += "No explicit port entries were returned for this host.\n\n"
                    markdown_report += "| State | Count |\n"
                    markdown_report += "|-------|-------|\n"
                    for extra in extraports:
                        state = extra.get('state', 'unknown')
                        count = extra.get('count', '0')
                        markdown_report += f"| {state} | {count} |\n"
                else:
                    markdown_report += "No port information available in the Nmap XML output.\n"

        markdown_report += "\n"

    return markdown_report


def parse_nmap_xml(xml_file):
    """
    Parses an Nmap XML file and generates a Markdown report.

    Args:
        xml_file (str): The path to the Nmap XML file.

    Returns:
        str: The generated Markdown report.
    """

    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    return build_markdown_report(root)


def parse_nmap_xml_string(xml_content):
    """
    Parses Nmap XML content from a string and generates a Markdown report.

    Args:
        xml_content (str): Raw Nmap XML content.

    Returns:
        str: The generated Markdown report.
    """
    root = ET.fromstring(xml_content)

    return build_markdown_report(root)


def save_report(markdown_report, output_file):
    """
    Save the generated Markdown report to a file.

    Args:
        markdown_report (str): The Markdown report to be saved.
        output_file (str): The path to the output Markdown file.
    """
    with open(output_file, 'w') as f:
        f.write(markdown_report)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Convert Nmap XML report to Markdown.")
    parser.add_argument("-i", "--input", required=False,
                        help="Path to the Nmap XML report file")
    parser.add_argument("-o", "--output", required=False,
                        help="Path to the output Markdown file")

    # Parse arguments
    args = parser.parse_args()

    markdown_report = ""
    used_stdin = False

    # Use file input when provided; otherwise, read XML from stdin.
    try:
        if args.input:
            input_file = args.input.strip()
            markdown_report = parse_nmap_xml(input_file)
        else:
            used_stdin = True
            stdin_content = sys.stdin.read()
            if not stdin_content.strip():
                parser.error("No input provided. Use -i/--input or pipe Nmap XML into stdin.")
            markdown_report = parse_nmap_xml_string(stdin_content)
    except ET.ParseError:
        parser.error(
            "Input is not valid Nmap XML. For piping, run nmap with XML output: nmap <target> -T4 -A -v -oX - | ./nmap_to_md.py"
        )

    if args.output:
        output_file = args.output.strip()

        # Save the report to a file
        save_report(markdown_report, output_file)
        print(f"Markdown report generated: {output_file}")
    elif used_stdin:
        # Pipeline-friendly behavior: print markdown to stdout when reading stdin.
        print(markdown_report, end="")
    else:
        output_file = "output.md"

        save_report(markdown_report, output_file)
        print(f"Markdown report generated: {output_file}")
