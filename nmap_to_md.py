import xml.etree.ElementTree as ET
import argparse


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

        # Find all open ports
        ports = host.find('ports')
        if ports is not None:
            markdown_report += "### Open Ports\n\n"
            markdown_report += "| Port | Protocol | Service | State | Version |\n"
            markdown_report += "|------|----------|---------|-------|---------|\n"
            for port in ports.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                service = port.find('service')
                service_name = service.get(
                    'name') if service is not None else 'Unknown'
                version = service.get('version') or "N/A" if service is not None else "N/A"

                markdown_report += f"| {port_id} | {protocol} | {service_name} | {state} | {version} |\n"

        markdown_report += "\n"

    return markdown_report


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
    parser.add_argument("-i", "--input", required=True,
                        help="Path to the Nmap XML report file")
    parser.add_argument("-o", "--output", required=False,
                        help="Path to the output Markdown file")

    # Parse arguments
    args = parser.parse_args()

    # Get the XML file path from the arguments
    input_file = args.input.strip()

    # Default to nmap_report.md if no args are given for the ouput path
    output_file = "nmap_report.md" if not args.output.strip() else args.output.strip()

    # Parse the XML and generate the Markdown report
    markdown_report = parse_nmap_xml(input_file)

    # Save the report to a file
    save_report(markdown_report, output_file)

    print(f"Markdown report generated: {output_file}")
