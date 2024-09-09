import argparse
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Initialize the Markdown report
    markdown_report = "# Nmap Scan Report\n\n"

    # Iterate over each host in the XML
    for host in root.findall('host'):
        addresses = host.findall('address')
        ip_addr = ""
        for addr in addresses:
            if addr.get('addrtype') == 'ipv4':
                ip_addr = addr.get('addr')

        # Skip hosts without IP address
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
            markdown_report += "| Port | Protocol | Service | State |\n"
            markdown_report += "|------|----------|---------|-------|\n"
            for port in ports.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                service = port.find('service')
                service_name = service.get('name') if service is not None else 'Unknown'

                markdown_report += f"| {port_id} | {protocol} | {service_name} | {state} |\n"

        markdown_report += "\n"

    return markdown_report

def save_report(markdown_report, output_file):
    with open(output_file, 'w') as f:
        f.write(markdown_report)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Convert Nmap XML report to Markdown.")
    parser.add_argument("-i", "--input", required=True, help="Path to the Nmap XML report file")
    parser.add_argument("-o", "--output", required=False, help="Path to the output Markdown file")

    # Parse arguments
    args = parser.parse_args()
    input_file = args.input.strip() # Replace with your XML file path
    output_file = "nmap_report.md" if not args.output.strip() else args.output.strip()  # Replace with your desired output path


    # Parse the XML and generate the Markdown report
    markdown_report = parse_nmap_xml(input_file)

    # Save the report to a file
    save_report(markdown_report, output_file)

    print(f"Markdown report generated: {output_file}")