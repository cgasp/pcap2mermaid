#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert pcap file to Mermaid sequence diagram and save as HTML.

The script uses Tshark to extract packet information such as source and destination IP addresses,
protocols, and information columns. It then creates a Mermaid sequence diagram to visualize the
communication flow between IP addresses and includes the information columns as labels.

The resulting Mermaid diagram is embedded in an HTML template for visualization.

Usage:
    python3 pcap2mermaid.py input_pcap_file

Args:
    input_pcap_file (str): The input pcap file to process.


Example:
    To convert 'input.pcap' to a Mermaid sequence diagram and save it as 'input.pcap.html':
    python3 pcap2mermaid.py input.pcap
"""

__author__ = "cgasp"
__version__ = "2023.09.06"
__license__ = "MIT"


import subprocess
import json
import subprocess
import argparse
import os

# Function to run the tshark command and return the JSON output


def run_tshark(input_file):
    """
    Run Tshark to extract packet information from a pcap file and return it as JSON.

    Args:
        input_file (str): The path to the input pcap file.

    Returns:
        dict: A JSON representation of packet information.
    """
    tshark_command = [
        'tshark', '-r', input_file, '-T', 'json',
        '-e', 'frame.number', '-e', 'frame.time', '-e', 'eth.src', '-e', 'eth.dst',
        '-e', 'eth.type', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport',
        '-e', 'tcp.dstport', '-e', 'udp.srcport', '-e', 'udp.dstport',
        '-e', 'ip.proto', '-e', 'ip.proto', '-e', '_ws.col.Info'
    ]
    print(" ".join(tshark_command))
    tshark_output = subprocess.check_output(tshark_command)
    return json.loads(tshark_output)

# Function to generate a Mermaid sequence diagram from the JSON data


def packet_interpreter(data_dict):
    # Interpret ip.proto (assuming it's in decimal format)
    ip_proto_decimal = int(data_dict.get('ip.proto', ['0'])[0])
    # Convert ip.proto to its corresponding protocol name
    ip_proto_name = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        # Add more protocol mappings as needed
    }.get(ip_proto_decimal, f'Unknown ({ip_proto_decimal})')

    # Interpret eth.type (assuming it's in hexadecimal format)
    eth_type_hex = data_dict.get('eth.type', ['0x0000'])[0]
    # Convert eth.type to its corresponding protocol name
    eth_type_name = {
        '0x0800': 'IPv4',
        '0x0806': 'ARP',
        '0x86dd': 'IPv6',  # Handle IPv6
        # Add more eth.type mappings as needed
    }.get(eth_type_hex, f'Unknown ({eth_type_hex})')

    # Get source and destination IP addresses
    src = data_dict.get(
        'ip.src', data_dict.get('eth.src', 'Unknown'))[0]
    dst = data_dict.get(
        'ip.dst', data_dict.get('eth.dst', 'Unknown'))[0]

    # Get source and destination ports if available
    src_port = data_dict.get('udp.srcport', [''])[
        0] or data_dict.get('tcp.srcport', [''])[0]
    dst_port = data_dict.get('udp.dstport', [''])[
        0] or data_dict.get('tcp.dstport', [''])[0]

    # Format the tuple based on ip.proto and eth.type
    if ip_proto_name in ('UDP', 'TCP'):
        net_tuple = f'{src} ->> {dst}: {ip_proto_name} {src_port} > {dst_port}'
    elif eth_type_name == 'IPv4':
        net_tuple = f'{src} ->> {dst}: {ip_proto_name} over {eth_type_name}'
    else:
        net_tuple = f'{src} ->> {dst}: {ip_proto_name} over {eth_type_name}'
    return net_tuple, src


def generate_mermaid_sequence_diagram(data):
    """
    Generate a Mermaid sequence diagram from JSON packet data.

    Args:
        data (list): List of dictionaries containing packet information.

    Returns:
        str: A Mermaid sequence diagram in text format.
    """
    diagram = ['sequenceDiagram']
    participants = set()  # Initialize a set to store unique participants

    for packet in data:
        layers = packet['_source']['layers']
        # ip_src = layers.get('ip.src', [''])[0]
        # ip_dst = layers.get('ip.dst', [''])[0]
        info = layers.get('_ws.col.Info', [''])[0]
        # diagram.append(f'{ip_src} ->> {ip_dst}: {info}')
        net_tuple, src = packet_interpreter(layers)

        # Add source IP to participants set
        participants.add(src)

        diagram.append(f'{net_tuple}: {info}')

    # Add participants to the diagram
    for participant in participants:
        diagram.insert(1, f'participant {participant} as {participant}')

    return '\n'.join(diagram)


# Function to write the Mermaid diagram to an HTML file
def write_out_in_mermaidMarkdown(mermaid_diagram, output_file):
    """
    Write a Mermaid diagram to an HTML file with Mermaid rendering.

    Args:
        mermaid_diagram (str): The Mermaid diagram in text format.
        output_file (str): The path to the output HTML file.
    """
    mermaid_template = f'''
    <html>
    <head>
      <script type="module">
        import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
        mermaid.initialize({{ startOnLoad: true }});
      </script>
    </head>
    <body>
      <div class="mermaid">
      {mermaid_diagram}
      </div>
    </body>
    </html>
    '''

    with open(output_file, 'w') as f:
        f.write(mermaid_template)

# Function to define argparse configuration


def configure_argparse():
    """
    Configure the command-line argument parser for the script.

    Returns:
        argparse.ArgumentParser: An ArgumentParser object with defined arguments.
    """
    parser = argparse.ArgumentParser(
        description='Convert pcap file to Mermaid sequence diagram')
    parser.add_argument('input_file', help='Input pcap file')
    parser.add_argument('--html', action='store_true',
                        help='Generate HTML output')
    parser.add_argument('--mmd', action='store_true',
                        help='Generate MMD output')
    parser.add_argument('--png', action='store_true',
                        help='Generate PNG output')
    return parser


# Main function
def main():
    """
    Main function to convert pcap file to Mermaid sequence diagram.

    Parses command-line arguments, extracts packet data, generates a Mermaid diagram,
    and saves it as an HTML file.
    """
    parser = configure_argparse()
    args = parser.parse_args()
    # Expand path to accept relative path line ~ or ../
    input_pcap_file = os.path.expanduser(args.input_file)

    if not os.path.exists(input_pcap_file):
        print(f"Error: File '{input_pcap_file}' does not exist.")
        return  # Exit the script

    # Run tshark and get JSON output
    tshark_json_output = run_tshark(input_pcap_file)

    # Generate Mermaid sequence diagram
    mermaid_diagram = generate_mermaid_sequence_diagram(tshark_json_output)

    # Print the Mermaid sequence diagram (always)
    print(mermaid_diagram)

    if args.html:
        # Write the Mermaid diagram to an HTML file
        output_html_file = f"{input_pcap_file}.html"
        write_out_in_mermaidMarkdown(mermaid_diagram, output_html_file)
        print(f"HTML file saved as '{output_html_file}'")

    if args.mmd:
        # Write the Mermaid diagram to an MMD (Mermaid Markdown) file
        output_mmd_file = f"{input_pcap_file}.mmd"
        with open(output_mmd_file, 'w') as f:
            f.write(mermaid_diagram)
        print(f"MMD file saved as '{output_mmd_file}'")

    if args.png:
        # Generate PNG from MMD using 'mmdc' command
        # Re-use mmd file
        if args.mmd:
            mmd_file = f"{input_pcap_file}.mmd"
        # create temp file
        else:
            filepath = os.path.basename(input_pcap_file)
            mmd_file = f"/dev/shm/{filepath}.mmd"
            with open(mmd_file, 'w') as f:
                f.write(mermaid_diagram)
        output_png_file = f"{mmd_file}.png"

        try:
            subprocess.run(['mmdc', '-i', mmd_file, '-o',
                           output_png_file], check=True)
            print(f"PNG file saved as '{output_png_file}'")
        except subprocess.CalledProcessError:
            print("Error: Unable to generate PNG file. Ensure 'mmdc' is installed and available in the system PATH.")


if __name__ == '__main__':
    main()
