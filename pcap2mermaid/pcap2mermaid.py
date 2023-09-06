#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert pcap file to Mermaid sequence diagram and save as HTML.

The script uses Tshark to extract packet information such as source and destination IP addresses,
protocols, and information columns. It then creates a Mermaid sequence diagram to visualize the
communication flow between IP addresses and includes the information columns as labels.

The resulting Mermaid diagram is embedded in an HTML template for visualization.

Usage:
    python script.py input_pcap_file

Args:
    input_pcap_file (str): The input pcap file to process.


Example:
    To convert 'input.pcap' to a Mermaid sequence diagram and save it as 'input.pcap.html':
    python script.py input.pcap
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
        '-e', 'ip.proto', '-e', '_ws.col.Info'
    ]
    tshark_output = subprocess.check_output(tshark_command)
    return json.loads(tshark_output)

# Function to generate a Mermaid sequence diagram from the JSON data


def generate_mermaid_sequence_diagram(data):
    """
    Generate a Mermaid sequence diagram from JSON packet data.

    Args:
        data (list): List of dictionaries containing packet information.

    Returns:
        str: A Mermaid sequence diagram in text format.
    """
    diagram = ['sequenceDiagram']
    for packet in data:
        layers = packet['_source']['layers']
        ip_src = layers.get('ip.src', [''])[0]
        ip_dst = layers.get('ip.dst', [''])[0]
        info = layers.get('_ws.col.Info', [''])[0]
        diagram.append(f'{ip_src} ->> {ip_dst}: {info}')
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

    # Print the Mermaid sequence diagram
    print(mermaid_diagram)

    # Write the Mermaid diagram to an HTML file
    output_html_file = f"{input_pcap_file}.html"
    write_out_in_mermaidMarkdown(mermaid_diagram, output_html_file)


if __name__ == '__main__':
    main()
