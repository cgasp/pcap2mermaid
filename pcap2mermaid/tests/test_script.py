import unittest
import os
import json
from io import StringIO
from pcap2mermaid import run_tshark, generate_mermaid_sequence_diagram, write_out_in_mermaidMarkdown


class TestScriptFunctions(unittest.TestCase):

    def test_run_tshark(self):
        # Create a test pcap file (for demonstration purposes)
        test_pcap_data = [
            {
                '_source': {
                    'layers': {
                        'frame.number': ['1'],
                        'frame.time': ['Jun 21, 2020 14:50:08.824079000 CEST'],
                        'eth.src': ['a4:83:e7:17:09:33'],
                        'eth.dst': ['1c:3b:f3:3c:04:26'],
                        'eth.type': ['0x0800'],
                        'ip.src': ['192.168.0.107'],
                        'ip.dst': ['8.8.8.8'],
                        'udp.srcport': ['65137'],
                        'udp.dstport': ['53'],
                        'ip.proto': ['17'],
                        '_ws.col.Info': ['Test Packet 1']
                    }
                }
            },
            {
                '_source': {
                    'layers': {
                        'frame.number': ['2'],
                        'frame.time': ['Jun 21, 2020 14:50:08.987412000 CEST'],
                        'eth.src': ['1c:3b:f3:3c:04:26'],
                        'eth.dst': ['a4:83:e7:17:09:33'],
                        'eth.type': ['0x0800'],
                        'ip.src': ['8.8.8.8'],
                        'ip.dst': ['192.168.0.107'],
                        'udp.srcport': ['53'],
                        'udp.dstport': ['65137'],
                        'ip.proto': ['17'],
                        '_ws.col.Info': ['Test Packet 2']
                    }
                }
            }
        ]

        # Create a temporary JSON file to simulate Tshark output
        with open('test_tshark_output.json', 'w') as temp_file:
            json.dump(test_pcap_data, temp_file)

        # Run run_tshark with the test file
        tshark_output = run_tshark('test_tshark_output.json')

        # Clean up the temporary file
        os.remove('test_tshark_output.json')

        # Ensure the output matches the expected data
        self.assertEqual(tshark_output, test_pcap_data)

    def test_generate_mermaid_sequence_diagram(self):
        # Sample packet data for testing
        packet_data = [
            {
                '_source': {
                    'layers': {
                        'ip.src': ['192.168.0.1'],
                        'ip.dst': ['192.168.0.2'],
                        '_ws.col.Info': ['Packet 1']
                    }
                }
            },
            {
                '_source': {
                    'layers': {
                        'ip.src': ['192.168.0.2'],
                        'ip.dst': ['192.168.0.1'],
                        '_ws.col.Info': ['Packet 2']
                    }
                }
            }
        ]

        expected_diagram = "sequenceDiagram\n192.168.0.1 ->> 192.168.0.2: Packet 1\n192.168.0.2 ->> 192.168.0.1: Packet 2"

        # Test generate_mermaid_sequence_diagram function
        diagram = generate_mermaid_sequence_diagram(packet_data)
        self.assertEqual(diagram, expected_diagram)

    def test_write_out_in_mermaidMarkdown(self):
        # Create a temporary Mermaid diagram
        mermaid_diagram = "sequenceDiagram\nA->>B: Message"

        # Redirect sys.stdout to capture the print output
        captured_output = StringIO()
        import sys
        sys.stdout = captured_output

        # Call write_out_in_mermaidMarkdown with a temporary HTML file
        with open('test_output.html', 'w') as temp_file:
            write_out_in_mermaidMarkdown(mermaid_diagram, temp_file.name)

        # Reset sys.stdout
        sys.stdout = sys.__stdout__

        # Read the contents of the captured print
        printed_output = captured_output.getvalue()

        # Clean up the temporary HTML file
        os.remove('test_output.html')

        # Ensure that the HTML content contains the Mermaid diagram
        self.assertIn(mermaid_diagram, printed_output)


if __name__ == '__main__':
    unittest.main()
