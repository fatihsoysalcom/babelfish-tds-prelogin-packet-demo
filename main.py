import socket
import struct
import sys
import time

def create_simple_tds_prelogin_packet():
    """
    Creates a simplified, non-malicious TDS Pre-Login packet.
    This demonstrates the byte-level structure of the TDS protocol
    where pre-authentication vulnerabilities can arise due to malformed
    offsets, lengths, or unexpected data during parsing.
    """
    
    # TDS Packet Header (8 bytes): Type, Status, Length, SPID, PacketID, Window
    TDS_PACKET_TYPE_PRELOGIN = 0x12
    
    # Options structure:
    # Each option: ID (1 byte), Offset (2 bytes), Length (2 bytes)
    # Followed by the actual option data.
    # Offsets are relative to the start of the options data section.

    # We'll include dummy Version and Encryption options.
    
    # --- Options Data ---
    # Dummy Version (4 bytes): Represents a client TDS version.
    version_data = b'\x00\x00\x00\x00' 
    # Dummy Encryption (1 byte): Represents encryption setting (e.g., no encryption).
    encryption_data = b'\x00'
    
    options_data_section = version_data + encryption_data
    
    # --- Options Metadata ---
    # This section describes where each option's data is located within options_data_section.
    # It also includes an End marker (0xFF).
    
    # Calculate offsets for options_data_section:
    # Version data starts at offset 0
    # Encryption data starts at offset 4 (after 4 bytes of version data)
    
    # Metadata for Version option (ID=0x00):
    # ID (1 byte) + Offset (2 bytes) + Length (2 bytes) = 5 bytes
    version_metadata = struct.pack('>BHH', 0x00, 0, len(version_data)) # ID, Offset, Length
    
    # Metadata for Encryption option (ID=0x01):
    # ID (1 byte) + Offset (2 bytes) + Length (2 bytes) = 5 bytes
    encryption_metadata = struct.pack('>BHH', 0x01, len(version_data), len(encryption_data)) # ID, Offset, Length
    
    # End of options marker
    end_marker = struct.pack('>B', 0xFF)
    
    options_metadata_section = version_metadata + encryption_metadata + end_marker
    
    # --- Full Packet Assembly ---
    # Total packet length includes header, options metadata, and options data.
    total_packet_length = 8 + len(options_metadata_section) + len(options_data_section)

    # Packet Header: Type, Status (EOM), Length, SPID, PacketID, Window
    # '>BBHHBB' -> Big-endian: byte, byte, short, short, byte, byte
    header = struct.pack('>BBHHBB',
                         TDS_PACKET_TYPE_PRELOGIN,
                         0x01, # Status: EOM (End Of Message)
                         total_packet_length,
                         0x0000, # SPID (Server Process ID - dummy for pre-login)
                         0x01,   # PacketID (dummy)
                         0x00)   # Window (dummy)

    # Combine all parts
    tds_packet = header + options_metadata_section + options_data_section
    
    # Verify calculated length matches actual length
    if len(tds_packet) != total_packet_length:
        print(f"Error: Packet length mismatch! Expected {total_packet_length}, got {len(tds_packet)}")
        sys.exit(1)

    return tds_packet

def main():
    # Babelfish typically listens on the default SQL Server port (1433)
    # or a custom port configured in AWS RDS/Aurora.
    # For this example, we'll use localhost:1433 as a placeholder.
    # You would replace this with your Babelfish endpoint.
    TARGET_HOST = "127.0.0.1" # Or your Babelfish endpoint, e.g., "your-babelfish-instance.xxxx.rds.amazonaws.com"
    TARGET_PORT = 1433

    print(f"Attempting to simulate a basic TDS Pre-Login handshake with {TARGET_HOST}:{TARGET_PORT}")
    print("This example demonstrates the byte-level nature of the TDS protocol,")
    print("where pre-authentication vulnerabilities (like RCE discussed in the article)")
    print("can arise from malformed packets or unexpected data during server parsing.")
    print("-" * 70)

    tds_prelogin_packet = create_simple_tds_prelogin_packet()

    print(f"Generated TDS Pre-Login packet ({len(tds_prelogin_packet)} bytes):")
    print(f"  Hex: {tds_prelogin_packet.hex()}")
    print(f"  ASCII (partial): {tds_prelogin_packet[:20].decode('latin-1', errors='ignore')}...")
    print("-" * 70)

    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5) # Set a timeout for connection and receive operations
            print(f"Connecting to {TARGET_HOST}:{TARGET_PORT}...")
            sock.connect((TARGET_HOST, TARGET_PORT))
            print("Connection established. Sending Pre-Login packet...")
            
            # Send the crafted TDS Pre-Login packet
            sock.sendall(tds_prelogin_packet)
            print("Packet sent. Awaiting response...")

            # Receive response (Babelfish/SQL Server would send a Pre-Login response)
            response = sock.recv(4096) # Read up to 4KB
            
            if response:
                print(f"Received response ({len(response)} bytes):")
                print(f"  Hex: {response.hex()}")
                print(f"  ASCII (partial): {response[:20].decode('latin-1', errors='ignore')}...")
                print("\nNote: A real Babelfish/SQL Server would send a proper Pre-Login response.")
                print("This example only demonstrates sending the initial client packet.")
            else:
                print("No response received from the server (or connection closed).")

    except ConnectionRefusedError:
        print(f"Error: Connection refused. Is a Babelfish/SQL Server instance running on {TARGET_HOST}:{TARGET_PORT}?")
        print("This example requires a TDS-compatible server to be listening.")
    except socket.timeout:
        print(f"Error: Connection or response timed out after 5 seconds.")
        print("Ensure the target server is reachable and responsive.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        print("-" * 70)
        print("Simulation complete.")

if __name__ == "__main__":
    main()
