"""
AV Production Analysis Test - Dotan Sadka

This script reads a hex dump log file, extracts and unescapes packets, validates frame checksums (FCS),
extracts speed data from packet contents, saves results to CSV files, and plots the speed over frames.

Please make sure that Parser 2.3 1.txt is in the same folder so it can read it properly
"""
import re
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import csv

# Load hex data from file
file_path = Path("Parser 2.3 1.txt")
with open(file_path, "r") as file:
    hex_data = file.read()

# Convert hex to byte array
bytes_list = re.findall(r"[0-9A-Fa-f]{2}", hex_data)
raw_bytes = bytearray(int(byte, 16) for byte in bytes_list)

# Unescape function (7D 5E → 7E, 7D 5D → 7D)
def unescape_data(data):
    unescaped = []
    i = 0
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            if i < len(data):
                if data[i] == 0x5E:
                    unescaped.append(0x7E)
                elif data[i] == 0x5D:
                    unescaped.append(0x7D)
        else:
            unescaped.append(data[i])
        i += 1
    return unescaped



# Extract escaped packets from raw byte stream
escaped_packets = []
current = []
inside_packet = False

for byte in raw_bytes:
    if byte == 0x7E:
        if inside_packet and current:
            escaped_packets.append(current)
            current = []
        inside_packet = True
    elif inside_packet:
        current.append(byte)

# Calculate and validate FCS for each unescaped packet
def calculate_fcs(packet):
    unescaped = unescape_data(packet)
    #print(unescaped)    
    data_section = unescaped[:-1]  # All but FCS
    given_fcs = unescaped[-1]      # Last byte is FCS
    calculated_fcs = 0xFF - (sum(data_section) % 256)
    return {
        "Calculated FCS": calculated_fcs,
        "Given FCS": given_fcs,
        "Valid": calculated_fcs == given_fcs
    }

# Apply FCS validation to all packets
fcs_results_fixed = []
for pkt in escaped_packets:
    fcs = calculate_fcs(pkt)
    if fcs is not None:
        fcs_results_fixed.append(fcs)

# Create DataFrame from FCS results
df_fcs = pd.DataFrame(fcs_results_fixed)

# Save DataFrame to CSV
# indexes increased by 1 for better compatibility with the parser text file
df_fcs.index = df_fcs.index + 1
df_fcs.to_csv("fcs_validation_results.csv", index=True)


# Use full data part bytes 2 to 18 (17 bytes) (without Header and FCS)

def extract_speed_from_packet_v2(packet):
    """
Extracts speed value from packet data.

Parameters:
    packet (list[int]): Unescaped packet byte list.

Returns:
    float: Speed extracted from bits 9 to 20.
"""
    unescaped = unescape_data(packet)
    data = unescaped[2:19] #remove header (2 bytes) and FCS (1 byte), keep data part (17 bytes)
    
    # Convert all 17 bytes to int, little endian
    raw = int.from_bytes(data, byteorder='little')
    
    # Extract bits 9 to 20 (12 bits), one-based so shift right by 8
    speed_raw = (raw >> 8) & 0xFFF    #0xFFF is 12 bits mask
    speed = speed_raw * 0.1
    #print(speed)
    return speed

# Extract speeds
speeds = []
for pkt in escaped_packets:
    try:
        speed = extract_speed_from_packet_v2(pkt)
        if speed is not None:
            speeds.append(speed)
    except Exception as e:
        speeds.append(None)  # In case of unexpected issues

# Create DataFrame from speeds list
df_speed = pd.DataFrame(speeds, columns=["Speed (km/h)"])

# Adjust index to start from 1
df_speed.index = df_speed.index + 1

# Save DataFrame to CSV
df_speed.to_csv("extracted_speeds.csv", index=True)


# Plotting
plt.figure(figsize=(10, 5))
plt.plot(speeds, marker='o', linestyle='-', color='blue', markersize=3)
plt.title("Extracted Speed per Frame")
plt.xlabel("Frame Index")
plt.ylabel("Speed")
plt.grid(True)
plt.tight_layout()
plt.show()