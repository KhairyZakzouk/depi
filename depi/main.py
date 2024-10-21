import xml.etree.ElementTree as ET
import os
import sys
import subprocess
import re
import chardet
import json
import hashlib

malicious=[]
outerdic = {}


def log_initialize(xml_file_path):
    global outerdic  # Declare outerdic as global to modify it within this function
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    i = len(outerdic)  # Start indexing where the last function call left off

    for event in root:
        i += 1
        sysdic = {}
        eventdic = {}
        userdic = {}
        innerdic = {}

        for item in event:
            item_tag = item.tag
            itemkey = item_tag[item_tag.rindex("}") + 1:]

            if itemkey == "System":
                for sub_item in item:
                    value = sub_item.text
                    sub_item_tag = sub_item.tag
                    attributes = sub_item.attrib
                    key = sub_item_tag[sub_item_tag.rindex("}") + 1:]
                    if key == "Provider":
                        sysdic["Provider Name"] = attributes.get("Name", "")
                        sysdic["Provider Guid"] = attributes.get("Guid", "")
                    elif key == "TimeCreated":
                        sysdic["TimeCreated SystemTime"] = attributes.get("SystemTime", "")
                    elif key == "Execution":
                        sysdic["Execution ThreadID"] = attributes.get("ThreadID", "")
                        sysdic["Execution ProcessID"] = attributes.get("ProcessID", "")
                    elif key == "Correlation":
                        sysdic["Correlation ActivityID"] = attributes.get("ActivityID", "")
                    elif key == "Security":
                        sysdic["Security UserID"] = attributes.get("UserID", "")
                    else:
                        sysdic[key] = value

            elif itemkey == "EventData":
                for sub_item in item:
                    value = sub_item.text
                    sub_item_tag = sub_item.tag
                    attributes = sub_item.attrib
                    key = sub_item_tag[sub_item_tag.rindex("}") + 1:]
                    if key == "Data":
                        key = attributes.get('Name', key)
                    eventdic[key] = value

            elif itemkey == "UserData":
                for sub_event in item:
                    for sub_sub_item in sub_event:
                        value = sub_sub_item.text
                        sub_sub_item_tag = sub_sub_item.tag
                        key = sub_sub_item_tag[sub_sub_item_tag.rindex("}") + 1:]
                        userdic[key] = value

        innerdic["System"] = sysdic
        innerdic["EventData"] = eventdic
        innerdic["UserData"] = userdic

        outerdic[i] = innerdic

def process_evtx_to_xml(input_dir):
    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} does not exist or is not a directory.")
        sys.exit(1)

    for filename in os.listdir(input_dir):
        file_path = os.path.join(input_dir, filename)
        if filename.endswith('.evtx'):
            output_xml = os.path.splitext(file_path)[0] + '.xml'
            command = f'wevtutil qe "{file_path}" /lf /f:xml > "{output_xml}"'
            subprocess.run(command, shell=True)
            with open(output_xml, 'rb') as file:
                xml_content = file.read()
            result = chardet.detect(xml_content)
            encoding = result['encoding']
            xml_content = xml_content.decode(encoding)    

            data = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<Events>'
            data += xml_content
            data += '</Events>'
            with open(output_xml, 'w', encoding='utf-8') as file:
                file.write(data)

def process_directory(input_dir):

    process_evtx_to_xml(input_dir)

    for filename in os.listdir(input_dir):
        if filename.endswith('.xml'):
            file_path = os.path.join(input_dir, filename)
            log_initialize(file_path)

def detect_malicious_executable(sysmon_log_path, hash_file):
    process_directory(sysmon_log_path)
    hash_list =[]

    with open(hash_file, "r") as file:
        hash_list = [line.strip() for line in file]

    for k in outerdic:
        if outerdic[k]["System"]["EventID"] == "1":
            hashes = outerdic[k]["EventData"]["Hashes"]
            md5_start_index = hashes.find("MD5=") + len("MD5=")
            md5_end_index = hashes.find(",", md5_start_index)
            md5_hash = hashes[md5_start_index:md5_end_index]
            if md5_hash.lower() in hash_list:
                malicious.append(outerdic[k])


def detect_malicious_hashes_via_folders(input_dir, hash_file):
    # Load known malicious hashes from the database file
    with open(hash_file, "r") as file:
        hash_list = [line.strip().lower() for line in file]  # Ensure lowercase for comparison
    
    # Recursively scan through files in the directory and its subdirectories
    for root, dirs, files in os.walk(input_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)  # Full path of the file

            # Calculate file hash using MD5
            file_hash = calculate_file_hash_md5(file_path)

            # Compare the hash with known malicious hashes
            if file_hash in hash_list:
                # print(f"Malicious file detected: {file_path} (Hash: {file_hash})")  # Display full path
                malicious.append({
                    "file_name": file_name,
                    "file_path": file_path,  # Store the full file path
                    "hash": file_hash
                })

# Function to calculate the MD5 hash of a file
def calculate_file_hash_md5(file_path):
    md5_hash = hashlib.md5()  # Use MD5 hash function
    
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
        return md5_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None


# Main function to perform detection
def detect_malicious():
    # Paths to input directory and malicious hash database
    events = "./Event/"  # Directory to scan for files
    monitor_path='F:\\Final\\depi\\files'
    hash_db = "./malicious_md5_hashes.txt"  # Database of known malicious hashes
    output_file = './detected_malicious_files.json'  # Output file to store results

    # Perform hash-based detection
    detect_malicious_hashes_via_folders(monitor_path, hash_db)
    process_directory(events)
    detect_malicious_executable(events,hash_db)

    # Save detected malicious files to a JSON output
    with open(output_file, 'w') as f:
        json.dump(malicious, f, indent=4)

    print(f"Detection complete. Results saved to {output_file}")

# Run the detection process
detect_malicious()