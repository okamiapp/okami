import os
import sys
import logging
from tqdm import tqdm
import pefile
import lief
from capstone import *
import humanize
import filetype
import sqlite3
import pandas as pd
import requests
import zipfile
import io
from concurrent.futures import ThreadPoolExecutor
import readline
from datetime import datetime
import hashlib

# Initialize logging
logger = logging.getLogger('OkamiLogger')
logger.setLevel(logging.DEBUG)

# Create console handler and set level to WARNING
ch = logging.StreamHandler()
ch.setLevel(logging.WARNING)

# Create file handler and set level to DEBUG
fh = logging.FileHandler('okami.log')
fh.setLevel(logging.DEBUG)

# Create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(ch)
logger.addHandler(fh)

# Global variables
current_db = 'Okami.db'
exit_after_download = False

def display_progress_indicator(description):
    print(description)

def save_disassembly_to_file(disassembly, filename='disassembly_output.txt'):
    try:
        with open(filename, 'w') as f:
            f.write(disassembly)
        file_size = os.path.getsize(filename)
        human_readable_size = humanize.naturalsize(file_size)
        logger.info(f"Disassembly output saved to {filename} ({human_readable_size}).")
        print(f"Disassembly output saved to {filename} ({human_readable_size}).")
    except Exception as e:
        logger.error(f"Error saving disassembly to file: {e}")
        print(f"Error saving disassembly to file: {e}")

def log_all_sections(pe):
    for section in pe.sections:
        section_name = section.Name.decode().strip()
        characteristics = section.Characteristics
        logger.info(f"Section: {section_name}, Characteristics: {characteristics}")

def log_all_elf_sections(elf):
    for section in elf.sections:
        section_name = section.name
        flags = section.flags
        logger.info(f"Section: {section_name}, Flags: {flags}")

def is_executable_section(section):
    return section.Characteristics & 0x20000020 != 0

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def disassemble_code(md, code, base_address):
    disassembled_code = []
    for instruction in md.disasm(code, base_address):
        disassembled_code.append(f"{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
    return disassembled_code

def process_pe_file(binary_name):
    try:
        pe = pefile.PE(binary_name)
        file_size = os.path.getsize(binary_name)
        file_type = 'PE'
        architecture = 'x86' if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else 'x64'
        timestamp = datetime.now()
        file_sha256 = calculate_sha256(binary_name)

        code = None
        base_address = None
        possible_sections = [b'.text', b'.code', b'.textbss', b'.init', b'.data']

        log_all_sections(pe)

        for section in pe.sections:
            logger.info(f"Found section: {section.Name}")
            if any(s in section.Name for s in possible_sections):
                if is_executable_section(section):
                    code = section.get_data()
                    base_address = section.VirtualAddress
                    break

        if not code:
            for section in pe.sections:
                if is_executable_section(section):
                    code = section.get_data()
                    base_address = section.VirtualAddress
                    break

        if not code:
            logger.error("No executable code section found in the PE file.")
            return [], file_size, file_type, architecture, timestamp, file_sha256

        md = Cs(CS_ARCH_X86, CS_MODE_32 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL
        disassembly_output = []

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT.symbols:
            symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
            logger.info("Export directory found, using exports for disassembly.")
            for entry in symbols:
                func_address = entry.address
                func_name = entry.name.decode('utf-8') if entry.name else f'func_{func_address:x}'
                func_code = code[func_address - base_address:]
                function_end = func_address + len(func_code)
                instruction_count = len(list(md.disasm(func_code, func_address)))
                function_size = len(func_code)
                disassembly_output.append((func_name, disassemble_code(md, func_code, func_address), func_address, function_end, instruction_count, function_size))
        else:
            logger.info("No export directory found, scanning for functions in executable sections.")
            disassembly_output.extend(scan_for_functions(md, code, base_address, binary_name))

        return disassembly_output, file_size, file_type, architecture, timestamp, file_sha256
    except pefile.PEFormatError as e:
        logger.error(f"PEFormatError: {e}")
        return [], None, None, None, None, None
    except Exception as e:
        logger.error(f"Error processing PE file: {e}")
        return [], None, None, None, None, None

def process_elf_file(binary_name):
    try:
        elf = lief.parse(binary_name)
        file_size = os.path.getsize(binary_name)
        file_type = 'ELF'
        architecture = 'x86' if elf.header.machine_type == lief.ELF.ARCH.i386 else 'x64'
        timestamp = datetime.now()
        file_sha256 = calculate_sha256(binary_name)

        code = None
        base_address = None

        if elf.sections:
            possible_sections = ['.text', '.init', '.fini']

            log_all_elf_sections(elf)

            for section in elf.sections:
                if section.name in possible_sections:
                    code = section.content
                    base_address = section.virtual_address
                    break

            if not code:
                for section in elf.sections:
                    if section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR:
                        code = section.content
                        base_address = section.virtual_address
                        break
        else:
            with open(binary_name, 'rb') as f:
                code = f.read()
                base_address = 0

        if not code:
            logger.error("No executable code section found in the ELF file.")
            return [], file_size, file_type, architecture, timestamp, file_sha256

        md = Cs(CS_ARCH_X86, CS_MODE_32 if elf.header.machine_type == lief.ELF.ARCH.i386 else CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL
        disassembly_output = []

        if any(sec.name == '.symtab' for sec in elf.sections):
            symbol_section = next(sec for sec in elf.sections if sec.name == '.symtab')
            logger.info("Symbol table found, using symbols for disassembly.")
            for symbol in elf.symbols:
                if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                    func_address = symbol.value
                    func_size = symbol.size
                    func_name = symbol.name or f'func_{func_address:x}'
                    func_code = code[func_address - base_address:func_address - base_address + func_size]
                    disassembly_output.append((func_name, disassemble_code(md, func_code, func_address), func_address, func_address + func_size, len(list(md.disasm(func_code, func_address))), func_size))
        else:
            logger.info("No symbol table found, scanning for functions in executable sections.")
            disassembly_output.extend(scan_for_functions(md, code, base_address, binary_name))

        return disassembly_output, file_size, file_type, architecture, timestamp, file_sha256
    except Exception as e:
        logger.error(f"Error processing ELF file: {e}")
        return [], None, None, None, None, None

def scan_for_functions(md, code, base_address, filename):
    try:
        disassembly_output = []
        code_length = len(code)
        with tqdm(total=code_length, desc=f"Analysing ({filename})", unit="byte", dynamic_ncols=True, leave=False) as pbar:
            functions = scan_for_instructions(md, code, base_address, pbar)
            for function in functions:
                disassembly_output.append((function['name'], function['bytecode'], function['address'], function['address'] + len(function['bytecode']), len(function['bytecode']), len(function['bytecode'])))
                pbar.update(len(function["bytecode"]))

                if pbar.n % 1000 == 0:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print(pbar)

        return disassembly_output
    except Exception as e:
        logger.error(f"Error Analysing: {e}")
        return []

def scan_for_instructions(md, code, base_address, pbar):
    functions = []
    current_function = None
    for i in range(len(code)):
        try:
            for insn in md.disasm(code[i:], base_address + i):
                hex_bytes = ' '.join([f"{byte:02x}" for byte in insn.bytes])

                if insn.mnemonic == 'push' and insn.op_str == 'ebp':
                    if current_function:
                        functions.append(current_function)
                    current_function = {
                        "name": f"Function: {insn.address:x} at 0x{insn.address:x}",
                        "address": insn.address,
                        "bytecode": []
                    }

                elif insn.mnemonic == 'ret' or insn.mnemonic == 'retf':
                    if current_function:
                        current_function["bytecode"].append(hex_bytes)
                        functions.append(current_function)
                        current_function = None
                    continue

                if current_function:
                    current_function["bytecode"].append(hex_bytes)
                break

        except CsError:
            continue

        if i % 1000 == 0:
            pbar.update(1000)

    if current_function:
        functions.append(current_function)

    return functions

def heuristic_based_detection(md, code, base_address):
    disassembly_output = []
    current_function = None
    instruction_count = 0

    for i in range(len(code)):
        try:
            for insn in md.disasm(code[i:], base_address + i):
                hex_bytes = ' '.join([f"{byte:02x}" for byte in insn.bytes])
                instruction_count += 1

                if insn.mnemonic == 'push' and insn.op_str == 'ebp':
                    if current_function:
                        disassembly_output.append(current_function)
                    current_function = {
                        "name": f"Function: {insn.address:x} at 0x{insn.address:x}",
                        "address": insn.address,
                        "bytecode": []
                    }

                elif insn.mnemonic == 'ret' or insn.mnemonic == 'retf':
                    if current_function:
                        current_function["bytecode"].append(hex_bytes)
                        disassembly_output.append(current_function)
                        current_function = None
                    continue

                if current_function:
                    current_function["bytecode"].append(hex_bytes)
                break

        except CsError:
            continue

    if current_function:
        disassembly_output.append(current_function)

    if not disassembly_output and instruction_count > 0:
        logger.error("Heuristic-based detection did not find any executable code.")
    elif instruction_count == 0:
        logger.error("No instructions found during heuristic-based detection.")

    return disassembly_output

def run_okami_disassembler(filename):
    try:
        if not os.path.isfile(filename):
            logger.error(f"File not found: {filename}")
            return [], filename, None, None, None, None, None

        file_sha256 = calculate_sha256(filename)

        if is_duplicate_sample(file_sha256):
            logger.info(f"File '{filename}' is a duplicate. Skipping disassembly.")
            print(f"The Provided Sample ({filename}) is a 100% match to an existing file in the database.")
            return [], filename, file_sha256, None, None, None, None

        kind = filetype.guess(filename)
        if kind is None:
            logger.error(f"Cannot guess the file type for {filename}!")
            return [], filename, file_sha256, None, None, None, None

        disassembly_output = []
        file_size = None
        file_type = None
        architecture = None
        timestamp = None

        if kind.extension == 'elf':
            disassembly_output, file_size, file_type, architecture, timestamp, file_sha256 = process_elf_file(filename)
        elif kind.extension == 'exe':
            disassembly_output, file_size, file_type, architecture, timestamp, file_sha256 = process_pe_file(filename)
        else:
            logger.error(f"Unsupported binary format for disassembly for {filename}.")
            return [], filename, file_sha256, None, None, None, None

        return disassembly_output, filename, file_sha256, file_size, file_type, architecture, timestamp
    except Exception as e:
        logger.error(f"Error in disassembler function for {filename}: {e}")
        return [], filename, None, None, None, None, None

def is_duplicate_sample(file_sha256):
    try:
        with sqlite3.connect(current_db) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT file_sha256 FROM file_hashes WHERE file_sha256 = ?', (file_sha256,))
            row = cursor.fetchone()
        if row:
            return True
        else:
            return False
    except Exception as e:
        logger.error(f"Error checking for duplicate sample: {e}")
        return False

def analyze_and_add_samples():
    global current_db
    ensure_default_database()
    clear_console()
    current_db_display = current_db if current_db else "(no database selected)"
    print(f"\nAnalyze and Add Samples: [Current Database: {current_db_display}]")

    filenames = upload_and_process_files()
    if not filenames:
        input("\nPress Enter to return to the main menu.")
        return

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_okami_disassembler, filename): filename for filename in filenames}
        for future in futures:
            disassembly_output, processed_filename, file_sha256, file_size, file_type, architecture, timestamp = future.result()
            if disassembly_output:
                clear_console()
                store_file_hashes(disassembly_output, current_db, os.path.basename(processed_filename), file_size, file_type, architecture, timestamp, file_sha256)
                clear_console()
                find_closest_match(os.path.basename(processed_filename), current_db, file_sha256)
                input("\nPress Enter to continue to the next file or return to the main menu.\n")
            elif file_sha256:
                clear_console()
                print(f"The Provided Sample ({processed_filename}) is a 100% match to an existing file in the database.")
                input("\nPress Enter to continue to the next file or return to the main menu.\n")
            else:
                logger.error(f"Failed to analyze file: {processed_filename}")

    input("\nPress Enter to return to the main menu.")

def upload_and_process_files():
    try:
        enable_auto_complete()
        filenames = input("Enter the path to the files to upload (comma separated for multiple files): ").strip().split(',')
        filenames = [filename.strip() for filename in filenames if filename.strip()]
        if not filenames:
            logger.error("No files uploaded.")
            print("Error: No files uploaded.")
            return []

        print(f"Files uploaded: {', '.join(filenames)}")
        clear_console()
        return filenames
    except Exception as e:
        logger.error(f"Error uploading files: {e}")
        print(f"Error: {e}")
        return []

def enable_auto_complete():
    def complete(text, state):
        return (glob.glob(text+'*')+[None])[state]

    readline.set_completer(complete)
    readline.parse_and_bind('tab: complete')

def clear_console():
    os.system('clear' if os.name == 'posix' else 'cls')

def store_file_hashes(disassembly_output, db_name, custom_name=None, file_size=None, file_type=None, architecture=None, timestamp=None, file_sha256=None):
    try:
        create_or_update_table(db_name)
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            display_name = os.path.basename(custom_name) if custom_name else "unknown"

            for func_name, func_code, func_start, func_end, instruction_count, func_size in disassembly_output:
                function_hash = hash_function(func_code)
                cursor.execute('''
                    INSERT INTO file_hashes (filename, function_name, function_hash, file_size, file_type, architecture, timestamp, function_start, function_end, instruction_count, function_size, file_sha256)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (display_name, func_name, function_hash, file_size, file_type, architecture, timestamp, func_start, func_end, instruction_count, func_size, file_sha256))

            conn.commit()
            print(f"Sample '{display_name}' successfully added to database '{db_name}'.")
    except Exception as e:
        logger.error(f"Error storing file hashes: {e}")

def hash_function(function_lines):
    function_code = ''.join(function_lines).replace(' ', '').replace('\r', '').replace('\n', '')
    return hashlib.sha256(function_code.encode('utf-8')).hexdigest()

def fetch_unique_filenames(db_name):
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT filename FROM file_hashes ORDER BY filename ASC')
            rows = cursor.fetchall()
            unique_filenames = [row[0] for row in rows]
            if unique_filenames:
                print("Unique Filenames in Database:")
                for filename in unique_filenames:
                    print(filename)
            else:
                print("No entries found in the database.")
    except Exception as e:
        logger.error(f"Error fetching file hashes: {e}")

def find_closest_match(new_filename, db_name, new_file_sha256):
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT filename, function_hash, file_sha256 FROM file_hashes')
            rows = cursor.fetchall()

        if not rows:
            print(f"\nNo entries in the database to compare against for '{new_filename}'.\n")
            return

        df = pd.DataFrame(rows, columns=['filename', 'function_hash', 'file_sha256'])
        grouped = df.groupby(['filename', 'file_sha256'])['function_hash'].apply(set).reset_index()

        if (new_filename, new_file_sha256) not in grouped[['filename', 'file_sha256']].values:
            print(f"\nNo similar files found for '{new_filename}'.\n")
            return

        new_file_hashes = grouped[(grouped['filename'] == new_filename) & (grouped['file_sha256'] == new_file_sha256)]['function_hash'].values[0]

        similarity_records = []
        for index, row in grouped.iterrows():
            if row['filename'] == new_filename and row['file_sha256'] == new_file_sha256:
                continue
            filename = row['filename']
            existing_hashes = row['function_hash']

            common_hashes = len(new_file_hashes.intersection(existing_hashes))
            total_hashes = len(new_file_hashes.union(existing_hashes))
            similarity_percentage = (common_hashes / total_hashes) * 100 if total_hashes > 0 else 0

            similarity_records.append({
                'filename': filename,
                'file_sha256': row['file_sha256'],
                'common_hashes': common_hashes,
                'similarity_percentage': similarity_percentage
            })

        similarity_df = pd.DataFrame(similarity_records)
        if similarity_df.empty:
            print(f"\nNo similar files found for '{new_filename}'.\n")
        else:
            closest_match = similarity_df.sort_values(by=['common_hashes', 'similarity_percentage'], ascending=False).iloc[0]
            closest_match_filename = closest_match['filename']
            closest_match_sha256 = closest_match['file_sha256']
            virus_total_link = f"https://www.virustotal.com/gui/search/{closest_match_sha256}"
            print(f"\n\nThe Provided Sample ({new_filename}) is most likely: '{closest_match_filename}' \nSimilarity: {closest_match['similarity_percentage']:.2f}% \nSHA256: {closest_match_sha256} \nVirusTotal: {virus_total_link} \n\n")
    except Exception as e:
        logger.error(f"Error finding closest match: {e}")
        print(f"Error finding closest match: {e}")

def get_file_sha256(filename, db_name):
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT file_sha256 FROM file_hashes WHERE filename = ?', (filename,))
            row = cursor.fetchone()
            if row:
                return row[0]
            else:
                return None
    except Exception as e:
        logger.error(f"Error fetching file SHA256: {e}")
        return None

def ensure_default_database():
    global current_db
    if os.path.isfile("Okami.db"):
        current_db = "Okami.db"
        print(f"Loaded default database '{current_db}'.")
    else:
        if not current_db:
            current_db = 'Okami.db'
            create_or_update_table(current_db)
            logger.info(f"Default database '{current_db}' created and loaded.")

def upload_database_file():
    try:
        db_path = input("Enter the path to the database file to upload: ").strip()
        if not db_path.endswith('.db'):
            print("Invalid file type. Please upload a .db file.")
            return None
        return db_path
    except Exception as e:
        logger.error(f"Error during file upload: {e}")
        return None

def connect_to_database(db_name):
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        return conn, cursor
    except sqlite3.Error as e:
        logger.error(f"Error connecting to database: {e}")
        return None, None

def fetch_data_from_db(cursor, progress_callback=None):
    try:
        query = "SELECT filename, function_hash FROM file_hashes"
        cursor.execute(query)
        results = cursor.fetchall()
        if progress_callback:
            progress_callback(1.0)
        return results
    except sqlite3.Error as e:
        logger.error(f"Error executing query: {e}")
        return []

def get_unique_filenames(df):
    return df['filename'].unique().tolist()

def calculate_similarity(df, selected_filename, progress_callback=None):
    grouped = df.groupby('filename')['function_hash'].apply(set).reset_index()
    selected_set = grouped[grouped['filename'] == selected_filename]['function_hash'].values[0]

    similarity_records = []
    total_files = len(grouped) - 1
    processed_files = 0

    for index, row in grouped.iterrows():
        if row['filename'] == selected_filename:
            continue
        filename = row['filename']
        function_hash_set = row['function_hash']

        common_hashes = len(selected_set.intersection(function_hash_set))
        total_hashes = len(selected_set.union(function_hash_set))
        similarity_percentage = (common_hashes / total_hashes) * 100 if total_hashes > 0 else 0

        similarity_records.append({
            'filename': filename,
            'common_hashes': common_hashes,
            'similarity_percentage': similarity_percentage
        })

        processed_files += 1
        if progress_callback:
            progress_callback(processed_files / total_files)

    similarity_df = pd.DataFrame(similarity_records)
    similarity_df = similarity_df.sort_values(by=['common_hashes', 'similarity_percentage'], ascending=False)
    return similarity_df

def rename_file_in_db(db_name):
    while True:
        try:
            with sqlite3.connect(db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT DISTINCT filename FROM file_hashes ORDER BY filename ASC')
                rows = cursor.fetchall()
                unique_filenames = [row[0] for row in rows]

                if not unique_filenames:
                    print("No files to rename.")
                    input("\nPress Enter to return to the main menu.")
                    return

                print("Select a file to rename:")
                for i, filename in enumerate(unique_filenames, 1):
                    print(f"{i}. {filename}")

                selected_index = input("\nEnter the number of the file to rename, or 'q' to quit:\n").strip()
                if selected_index.lower() == 'q':
                    break

                selected_index = int(selected_index) - 1
                if selected_index < 0 or selected_index >= len(unique_filenames):
                    print("Invalid selection. Please try again.")
                    continue

                old_filename = unique_filenames[selected_index]
                new_filename = input(f"Enter new name for the file '{old_filename}':\n").strip()
                if new_filename:
                    cursor.execute('UPDATE file_hashes SET filename = ? WHERE filename = ?', (new_filename, old_filename))
                    conn.commit()
                    print(f"File '{old_filename}' renamed to '{new_filename}' in the database.")
                else:
                    print("Invalid new filename.")

                more = input("Do you want to rename another file? (y/n):\n").strip().lower()
                if more != 'y':
                    break

        except Exception as e:
            logger.error(f"Error renaming file in database: {e}")
            print(f"Error: {e}")
            input("\nPress Enter to return to the main menu.")

def delete_file_from_db(db_name):
    while True:
        try:
            with sqlite3.connect(db_name) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT DISTINCT filename FROM file_hashes ORDER BY filename ASC')
                rows = cursor.fetchall()
                unique_filenames = [row[0] for row in rows]

                if not unique_filenames:
                    print("No files to delete.")
                    input("\nPress Enter to return to the main menu.")
                    return

                print("Select a file to delete:")
                for i, filename in enumerate(unique_filenames, 1):
                    print(f"{i}. {filename}")

                selected_index = input("\nEnter the number of the file to delete, or 'q' to quit:\n").strip()
                if selected_index.lower() == 'q':
                    break

                selected_index = int(selected_index) - 1
                if selected_index < 0 or selected_index >= len(unique_filenames):
                    print("Invalid selection. Please try again.")
                    continue

                filename = unique_filenames[selected_index]
                cursor.execute('DELETE FROM file_hashes WHERE filename = ?', (filename,))
                conn.commit()
                print(f"File '{filename}' deleted from the database.")

                more = input("Do you want to delete another file? (y/n):\n").strip().lower()
                if more != 'y':
                    break

        except Exception as e:
            logger.error(f"Error deleting file from database: {e}")
            print(f"Error: {e}")
            input("\nPress Enter to return to the main menu.")

def merge_database_entries():
    print("Upload the database file to merge from.")
    db_name = upload_database_file()
    if not db_name:
        input("\nPress Enter to return to the main menu.")
        return

    global current_db
    if not current_db:
        current_db = 'Okami.db'
        create_or_update_table(current_db)

    try:
        with sqlite3.connect(current_db) as conn:
            cursor = conn.cursor()
            with sqlite3.connect(db_name) as merge_conn:
                merge_cursor = merge_conn.cursor()
                merge_cursor.execute('SELECT filename, function_name, function_hash, file_size, file_type, architecture, timestamp, function_start, function_end, instruction_count, function_size, file_sha256 FROM file_hashes')
                rows = merge_cursor.fetchall()
                for row in rows:
                    cursor.execute('''
                        INSERT OR REPLACE INTO file_hashes (filename, function_name, function_hash, file_size, file_type, architecture, timestamp, function_start, function_end, instruction_count, function_size, file_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', row)
                conn.commit()
                print(f"Entries from '{db_name}' merged into '{current_db}'.")
    except Exception as e:
        logger.error(f"Error merging database entries: {e}")
        print(f"Error: {e}")

    input("\nPress Enter to return to the main menu.")

def create_or_update_table(db_name):
    try:
        with sqlite3.connect(db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    function_name TEXT,
                    function_hash TEXT,
                    file_size INTEGER,
                    file_type TEXT,
                    architecture TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    function_start INTEGER,
                    function_end INTEGER,
                    instruction_count INTEGER,
                    function_size INTEGER,
                    analysis_tool_version TEXT,
                    analysis_notes TEXT,
                    file_sha256 TEXT
                )
            ''')
            cursor.execute("PRAGMA table_info(file_hashes)")
            columns = [info[1] for info in cursor.fetchall()]
            required_columns = ['filename', 'function_name', 'function_hash', 'file_size', 'file_type', 'architecture', 'timestamp', 'function_start', 'function_end', 'instruction_count', 'function_size', 'analysis_tool_version', 'analysis_notes', 'file_sha256']
            for column in required_columns:
                if column not in columns:
                    cursor.execute(f'ALTER TABLE file_hashes ADD COLUMN {column} TEXT')
            conn.commit()
    except Exception as e:
        logger.error(f"Error creating or updating table: {e}")
        print(f"Error creating or updating table: {e}")

def advanced_menu():
    while True:
        clear_console()
        current_db_display = current_db if current_db else "(no database selected)"
        print(f"\nAdvanced Options: [Current Database: {current_db_display}]")
        print("1. View unique filenames in database")
        print("2. Select or create database")
        print("3. Download current database")
        print("4. Rename file in database")
        print("5. Delete file from database")
        print("6. Merge entries from another database")
        print("7. Return to Main Menu")
        print("=" * 40)

        choice = input("\nPlease select an option (1, 2, 3, 4, 5, 6, 7):\n").strip()

        if choice == '1':
            fetch_unique_filenames(current_db)
            input("\nPress Enter to return to the main menu.")
        elif choice == '2':
            select_or_create_database()
        elif choice == '3':
            download_current_database()
        elif choice == '4':
            rename_file_in_db(current_db)
        elif choice == '5':
            delete_file_from_db(current_db)
        elif choice == '6':
            merge_database_entries()
        elif choice == '7':
            return
        else:
            print("Invalid choice. Please try again.")

def select_or_create_database():
    def create_new_database():
        db_name = input("Enter database name (with .db extension):\n").strip()
        if db_name:
            global current_db
            current_db = db_name
            create_or_update_table(current_db)
            print(f"Database '{current_db}' created and loaded.")
        else:
            print("Invalid database name.")
        input("\nPress Enter to return to the main menu.")
        main_menu()

    def select_existing_database():
        uploaded_db = upload_database_file()
        if uploaded_db:
            global current_db
            current_db = uploaded_db
            print(f"Database '{current_db}' selected.")
        input("\nPress Enter to return to the main menu.")
        main_menu()

    while True:
        clear_console()
        print("Select or Create Database")
        print("1. Create new database")
        print("2. Select existing database")
        print("3. Cancel")
        print("=" * 40)

        sub_choice = input("\nPlease select an option (1, 2, 3):\n").strip()

        if sub_choice == '1':
            create_new_database()
            break
        elif sub_choice == '2':
            select_existing_database()
            break
        elif sub_choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

def download_current_database():
    if current_db:
        print(f"Database '{current_db}' is ready to be downloaded. Please find it in the current directory.")
    else:
        print("No database selected.")
    input("\nPress Enter to return to the main menu.")

def update_signatures():
    global current_db
    url = 'https://github.com/Benjamyn93/Okami-Ben/raw/main/Okami.db'

    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to download the database file from the URL.")
        input("\nPress Enter to return to the main menu.")
        return

    new_db_path = 'Okami.db'
    with open(new_db_path, 'wb') as f:
        f.write(response.content)

    if zipfile.is_zipfile(new_db_path):
        with zipfile.ZipFile(new_db_path, 'r') as zip_ref:
            zip_ref.extractall('./')
        new_db_path = 'Okami.db'

    if not current_db:
        current_db = 'Okami.db'
        create_or_update_table(current_db)

    try:
        with sqlite3.connect(current_db) as conn:
            cursor = conn.cursor()
            with sqlite3.connect(new_db_path) as merge_conn:
                merge_cursor = merge_conn.cursor()
                merge_cursor.execute('SELECT filename, function_name, function_hash, file_size, file_type, architecture, timestamp, function_start, function_end, instruction_count, function_size, file_sha256 FROM file_hashes')
                rows = merge_cursor.fetchall()
                for row in rows:
                    cursor.execute('''
                        INSERT OR REPLACE INTO file_hashes (filename, function_name, function_hash, file_size, file_type, architecture, timestamp, function_start, function_end, instruction_count, function_size, file_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', row)
                conn.commit()
                print(f"Entries from the downloaded database have been merged into '{current_db}'.")
    except Exception as e:
        logger.error(f"Error merging database entries: {e}")
        print(f"Error: {e}")

    input("\nPress Enter to return to the main menu.")

def main_menu():
    global exit_after_download, current_db
    exit_after_download = False
    ensure_default_database()
    while True:
        if exit_after_download:
            print("Exiting application.")
            break
        clear_console()
        current_db_display = current_db if current_db else "(no database selected)"
        print(f"\nMain Menu: [Current Database: {current_db_display}]")
        print("1. Analyse New Sample")
        print("2. Update Signatures")
        print("3. Advanced Options")
        print("4. Exit Application")
        print("=" * 40)

        choice = input("\nPlease select an option (1, 2, 3, 4):\n").strip()

        if choice == '1':
            analyze_and_add_samples()
        elif choice == '2':
            update_signatures()
        elif choice == '3':
            advanced_menu()
        elif choice == '4':
            print("Exiting application.")
            break
        else:
            print("Invalid choice. Please try again.")

def ensure_default_database():
    global current_db
    if not current_db:
        current_db = 'Okami.db'
        create_or_update_table(current_db)
        logger.info(f"Default database '{current_db}' created and loaded.")

# Start the application
main_menu()

