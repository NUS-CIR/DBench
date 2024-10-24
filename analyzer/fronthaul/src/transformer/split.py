import os
import csv
from collections import defaultdict

def split_csv(file_path, output_dir):
    key_entry_counter = defaultdict(int)
    entries = defaultdict(list)
    
    # Read the CSV and collect entries by key
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            key = (row['Frame'], row['Subframe'], row['Slot'], row['StartSymbol'])
            entry_index = key_entry_counter[key]
            entries[entry_index].append(row)
            key_entry_counter[key] += 1
    
    base_name = os.path.basename(file_path).split('.')[0]
    
    # Write the collected entries to separate files
    for entry_index, rows in entries.items():
        new_file_name = os.path.join(output_dir, f"{base_name}_{entry_index}.csv")
        with open(new_file_name, 'w', newline='') as csvfile:
            fieldnames = ['Frame', 'Subframe', 'Slot', 'StartSymbol', 'Bitmap', 'Timestamp(ms)']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

def main():
    input_dir = '../../data/prb_bitmaps/'
    output_dir = os.path.join(input_dir, 'split')
    os.makedirs(output_dir, exist_ok=True)
    
    csv_files = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.csv')]
    
    for csv_file in csv_files:
        split_csv(csv_file, output_dir)

if __name__ == "__main__":
    main()
