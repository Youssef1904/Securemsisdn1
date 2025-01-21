import zipfile

file_path = "invalid_bytes_output.xlsx"

if zipfile.is_zipfile(file_path):
    print("The file is a valid ZIP archive.")
    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        print("Contents of the ZIP file:")
        zip_ref.printdir()
else:
    print("The file is not a valid ZIP archive.")

