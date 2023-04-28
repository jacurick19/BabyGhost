import subprocess
import zipfile
import glob
import os
import stat

num_attempts = 100

zip_files = glob.glob("*.zip")

for zip_file in zip_files:
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall()

        extracted_dir = zip_file.replace(".zip", "")
        files = os.listdir(extracted_dir)
        executables = [f for f in files if os.access(f"{extracted_dir}/{f}", os.X_OK)]

        for executable in executables:
            command = f"./{extracted_dir}/{executable}"

            total_percentage = 0

            for i in range(num_attempts):
                result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, text=True)
                output = result.stdout.strip()  # Capture the output and remove leading/trailing whitespaces

                magic_words = "The Magic Words are Sqeamish Ossifraggee"
                num_characters = len(output)
                num_matches = sum([1 for i, char in enumerate(output) if char == magic_words[i]])
                percentage = (num_matches / num_characters) * 100

                total_percentage += percentage

            average_percentage = total_percentage / num_attempts

            print(f"Zip file: {zip_file}, Executable: {executable}, Average percentage of characters that match the magic words: {average_percentage}%")

    except zipfile.BadZipFile:
        print(f"Error extracting '{zip_file}': Not a valid zip file")
    except subprocess.CalledProcessError as e:
        print(f"Error running executable '{executable}' in '{zip_file}': {e}")
