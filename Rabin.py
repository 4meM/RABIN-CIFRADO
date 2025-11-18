import tkinter as tk
from tkinter import scrolledtext, messagebox
from rabin_lib import (
    miyao, JiaMi, JieMi, 

    add_random_letter_to_string,   
    string_to_unicode_with_tuple,
    filter_decrypt_combinations,
    get_reduced_alphabet,
    remove_letters_from_string,

    add_sequence_and_checksum_to_string,
    split_encoding,
    combine_and_verify,

    add_timestamp_to_unicode,
    verify_and_extract_characters
)
import string

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rabin Encryption and Decryption Tool")
        self.root.geometry("700x650")
        self.root.rowconfigure(0, weight=1)  # Configure the only row of the main window
        self.root.columnconfigure(0, weight=1)  # Configure the only column of the main window

        # Initialize quotient list
        self.shang = []
        # Initialize encrypted data storage
        self.encrypted_data = {}
        
        # 设置GUI布局
        self.setup_gui()

    def setup_gui(self):

        # Create a main frame that fills the entire window
        main_frame = tk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky='nsew')
        main_frame.rowconfigure(0, weight=0)  # Mode selection frame
        main_frame.rowconfigure(1, weight=0)  # Input frame
        main_frame.rowconfigure(2, weight=1)  # Display frame
        main_frame.rowconfigure(3, weight=0)  # Button frame
        main_frame.columnconfigure(0, weight=1)  # Only one column

        # Label method selection
        mode_frame = tk.Frame(main_frame)
        mode_frame.grid(row=0, column=0, padx=10, pady=10, sticky='ew')
        mode_frame.columnconfigure(1, weight=1)  # Allow dropdown menu to expand

        mode_label = tk.Label(mode_frame, text="Select Tag Method:")
        mode_label.grid(row=0, column=0, padx=5,pady=5,sticky='w')

        self.mode_var = tk.StringVar(value='Method 1 (Random Letters)')
        mode_options = ['Method 1 (Random Letters)', 'Method 2 (Sequence and Checksum)','Method 3 (Timestamp)']
        mode_dropdown = tk.OptionMenu(mode_frame, self.mode_var, *mode_options)
        mode_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Letter range selection (only for Method 1)
        self.range_frame = tk.Frame(mode_frame)
        self.range_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky='ew')
        self.range_frame.columnconfigure(1, weight=1)
        self.range_frame.columnconfigure(3, weight=1)


        start_label = tk.Label(self.range_frame, text="Start Letter:")
        start_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        self.letter_start = tk.StringVar(value='a')
        start_dropdown = tk.OptionMenu(self.range_frame, self.letter_start, *string.ascii_lowercase)
        start_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        end_label = tk.Label(self.range_frame, text="End Letter:")
        end_label.grid(row=0, column=2, padx=5, pady=5, sticky='w')

        self.letter_end = tk.StringVar(value='f')
        end_dropdown = tk.OptionMenu(self.range_frame, self.letter_end, *string.ascii_lowercase)
        end_dropdown.grid(row=0, column=3, padx=5, pady=5, sticky='ew')

        # Place range_frame on the next row (row=1) of mode_frame
        self.range_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky='w')

       # Bind mode change event
        self.mode_var.trace_add('write', self.update_range_frame_visibility)

        # Initialize range_frame visibility based on current mode
        self.update_range_frame_visibility()

        # Input frame
        entry_frame = tk.Frame(main_frame)
        entry_frame.grid(row=1, column=0, padx=10, pady=5, sticky='ew')
        entry_frame.columnconfigure(1, weight=1)

        entry_label = tk.Label(entry_frame, text="Please enter a string:")
        entry_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')

        self.entry = tk.Entry(entry_frame, width=80)
        self.entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Display frame
        self.result_box = scrolledtext.ScrolledText(main_frame, width=100, height=30, wrap=tk.WORD)
        self.result_box.grid(row=2, column=0, padx=10, pady=10, sticky='nsew')
        self.result_box.configure(state='normal')


        # Button frame
        button_frame = tk.Frame(main_frame)
        button_frame.grid(row=3, column=0, padx=10, pady=10, sticky='ew')
        button_frame.columnconfigure((0,1,2), weight=1)  # Let three buttons share space equally

        # Encrypt button
        encrypt_button = tk.Button(button_frame, text="Encrypt", command=self.on_encrypt)
        encrypt_button.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

        # Decrypt button
        decrypt_button = tk.Button(button_frame, text="Decrypt", command=self.on_decrypt)
        decrypt_button.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Clear button
        clear_button = tk.Button(button_frame, text="Clear",command=self.clear)
        clear_button.grid(row=0, column=2, padx=5, pady=5, sticky='ew')

        # Add program information button
        info_button = tk.Button(main_frame, text="Program Info", command=self.show_info)
        info_button.grid(row=4, column=0, padx=10, pady=10, sticky='ew')

    def show_info(self):
        # Pop up information dialog
        messagebox.showinfo("Program Information", """
        This is a Rabin encryption and decryption tool. You can choose different tag methods for string encryption and decryption:   
                                        
        Method 1: Encryption by adding random letters.
                Implementation: Randomly select one of the 26 lowercase English letters, convert it to Unicode encoding with a fixed 4-digit format. For example, "a" is converted to "0097" and appended to the Unicode encoding of each character. During decryption, extract the last four digits and convert to a character, then check if it's within the selected letter range.
                            
        Method 2: Encryption using sequence numbers and checksums.
                Implementation: Number each character sequentially starting from 0, with format 0000 (max input number 9999). This number and the Unicode encoding of the input character undergo hash operation. The last four digits of the hash value serve as the checksum. Only the Unicode code of the input characters is encrypted/decrypted. Finally, perform hash operation sequentially with the four results obtained from decrypting each character and compare with the last four digits of the correct hash value.
                            
        Method 3: Encryption using timestamps.
                Implementation: Add a timestamp suffix to each character (accurate to year, month, day, hour, minute - 12 digits total). The timestamp is stripped and saved as a subsequent comparison standard. The entire character (Unicode code + timestamp) is encrypted/decrypted, and finally the timestamp in the result is compared.

        Author: Ni Shuo                                    
        """)


    def update_range_frame_visibility(self, *args):
        if self.mode_var.get() == 'Method 1 (Random Letters)':
            self.range_frame.grid()
        else:
            self.range_frame.grid_remove()


    def clear(self):
        self.entry.delete(0, tk.END)  # Clear input box
        self.result_box.delete(1.0, tk.END)  # Clear display box
        self.encrypted_data = {}  # Clear encrypted data

    def on_encrypt(self):
        input_text = self.entry.get().strip()  # Get input box content and remove leading/trailing spaces

        if not input_text:
            messagebox.showwarning("Input Error", "Please enter a string to encrypt.")
            return

        mode = self.mode_var.get()
        self.result_box.insert(tk.END, "=== Encryption Process ===\n\n")

        # Generate new p and q for each encryption
        p, q = miyao()
        n = p * q
        self.result_box.insert(tk.END, f"Generated keys p and q: {p}, {q}\n\n")

        if mode == 'Method 1 (Random Letters)':
            # Get letter range
            start = self.letter_start.get()
            end = self.letter_end.get()

            if start > end:
                messagebox.showwarning("Range Error", "Start letter cannot be greater than end letter.")
                return

            letter_range = get_reduced_alphabet(start, end)

            # Add random letter tags
            encoded_string = add_random_letter_to_string(input_text, letter_range)
            self.result_box.insert(tk.END, f"Processed string (each character appended with a random letter): {encoded_string}\n\n")  

            # Convert to Unicode integer list
            unicode_ints = string_to_unicode_with_tuple(encoded_string)
            self.result_box.insert(tk.END, f"Processed string Unicode values (integer): {unicode_ints}\n\n")

            # Perform encryption
            miwen, shang = JiaMi(unicode_ints, p, q)
            self.result_box.insert(tk.END, f"Encrypted ciphertext Unicode values: {miwen}\n\n")
            self.encrypted_data['Method 1'] = {'miwen': miwen, 'shang': shang, 'p': p, 'q': q}

        elif mode == 'Method 2 (Sequence and Checksum)':
            # Add sequence number and checksum tags
            encoded_string = add_sequence_and_checksum_to_string(input_text)
            self.result_box.insert(tk.END, f"Processed string (each character prepended with sequence number and checksum): {encoded_string}\n\n")  

            prefixes, char_codes = split_encoding(encoded_string)
            self.result_box.insert(tk.END, f"Sequence number and checksum part: {prefixes}\n")
            self.result_box.insert(tk.END, f"Character Unicode value part: {char_codes}\n\n")

            # Perform encryption
            miwen, shang = JiaMi(char_codes, p, q)
            self.result_box.insert(tk.END, f"Encrypted ciphertext Unicode values: {miwen}\n\n")
            self.encrypted_data['Method 2'] = {'miwen': miwen, 'shang': shang, 'prefixes': prefixes, 'p': p, 'q': q}
        
        elif mode == 'Method 3 (Timestamp)':

            # Add timestamp to each Unicode encoding
            unicode_with_timestamps, timestamps = add_timestamp_to_unicode(input_text)
            self.result_box.insert(tk.END, f"Unicode encoding with timestamps (integer): {unicode_with_timestamps}\n\n")
            self.result_box.insert(tk.END, f"Timestamp for each character: {timestamps}\n\n")

            # Perform encryption
            miwen, shang = JiaMi(unicode_with_timestamps, p, q)
            self.result_box.insert(tk.END, f"Encrypted ciphertext Unicode values: {miwen}\n\n")
        
        # Store encrypted data
            self.encrypted_data['Method 3'] = {'p': p,'q': q,'miwen': miwen,'shang': shang,'timestamps': timestamps  # Store timestamp for each character
                                          }
        else:
            messagebox.showwarning("Mode Error", "No valid tag method selected.")
            return

    def on_decrypt(self):
        input_text = self.entry.get().strip()  # Get input box content and remove leading/trailing spaces

        if not input_text:
            messagebox.showwarning("Input Error", "Please enter a string to encrypt.")
            return
        
        mode = self.mode_var.get()

        if mode == 'Method 1 (Random Letters)':
            data = self.encrypted_data.get('Method 1')
            if not data:
                messagebox.showwarning("Decryption Error", "Encrypted data not found. Please perform encryption first.")
                return
            miwen = data['miwen']
            shang = data['shang']
            p = data['p']
            q = data['q']
        
            # Perform decryption
            decrypted_chars = JieMi(miwen, p, q, shang)
            # Get letter range
            start = self.letter_start.get()
            end = self.letter_end.get()

            if start > end:
                messagebox.showwarning("Range Error", "Start letter cannot be greater than end letter.")
                return

            letter_range = get_reduced_alphabet(start, end)

            # Filter valid decryption combinations
            valid_combinations = filter_decrypt_combinations(decrypted_chars, letter_range)

            # Remove letter suffixes
            cleaned_combinations = [remove_letters_from_string(s) for s in valid_combinations]

            # Output decryption results
            self.result_box.insert(tk.END, "=== Decryption Results ===\n\n")
            self.result_box.insert(tk.END, f"Keys p and q used: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"All decrypted solutions: {decrypted_chars}\n\n")

            if valid_combinations:
                self.result_box.insert(tk.END, f"Valid solution combinations: {', '.join(valid_combinations)}\n\n")
                self.result_box.insert(tk.END, f"Decrypted string (without letter suffix): {', '.join(cleaned_combinations)}\n\n")
            else:
                self.result_box.insert(tk.END, "No valid solution combinations found.\n\n")

        elif mode == 'Method 2 (Sequence and Checksum)':
                
            data = self.encrypted_data.get('Method 2')
            if not data:
                messagebox.showwarning("Decryption Error", "Encrypted data not found. Please perform encryption first.")
                return
            miwen = data['miwen']
            shang = data['shang']
            prefixes = data['prefixes']
            p = data['p']
            q = data['q']

                # Perform decryption
            decrypted_chars = JieMi(miwen, p, q, shang)

            # Filter valid decryption combinations
            valid_combinations = combine_and_verify(prefixes, decrypted_chars)

            # Output decryption results
            self.result_box.insert(tk.END, "=== Decryption Results ===\n\n")
            self.result_box.insert(tk.END, f"Keys p and q used: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"All decrypted solutions: {decrypted_chars}\n\n")
            self.result_box.insert(tk.END, f"Valid solution combinations: {valid_combinations}\n\n")
        
        elif mode == 'Method 3 (Timestamp)':
            data = self.encrypted_data.get('Method 3')
            if not data:
                messagebox.showwarning("Decryption Error", "Encrypted data not found. Please perform encryption first.")
                return
            p = data['p']
            q = data['q']
            miwen = data['miwen']
            shang = data['shang']
            original_timestamps = data['timestamps']
        
            # Perform decryption
            decrypted_chars = JieMi(miwen, p, q, shang)

            self.result_box.insert(tk.END, "=== Decryption Process ===\n\n")
            self.result_box.insert(tk.END, f"Keys p and q used: {p}, {q}\n\n")
            self.result_box.insert(tk.END, f"Decrypted Unicode values with timestamps: {decrypted_chars}\n\n")

            # Compare and extract correct characters
            valid_chars_with_timestamps, valid_chars ,all_valid_combinations= verify_and_extract_characters(original_timestamps, decrypted_chars)

            if valid_chars_with_timestamps:
                # Display successfully matched characters (with timestamps)
                flattened_valid_chars_with_ts = [item for sublist in valid_chars_with_timestamps for item in sublist]
                self.result_box.insert(tk.END, f"Successfully matched characters (with timestamps): {', '.join(flattened_valid_chars_with_ts)}\n\n")
        
                # Display characters after stripping timestamps
                flattened_valid_chars = [item for sublist in valid_chars for item in sublist]
                self.result_box.insert(tk.END, f"Characters after stripping timestamps: {', '.join(flattened_valid_chars)}\n\n")
        
                # Display all possible decryption combinations
                self.result_box.insert(tk.END, f"Valid solution combinations: {', '.join(all_valid_combinations)}\n\n")
            else:
                self.result_box.insert(tk.END, "No successfully matched solution combinations.\n\n")
           
        else:
            messagebox.showwarning("Mode Error", "No valid tag method selected.")
            return

def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()