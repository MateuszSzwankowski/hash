import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox


class App:
    def __init__(self, root):
        self._hash_strings = {('MD5',    hashlib.md5):      tk.StringVar(),
                              ('SHA1',   hashlib.sha1):     tk.StringVar(),
                              ('SHA224', hashlib.sha224):   tk.StringVar(),
                              ('SHA256', hashlib.sha256):   tk.StringVar()}

        for hash_str in self._hash_strings.values():
            hash_str.trace("w", self._can_verify)

        self._path_string = tk.StringVar()
        self._checksum_string = tk.StringVar()
        self._checksum_string.trace("w", self._can_verify)

        input_frame = tk.Frame(root)
        input_frame.pack(pady=15)
        self._create_file_frame(parent=input_frame)
        self._create_validation_frame(parent=input_frame)

        hash_frame = tk.Frame(root)
        hash_frame.pack()
        for key in self._hash_strings:
            self._create_hash_frame(key, parent=hash_frame)

        self._create_button_frame(root)

    def _create_file_frame(self, parent):
        file_frame = tk.Frame(parent)
        file_frame.pack()

        path_lbl = tk.Label(file_frame, text='File path:', anchor='w', width=8)
        path_lbl.pack(side=tk.LEFT, padx=5, pady=5)

        path_entry = tk.Entry(file_frame, width=70, state='readonly',
                              text=self._path_string)
        path_entry.pack(side=tk.LEFT, padx=5, pady=5)

    def _create_validation_frame(self, parent):
        frame = tk.Frame(parent)
        frame.pack()

        label = tk.Label(frame, text='Hash:', anchor='w', width=8)
        label.pack(side=tk.LEFT, padx=5, pady=5)

        checksum_entry = tk.Entry(frame, width=70, text=self._checksum_string)
        checksum_entry.pack(side=tk.LEFT, padx=5, pady=5)

    def _create_hash_frame(self, key, parent):
        frame = tk.Frame(parent)
        frame.pack()

        name, __ = key
        label = tk.Label(frame, text=f'{name}:', anchor='w', width=8)
        label.pack(side=tk.LEFT, padx=5, pady=5)

        entry = tk.Entry(frame, width=70, state='readonly',
                         text=self._hash_strings[key])
        entry.pack(side=tk.LEFT, padx=5, pady=5)

    def _create_button_frame(self, root):
        button_frame = tk.Frame(root)
        button_frame.pack(padx=10, pady=15, fill=tk.X)

        browse_btn = tk.Button(button_frame, text='Select file',
                               command=self._select_file)
        browse_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5, pady=5)

        self._verify_btn = tk.Button(button_frame, text='Verify hash',
                                     state=tk.DISABLED, command=self._verify_hash)
        self._verify_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=5, pady=5)

    def _select_file(self):
        path = filedialog.askopenfilename(title="Select file")
        if not path:
            return

        self._path_string.set(path)
        for key in self._hash_strings:
            self._hash_strings[key].set('')

        t = threading.Thread(target=self._calculate_hashes)
        t.start()

    def _calculate_hashes(self):
        path = self._path_string.get()
        try:
            with open(path, 'rb') as file:
                    contents = file.read()
        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except MemoryError:
            messagebox.showerror("Error", "File too big.")
        else:
            for key in self._hash_strings:
                t = threading.Thread(target=lambda: self._hash(key, contents))
                t.start()

    def _hash(self, key, contents):
        __, hash_function = key
        checksum = hash_function(contents).hexdigest()
        self._hash_strings[key].set(checksum)

    def _can_verify(self, *__):
        if not self._checksum_string.get():
            self._verify_btn['state'] = tk.DISABLED
            return

        for key in self._hash_strings:
            if not self._hash_strings[key].get():
                self._verify_btn['state'] = tk.DISABLED
                break
        else:
            self._verify_btn['state'] = tk.NORMAL

    def _verify_hash(self):
        for key in self._hash_strings:
            if self._hash_strings[key].get() == self._checksum_string.get():
                hash_type, __ = key
                messagebox.showinfo('Success', f'{hash_type}: hash matched.')
                break
        else:
            messagebox.showwarning('Failure', 'Hash does not match.')
