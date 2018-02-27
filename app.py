import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox


class App(tk.Tk):
    HASH_FUNCTIONS = [('MD5',    hashlib.md5),
                      ('SHA1',   hashlib.sha1),
                      ('SHA224', hashlib.sha224),
                      ('SHA256', hashlib.sha256),
                      ('SHA512', hashlib.sha512)]

    def __init__(self):
        super().__init__()
        self.title('Checksum Verifier')
        self.resizable(False, False)
        
        self._path_string = tk.StringVar()
        self._checksum_string = tk.StringVar()
        self._checksum_string.trace("w", self._can_verify)

        self._hash_strings = dict()
        for key in self.HASH_FUNCTIONS:
            self._hash_strings[key] = tk.StringVar()
            self._hash_strings[key].trace("w", self._can_verify)

        input_frame = tk.Frame(self)
        input_frame.pack(pady=15)
        self._create_file_frame(master=input_frame)
        self._create_validation_frame(master=input_frame)

        hash_frame = tk.Frame(self)
        hash_frame.pack(padx=10)
        for key in self._hash_strings:
            self._create_hash_frame(key, master=hash_frame)

        button_frame = tk.Frame(self)
        button_frame.pack(fill=tk.X, padx=10, pady=25)
        self._create_buttons(master=button_frame)

    def _create_file_frame(self, master):
        file_frame = tk.Frame(master)
        file_frame.pack(pady=5)

        path_lbl = tk.Label(file_frame, text='File path:', anchor='w', width=8)
        path_lbl.pack(side=tk.LEFT)

        path_entry = tk.Entry(file_frame, text=self._path_string,
                              width=70, state='readonly')
        path_entry.pack(side=tk.LEFT)

    def _create_validation_frame(self, master):
        frame = tk.Frame(master)
        frame.pack(pady=5)

        label = tk.Label(frame, text='Hash:', anchor='w', width=8)
        label.pack(side=tk.LEFT)

        checksum_entry = tk.Entry(frame, text=self._checksum_string, width=70)
        checksum_entry.pack(side=tk.LEFT)

    def _create_hash_frame(self, key, master):
        frame = tk.Frame(master)
        frame.pack(pady=5)

        name, __ = key
        label = tk.Label(frame, text=f'{name}:', anchor='w', width=8)
        label.pack(side=tk.LEFT)

        entry = tk.Entry(frame, text=self._hash_strings[key],
                         width=70, state='readonly')
        entry.pack(side=tk.LEFT)

    def _create_buttons(self, master):
        browse_btn = tk.Button(master, text='Select file',
                               command=self._select_file)
        browse_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

        self._verify_btn = tk.Button(master, text='Verify hash', state=tk.DISABLED,
                                     command=self._verify_hash)
        self._verify_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=5)

    def _select_file(self):
        path = filedialog.askopenfilename(title="Select file")
        if not path:
            return
        self._path_string.set(path)

        t = threading.Thread(target=self._calculate_hashes)
        t.start()

    def _calculate_hashes(self):
        for key in self._hash_strings:
            self._hash_strings[key].set('')

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
                name, __ = key
                messagebox.showinfo('Success', f'{name}: hash matched.')
                break
        else:
            messagebox.showwarning('Failure', 'Hash does not match.')

