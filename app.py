import tkinter as tk
import hashlib


class App:
    def __init__(self, root):
        # key is a tuple of the hash name and its hashing function
        # value is a corresponding entry widget
        self._hash_entries = {('MD5',    hashlib.md5):      None,
                              ('SHA1',   hashlib.sha1):     None,
                              ('SHA224', hashlib.sha224):   None,
                              ('SHA256', hashlib.sha256):   None}

        self._root = root
        tk.Label(root).pack()  # empty line
        self._create_file_frame()
        tk.Label(root).pack()  # empty line

        self._hash_frame = tk.Frame(root)
        self._hash_frame.pack()
        for key in self._hash_entries:
            self._create_hash_frame(key)
        tk.Label(root).pack()  # empty line

        self._create_validation_frame()
        tk.Label(root).pack()  # empty line

    def _create_file_frame(self):
        file_frame = tk.Frame(self._root)
        file_frame.pack()

        path_lbl = tk.Label(file_frame, text='File path:', anchor='w', width=8)
        path_lbl.pack(side=tk.LEFT, padx=5, pady=5)

        self._path_entry = tk.Entry(file_frame, width=70)
        self._path_entry.insert(tk.END, r'C:\Users\Mateusz\Desktop\python\btc.py')
        self._path_entry.pack(side=tk.LEFT, pady=5)

        browse_btn = tk.Button(file_frame, text='browse', width=8,
                               command=self._select_file)
        browse_btn.pack(side=tk.LEFT, padx=5, pady=5)

    def _create_hash_frame(self, key):
        frame = tk.Frame(self._hash_frame)
        frame.pack()

        name, __ = key
        label = tk.Label(frame, text=f'{name}:', anchor='w', width=8)
        label.pack(side=tk.LEFT, padx=5, pady=5)

        entry = tk.Entry(frame, width=70, state='readonly')
        entry.pack(side=tk.LEFT, pady=5)
        self._hash_entries[key] = entry

        button = tk.Button(frame, text='calculate', width=8,
                           command=lambda: self._calculate_hash(key))
        button.pack(side=tk.LEFT, padx=5, pady=5)

    def _create_validation_frame(self):
        frame = tk.Frame(self._root)
        frame.pack()

        label = tk.Label(frame, text='Hash:', anchor='w', width=8)
        label.pack(side=tk.LEFT, padx=5, pady=5)

        self._checksum_entry = tk.Entry(frame, width=70)
        self._checksum_entry.pack(side=tk.LEFT, pady=5)

        verify_btn = tk.Button(frame, text='verify', width=8,
                               command=self._verify_hash)
        verify_btn.pack(side=tk.LEFT, padx=5, pady=5)

    def _select_file(self):
        raise NotImplementedError
        # self._path_entry.delete(0, tk.END)
        # self._path_entry.insert(tk.END, path)

    def _calculate_hash(self, key):
        __, hash_function = key
        path = self._path_entry.get()

        try:
            with open(path, 'rb') as file:
                    contents = file.read()
        except FileNotFoundError:
            print('foo')
        else:
            checksum = hash_function(contents).hexdigest()
            self._hash_entries[key]['state'] = tk.NORMAL
            self._hash_entries[key].delete(0, tk.END)
            self._hash_entries[key].insert(tk.END, checksum)
            self._hash_entries[key]['state'] = 'readonly'

    def _verify_hash(self):
        raise NotImplementedError
