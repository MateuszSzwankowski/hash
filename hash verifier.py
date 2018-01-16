import tkinter as tk
from app import App

if __name__ == '__main__':
    root = tk.Tk()
    root.title('Checksum verifier')
    root.resizable(False, False)

    app = App(root)
    root.mainloop()
