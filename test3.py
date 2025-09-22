import re
import random
import string
import customtkinter as ctk
import pyperclip

# Initialize CTk appearance
ctk.set_appearance_mode("dark")  # or "light"
ctk.set_default_color_theme("blue")

class PasswordStrengthApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Password Strength Checker")
        self.geometry("480x420")
        self.resizable(False, False)

        self.options = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special_char': True
        }

        self.create_widgets()
        self.password_var.trace_add('write', self.on_password_change)

    def create_widgets(self):
        self.label_title = ctk.CTkLabel(self, text="Enter Password:", font=ctk.CTkFont(size=16, weight="bold"))
        self.label_title.pack(pady=(20, 10))

        self.password_var = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(self, textvariable=self.password_var, width=350, show="*", font=ctk.CTkFont(size=12))
        self.password_entry.pack(pady=(0, 15))
        self.password_entry.focus()

        # Frame for buttons side by side
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(pady=(0, 10))

        self.check_btn = ctk.CTkButton(btn_frame, text="Check Strength", command=self.check_password_strength, width=160)
        self.check_btn.grid(row=0, column=0, padx=10, pady=5)

        self.generate_btn = ctk.CTkButton(btn_frame, text="Generate Strong Password", command=self.generate_password, width=160)
        self.generate_btn.grid(row=0, column=1, padx=10, pady=5)

        self.copy_password_btn = ctk.CTkButton(self, text="Copy Password to Clipboard", command=self.copy_password, width=350)
        self.copy_password_btn.pack(pady=(0,10))

        self.result_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=14, weight="bold"))
        self.result_label.pack(pady=10)

        self.details_text = ctk.CTkTextbox(self, width=440, height=140, state="disabled", font=ctk.CTkFont(family="Courier", size=11))
        self.details_text.pack()

        self.copy_btn = ctk.CTkButton(self, text="Copy Results to Clipboard", command=self.copy_results, width=350)
        self.copy_btn.pack(pady=10)

    def copy_password(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            ctk.CTkMessagebox(title="Copied", message="Password copied to clipboard!", icon="information").show()
        else:
            ctk.CTkMessagebox(title="Error", message="No password to copy.", icon="error").show()

    def copy_results(self):
        text = self.details_text.get("1.0", "end").strip()
        if text:
            pyperclip.copy(text)
            ctk.CTkMessagebox(title="Copied", message="Password results copied to clipboard!", icon="information").show()

    def on_password_change(self, *args):
        password = self.password_var.get()
        if password:
            self.display_results(self.assess_password_strength(password, self.options))
        else:
            self.result_label.configure(text="")
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.configure(state="disabled")

    def check_password_strength(self):
        password = self.password_var.get()
        if not password:
            ctk.CTkMessagebox(title="Error", message="Please enter a password to check.", icon="error").show()
            return
        self.display_results(self.assess_password_strength(password, self.options))

    def assess_password_strength(self, password, options):
        score = 0
        length = len(password)
        min_length = options['min_length']
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_number = bool(re.search(r'[0-9]', password))
        has_special_char = bool(re.search(r'[^a-zA-Z0-9]', password))

        if length >= min_length:
            score += 1
        if options['require_uppercase'] and has_uppercase:
            score += 1
        if options['require_lowercase'] and has_lowercase:
            score += 1
        if options['require_numbers'] and has_number:
            score += 1
        if options['require_special_char'] and has_special_char:
            score += 1

        max_score = 1
        if options['require_uppercase']:
            max_score += 1
        if options['require_lowercase']:
            max_score += 1
        if options['require_numbers']:
            max_score += 1
        if options['require_special_char']:
            max_score += 1

        percentage = (score / max_score) * 100 if max_score else 0

        if percentage == 100:
            strength = 'Very Strong'
            color = "#4CAF50"
        elif percentage >= 80:
            strength = 'Strong'
            color = "#8BC34A"
        elif percentage >= 60:
            strength = 'Medium'
            color = "#FFC107"
        elif percentage >= 40:
            strength = 'Weak'
            color = "#FF9800"
        else:
            strength = 'Very Weak'
            color = "#F44336"

        return {
            'length': length,
            'has_uppercase': has_uppercase,
            'has_lowercase': has_lowercase,
            'has_number': has_number,
            'has_special_char': has_special_char,
            'score': score,
            'max_score': max_score,
            'strength': strength,
            'percentage': percentage,
            'min_length': min_length,
            'color': color
        }

    def display_results(self, result):
        self.result_label.configure(text=f"Strength: {result['strength']} ({result['percentage']:.1f}%)",
                                    text_color=result['color'])

        details = (
            f"Password length: {result['length']} (Minimum required: {result['min_length']})\n"
            f"Contains uppercase letters: {result['has_uppercase']}\n"
            f"Contains lowercase letters: {result['has_lowercase']}\n"
            f"Contains numbers: {result['has_number']}\n"
            f"Contains special characters: {result['has_special_char']}\n"
            f"Score: {result['score']} / {result['max_score']}\n"
        )

        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", details)
        self.details_text.configure(state="disabled")

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)
        self.check_password_strength()

if __name__ == "__main__":
    app = PasswordStrengthApp()
    app.mainloop()
