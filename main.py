"""
CrypRat — учебный шифратор с ретро-интерфейсом (вайб Windows 95/98).

Главная точка входа программы. При запуске (двойным кликом или
командой `python main.py`) сразу открывается графическое окно —
если программа была запущена через python.exe (который по умолчанию
тянет за собой окно консоли), она незаметно перезапускает сама себя
через pythonw.exe (без консоли) и закрывает исходный консольный
процесс — так что в итоге видно только окно GUI.

⚠ Учебный проект: алгоритм — моноалфавитная подстановка, не для
защиты реальных секретов.
"""

from __future__ import annotations

import base64
import os
import secrets
import string
import subprocess
import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont

# ---------------------------------------------------------------------------
# Логика шифра (та же, что в консольной версии — без изменений)
# ---------------------------------------------------------------------------

CYRILLIC_LOWER: str = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяіїєґ"
CYRILLIC_UPPER: str = CYRILLIC_LOWER.upper()

ALPHABET: str = (
    " "
    + string.punctuation
    + string.digits
    + string.ascii_letters
    + CYRILLIC_LOWER
    + CYRILLIC_UPPER
)


class CipherError(Exception):
    pass


@dataclass
class EncryptionResult:
    ciphertext: str
    key_token: str


class SubstitutionCipher:
    alphabet: str = ALPHABET

    @staticmethod
    def generate_key() -> list[str]:
        key = list(SubstitutionCipher.alphabet)
        secrets.SystemRandom().shuffle(key)
        return key

    @staticmethod
    def key_to_token(key: list[str]) -> str:
        raw = "".join(key).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @staticmethod
    def key_from_token(token: str) -> list[str]:
        try:
            raw = base64.urlsafe_b64decode(token.strip().encode("ascii")).decode("utf-8")
        except Exception as exc:
            raise CipherError("Ключ повреждён или введён неверно.") from exc
        key = list(raw)
        if sorted(key) != sorted(SubstitutionCipher.alphabet):
            raise CipherError("Ключ не соответствует ожидаемому алфавиту.")
        return key

    def encrypt(self, plaintext: str) -> EncryptionResult:
        key = self.generate_key()
        try:
            ciphertext = "".join(key[self.alphabet.index(ch)] for ch in plaintext)
        except ValueError as exc:
            bad = next(ch for ch in plaintext if ch not in self.alphabet)
            raise CipherError(f"Символ {bad!r} не поддерживается алфавитом программы.") from exc
        return EncryptionResult(ciphertext=ciphertext, key_token=self.key_to_token(key))

    def decrypt(self, ciphertext: str, key_token: str) -> str:
        key = self.key_from_token(key_token)
        try:
            return "".join(self.alphabet[key.index(ch)] for ch in ciphertext)
        except ValueError as exc:
            bad = next((ch for ch in ciphertext if ch not in key), "?")
            raise CipherError(
                f"Символ {bad!r} отсутствует в ключе — неверный ключ или повреждённый шифротекст."
            ) from exc


# ---------------------------------------------------------------------------
# Ретро-палитра (Windows 95/98 "classic grey")
# ---------------------------------------------------------------------------

BG = "#c0c0c0"
TITLEBAR = "#000080"
TITLEBAR_TEXT = "#ffffff"
BORDER_LIGHT = "#ffffff"
BORDER_DARK = "#808080"
TEXT_BG = "#ffffff"
ACCENT = "#000080"


def retro_font(size: int = 9, bold: bool = False) -> tuple:
    family = "MS Sans Serif"
    try:
        families = set(tkfont.families())
    except Exception:
        families = set()
    if family not in families:
        family = "Tahoma" if "Tahoma" in families else "Helvetica"
    return (family, size, "bold" if bold else "normal")


class Raised(tk.Frame):
    """Панель с объёмной 3D-рамкой 'в стиле Windows 95'."""

    def __init__(self, master, **kw):
        super().__init__(master, bg=BG, bd=2, relief="raised", **kw)


class RetroButton(tk.Button):
    def __init__(self, master, **kw):
        kw.setdefault("bg", BG)
        kw.setdefault("activebackground", BG)
        kw.setdefault("relief", "raised")
        kw.setdefault("bd", 2)
        kw.setdefault("font", retro_font())
        kw.setdefault("padx", 10)
        kw.setdefault("pady", 4)
        super().__init__(master, **kw)


class CustomTitleBar(tk.Frame):
    """Имитация синего заголовка окна Windows 95 (т.к. overrideredirect
    убирает системную рамку)."""

    def __init__(self, master, title: str, on_close):
        super().__init__(master, bg=TITLEBAR, height=26)
        self.pack_propagate(False)
        label = tk.Label(
            self, text=title, bg=TITLEBAR, fg=TITLEBAR_TEXT,
            font=retro_font(9, bold=True), anchor="w"
        )
        label.pack(side="left", padx=6)

        close_btn = tk.Button(
            self, text="X", command=on_close, bg=BG, relief="raised", bd=1,
            font=("Arial", 8, "bold"), width=2, cursor="hand2"
        )
        close_btn.pack(side="right", padx=2, pady=2)

        min_btn = tk.Button(
            self, text="_", command=self._minimize, bg=BG, relief="raised", bd=1,
            font=("Arial", 8, "bold"), width=2, cursor="hand2"
        )
        min_btn.pack(side="right", padx=0, pady=2)

        for widget in (self, label):
            widget.bind("<ButtonPress-1>", self._start_move)
            widget.bind("<B1-Motion>", self._do_move)

        self._drag_x = 0
        self._drag_y = 0

    def _start_move(self, event) -> None:
        self._drag_x = event.x
        self._drag_y = event.y

    def _do_move(self, event) -> None:
        root = self.winfo_toplevel()
        x = root.winfo_x() + (event.x - self._drag_x)
        y = root.winfo_y() + (event.y - self._drag_y)
        root.geometry(f"+{x}+{y}")

    def _minimize(self) -> None:
        root = self.winfo_toplevel()
        # Окну без стандартной рамки (overrideredirect) Windows обычно не
        # даёт значка в панели задач, так что "свернуть" выглядело бы как
        # "закрыть" — нечем будет вернуть окно обратно. Поэтому сначала на
        # мгновение возвращаем обычную рамку (чтобы Windows успела завести
        # значок в панели задач), ждём немного (update_idletasks + after),
        # и только потом сворачиваем — это даёт менеджеру окон время
        # зарегистрировать окно, вместо того чтобы сворачивать и убирать
        # рамку практически одновременно.
        root.overrideredirect(False)
        root.update_idletasks()
        root.after(60, root.iconify)

        def _on_restore(_event=None) -> None:
            if root.state() == "normal":
                root.unbind("<Map>")
                root.after(60, lambda: root.overrideredirect(True))

        root.bind("<Map>", _on_restore)


# ---------------------------------------------------------------------------
# Экраны приложения
# ---------------------------------------------------------------------------

class EncryptScreen(Raised):
    def __init__(self, master, cipher: SubstitutionCipher, show_menu):
        super().__init__(master)
        font_lbl = retro_font(9, bold=True)
        font_mono = ("Courier New", 10)

        tk.Label(self, text="Сообщение для шифрования:", bg=BG, font=font_lbl).pack(
            anchor="w", padx=8, pady=(8, 2)
        )
        self.input = tk.Text(self, height=5, width=48, font=font_mono, bd=2, relief="sunken")
        self.input.pack(padx=8, pady=(0, 6))

        RetroButton(self, text="Зашифровать →", command=self._encrypt).pack(pady=4)

        tk.Label(self, text="Результат:", bg=BG, font=font_lbl).pack(anchor="w", padx=8, pady=(6, 2))
        self.output = tk.Text(self, height=3, width=48, font=font_mono, bd=2, relief="sunken", state="disabled")
        self.output.pack(padx=8, pady=(0, 2))
        RetroButton(self, text="📋 Копировать шифротекст", command=self._copy_ciphertext).pack(pady=(0, 6))

        tk.Label(self, text="Ключ (сохраните — без него не расшифровать):", bg=BG, font=font_lbl).pack(
            anchor="w", padx=8, pady=(0, 2)
        )
        self.key_box = tk.Text(self, height=3, width=48, font=font_mono, bd=2, relief="sunken", state="disabled")
        self.key_box.pack(padx=8, pady=(0, 2))
        RetroButton(self, text="📋 Копировать ключ", command=self._copy_key).pack(pady=(0, 6))

        self.status = tk.Label(self, text="", bg=BG, fg="#aa0000", font=retro_font(8))
        self.status.pack(anchor="w", padx=8)

        RetroButton(self, text="← Назад в меню", command=show_menu).pack(pady=(4, 8))

        self.cipher = cipher
        self._last_ciphertext = ""
        self._last_key_token = ""

    def _set_readonly_text(self, widget: tk.Text, value: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _copy_to_clipboard(self, value: str) -> None:
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self.update()  # чтобы буфер обмена сохранился, даже если окно сразу закроют
        self.status.configure(text="Скопировано в буфер обмена", fg="#006600")

    def _copy_ciphertext(self) -> None:
        self._copy_to_clipboard(self._last_ciphertext)

    def _copy_key(self) -> None:
        self._copy_to_clipboard(self._last_key_token)

    def _encrypt(self) -> None:
        text = self.input.get("1.0", "end-1c")
        try:
            result = self.cipher.encrypt(text)
        except CipherError as exc:
            self.status.configure(text=f"Ошибка: {exc}", fg="#aa0000")
            return
        self.status.configure(text="", fg="#aa0000")
        self._last_ciphertext = result.ciphertext
        self._last_key_token = result.key_token
        self._set_readonly_text(self.output, result.ciphertext)
        self._set_readonly_text(self.key_box, result.key_token)


class DecryptScreen(Raised):
    def __init__(self, master, cipher: SubstitutionCipher, show_menu):
        super().__init__(master)
        font_lbl = retro_font(9, bold=True)
        font_mono = ("Courier New", 10)

        tk.Label(self, text="Зашифрованное сообщение:", bg=BG, font=font_lbl).pack(
            anchor="w", padx=8, pady=(8, 2)
        )
        self.cipher_input = tk.Text(self, height=4, width=48, font=font_mono, bd=2, relief="sunken")
        self.cipher_input.pack(padx=8, pady=(0, 6))

        tk.Label(self, text="Ключ:", bg=BG, font=font_lbl).pack(anchor="w", padx=8, pady=(0, 2))
        self.key_input = tk.Text(self, height=3, width=48, font=font_mono, bd=2, relief="sunken")
        self.key_input.pack(padx=8, pady=(0, 6))

        RetroButton(self, text="Расшифровать →", command=self._decrypt).pack(pady=4)

        tk.Label(self, text="Результат:", bg=BG, font=font_lbl).pack(anchor="w", padx=8, pady=(6, 2))
        self.output = tk.Text(self, height=4, width=48, font=font_mono, bd=2, relief="sunken", state="disabled")
        self.output.pack(padx=8, pady=(0, 2))
        RetroButton(self, text="📋 Копировать результат", command=self._copy_result).pack(pady=(0, 6))

        self.status = tk.Label(self, text="", bg=BG, fg="#aa0000", font=retro_font(8))
        self.status.pack(anchor="w", padx=8)

        RetroButton(self, text="← Назад в меню", command=show_menu).pack(pady=(4, 8))

        self.cipher = cipher
        self._last_plaintext = ""

    def _copy_result(self) -> None:
        if not self._last_plaintext:
            return
        self.clipboard_clear()
        self.clipboard_append(self._last_plaintext)
        self.update()
        self.status.configure(text="Скопировано в буфер обмена", fg="#006600")

    def _decrypt(self) -> None:
        ciphertext = self.cipher_input.get("1.0", "end-1c")
        key_token = self.key_input.get("1.0", "end-1c")
        try:
            plaintext = self.cipher.decrypt(ciphertext, key_token)
        except CipherError as exc:
            self.status.configure(text=f"Ошибка: {exc}", fg="#aa0000")
            return
        self.status.configure(text="", fg="#aa0000")
        self._last_plaintext = plaintext
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", plaintext)
        self.output.configure(state="disabled")


class MainMenu(Raised):
    def __init__(self, master, show_encrypt, show_decrypt):
        super().__init__(master)
        tk.Label(
            self, text="CrypRat", bg=BG, font=retro_font(20, bold=True), fg=ACCENT
        ).pack(pady=(20, 0))
        tk.Label(
            self, text="учебный шифратор", bg=BG, font=retro_font(9)
        ).pack(pady=(0, 20))

        RetroButton(self, text="🔒  Зашифровать сообщение", width=28, command=show_encrypt).pack(pady=6)
        RetroButton(self, text="🔓  Расшифровать сообщение", width=28, command=show_decrypt).pack(pady=6)

        tk.Label(
            self, text="⚠ Не для защиты реальных секретов", bg=BG,
            font=retro_font(8), fg="#aa0000"
        ).pack(pady=(20, 16))


class CrypRatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.overrideredirect(True)
        self.configure(bg=BORDER_DARK)
        self.geometry("440x620+280+80")
        self.resizable(False, False)
        self._set_icon()

        outer = tk.Frame(self, bg=BORDER_DARK, bd=2)
        outer.pack(fill="both", expand=True, padx=2, pady=2)

        CustomTitleBar(outer, "CrypRat.exe — учебный шифратор", self._close).pack(fill="x")

        self.body = tk.Frame(outer, bg=BG)
        self.body.pack(fill="both", expand=True)

        self.cipher = SubstitutionCipher()
        self.current: tk.Widget | None = None
        self._show_menu()

    def _clear(self) -> None:
        if self.current is not None:
            self.current.destroy()

    def _show_menu(self) -> None:
        self._clear()
        self.current = MainMenu(self.body, self._show_encrypt, self._show_decrypt)
        self.current.pack(fill="both", expand=True, padx=4, pady=4)

    def _show_encrypt(self) -> None:
        self._clear()
        self.current = EncryptScreen(self.body, self.cipher, self._show_menu)
        self.current.pack(fill="both", expand=True, padx=4, pady=4)

    def _show_decrypt(self) -> None:
        self._clear()
        self.current = DecryptScreen(self.body, self.cipher, self._show_menu)
        self.current.pack(fill="both", expand=True, padx=4, pady=4)

    def _close(self) -> None:
        self.destroy()

    def _set_icon(self) -> None:
        """Пытается поставить icon.ico, если он лежит рядом с программой.
        Если файла нет (или это не Windows) — просто остаётся иконка по
        умолчанию, без ошибок."""
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass


def _relaunch_without_console() -> bool:
    """На Windows: если этот процесс привязан к окну консоли (запуск
    двойным кликом или командой `python main.py`), перезапустить себя
    через pythonw.exe (который консоль не создаёт) и вернуть True, чтобы
    текущий процесс сразу завершился. На не-Windows системах или если
    pythonw.exe не найден — ничего не делает (GUI просто откроется как
    обычно, вместе с терминалом, из которого его запустили)."""
    if sys.platform != "win32":
        return False
    if os.environ.get("CRYPRAT_NO_RELAUNCH") == "1":
        return False  # уже перезапускались один раз — не зацикливаемся
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        return False
    try:
        env = os.environ.copy()
        env["CRYPRAT_NO_RELAUNCH"] = "1"
        subprocess.Popen(
            [pythonw, os.path.abspath(__file__)],
            env=env,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return True
    except Exception:
        return False


if __name__ == "__main__":
    if _relaunch_without_console():
        sys.exit(0)
    CrypRatApp().mainloop()
