"""
CrypRat — учебный консольный шифратор (моноалфавитная подстановка).

⚠ Это учебный проект. Используемый алгоритм не даёт криптографической
стойкости и легко взламывается частотным анализом. Не используйте для
защиты реальных секретов — для этого нужен AES/ChaCha20 и т.п.
"""

from __future__ import annotations

import base64
import secrets
import string
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Цветной вывод (без внешних зависимостей; безопасный фолбэк без цвета)
# ---------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def c(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return "".join(codes) + text + Color.RESET


# ---------------------------------------------------------------------------
# Алфавит и шифр — без глобального изменяемого состояния
# ---------------------------------------------------------------------------

ALPHABET: str = " " + string.punctuation + string.digits + string.ascii_letters


class CipherError(Exception):
    """Неизвестный символ, либо повреждённый/неверный ключ."""


@dataclass
class EncryptionResult:
    ciphertext: str
    key_token: str  # компактный вид ключа, безопасный для копирования


class SubstitutionCipher:
    """Моноалфавитный шифр подстановки на фиксированном алфавите ALPHABET."""

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
# CLI / меню
# ---------------------------------------------------------------------------

BANNER = r"""
   ______                 ____        __
  / ____/______  ______  / __ \____ _/ /_
 / /   / ___/ / / / __ \/ /_/ / __ `/ __/
/ /___/ /  / /_/ / /_/ / _, _/ /_/ / /_
\____/_/   \__, / .___/_/ |_|\__,_/\__/
          /____/_/
"""


def print_banner() -> None:
    print(c(BANNER, Color.CYAN, Color.BOLD))
    print(c("  Учебный консольный шифратор", Color.DIM))
    print(c("  ⚠ Не для защиты реальных данных\n", Color.YELLOW))


def print_menu() -> None:
    print(c("┌───────────────────────────────────────┐", Color.CYAN))
    print(c("│  1. Зашифровать сообщение              │", Color.CYAN))
    print(c("│  2. Расшифровать сообщение             │", Color.CYAN))
    print(c("│  3. О программе                        │", Color.CYAN))
    print(c("│  4. Выход                              │", Color.CYAN))
    print(c("└───────────────────────────────────────┘", Color.CYAN))


def action_encrypt(cipher: SubstitutionCipher) -> None:
    text = input(c("Введите сообщение для шифрования: ", Color.BOLD))
    try:
        result = cipher.encrypt(text)
    except CipherError as exc:
        print(c(f"Ошибка: {exc}", Color.RED))
        return
    print()
    print(c("Зашифрованное сообщение:", Color.GREEN), result.ciphertext)
    print(c("Ключ (сохраните — без него расшифровка невозможна):", Color.YELLOW))
    print(result.key_token)
    print()


def action_decrypt(cipher: SubstitutionCipher) -> None:
    text = input(c("Введите зашифрованное сообщение: ", Color.BOLD))
    key_token = input(c("Введите ключ: ", Color.BOLD))
    try:
        plaintext = cipher.decrypt(text, key_token)
    except CipherError as exc:
        print(c(f"Ошибка: {exc}", Color.RED))
        return
    print()
    print(c("Расшифрованное сообщение:", Color.GREEN), plaintext)
    print()


def action_about() -> None:
    print()
    print("CrypRat — учебная программа шифрования текста.")
    print("Алгоритм: моноалфавитная замена со случайным ключом на каждое сообщение.")
    print("Ключ не хранится программой — вы отвечаете за его сохранение и передачу.")
    print(c("Внимание: этот шифр легко взламывается частотным анализом и", Color.YELLOW))
    print(c("не подходит для защиты реальных секретов.", Color.YELLOW))
    print()


def main() -> None:
    cipher = SubstitutionCipher()
    print_banner()
    while True:
        print_menu()
        try:
            choice = input(c("Выберите пункт (1-4): ", Color.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nВыход.")
            break

        if choice == "1":
            action_encrypt(cipher)
        elif choice == "2":
            action_decrypt(cipher)
        elif choice == "3":
            action_about()
        elif choice == "4":
            print(c("До встречи!", Color.CYAN))
            break
        else:
            print(c("Некорректный выбор. Введите число от 1 до 4.", Color.RED))


if __name__ == "__main__":
    main()
