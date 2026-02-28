# python3 -m pip install --break-system-packages --user matplotlib numpy
import numpy as np
import matplotlib.pyplot as plt
import math

# ==========================
# Настраиваемая вероятность
# ==========================
PROBABILITY = 0.01   # например: 0.01, 0.1, 0.5, 0.9
MAX_LENGTH = 256

def collision_threshold(bits: int, p: float) -> float:
    """
    Возвращает количество хешей k,
    при котором вероятность коллизии ≈ p
    для n-битного равномерного хеша.
    """
    N = 2.0 ** bits
    return math.sqrt(-2.0 * N * math.log(1.0 - p))

# Диапазон длин хеша
bit_lengths = np.arange(8, MAX_LENGTH + 1, 8)

# Расчёт значений
values = np.array([collision_threshold(b, PROBABILITY) for b in bit_lengths])

# Построение графика (без логарифма)
plt.figure(figsize=(9, 6))
plt.plot(bit_lengths, values)

plt.xlabel("Длина хеша (бит)")
plt.ylabel(f"Количество хешей до вероятности {PROBABILITY}")
plt.title("Зависимость длины хеша от порога коллизии")
plt.yscale("log")
plt.grid(True)

plt.tight_layout()
plt.show()