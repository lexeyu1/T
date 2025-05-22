import hashlib
import time
import random
import zlib
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# --- Константы ---
BASE_X = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
BASE_Y = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
LAMBDA = "5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72"
BETA = "7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE"
N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"  # порядок группы для secp256k1
P = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"  # модуль поля GF(p)

N_INT = int(N, 16)
P_INT = int(P, 16)

# --- Вспомогательные функции ---
def hex_to_int(h): return int(h, 16)
def int_to_hex(i): return hex(i)[2:].upper()
def reverse_hex(h): return h[::-1]
def xor_hex(a, b): return hex(hex_to_int(a) ^ hex_to_int(b))[2:].upper()
def add_hex(a, b, m=None): return int_to_hex((hex_to_int(a) + hex_to_int(b)) % hex_to_int(m or N))
def mul_hex(a, b, m=None): return int_to_hex((hex_to_int(a) * hex_to_int(b)) % hex_to_int(m or N))
def hash_hex(s): return hashlib.sha256(s.encode()).hexdigest().upper()

# --- Файловые операции ---
LOG_FILENAME = "private_key_generation_log.txt"
RESULT_FILENAME = "private_key_results.txt"

def log_action(message):
    with open(LOG_FILENAME, "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")

def save_results_to_file(results, filename=RESULT_FILENAME):
    with open(filename, "w", encoding="utf-8") as f:
        for key, value in results.items():
            f.write(f"{key}: {value}\n")
    print(f"\nРезультаты сохранены в файл: {filename}")

# --- Дополнительные функции ---
def chained_hash(x, y):
    h1 = hash_hex(x + y)
    h2 = hash_hex(h1 + BASE_X)
    h3 = hash_hex(h2 + LAMBDA)
    return h3[:64]

def mod_exp(x, y):
    return int_to_hex(pow(hex_to_int(x), hex_to_int(y), N_INT))

def crc32_sum(x, y):
    data = bytes.fromhex(x + y)
    return format(zlib.crc32(data) & 0xFFFFFFFF, '08X')

def pbkdf2_key(x, y):
    salt = bytes.fromhex(x + y)
    return pbkdf2_hmac('sha256', b'secret', salt, 100000, 32).hex().upper()

def aes_encrypt(x, y):
    key = bytes.fromhex(x[:32])
    cipher = AES.new(key, AES.MODE_ECB)
    msg = pad(bytes.fromhex(y), AES.block_size)
    return cipher.encrypt(msg).hex().upper()

def permute_blocks(x, y, size=8):
    return ''.join(x[i:i+size] if i//size % 2 == 0 else y[i:i+size] for i in range(0, len(x), size)).upper()

def bit_permutation(x, y):
    bits = bin(int(x + y, 16))[2:].zfill(512)
    return hex(int(''.join(bits[i] for i in [i ^ 0xFF for i in range(512)]), 2))[2:].upper()

def gf_add(x, y):
    return int_to_hex((pow(hex_to_int(x), 1, P_INT) + pow(hex_to_int(y), 1, P_INT)) % P_INT)

def add_mod_prime(x, y):
    return int_to_hex((hex_to_int(x) + hex_to_int(y)) % P_INT)

def rng_from_seed(x, y, seed=None):
    if not seed:
        seed = str(int(time.time()))
    try:
        seed_int = int(seed)
        seed_bytes = seed_int.to_bytes((seed_int.bit_length() + 7) // 8, 'big')
    except:
        seed_bytes = seed.encode()
    combined = bytes.fromhex(x + y) + seed_bytes
    seed_value = hashlib.sha256(combined).digest()
    rand_gen = random.Random(seed_value)
    priv_key_int = rand_gen.randint(1, N_INT - 1)
    return int_to_hex(priv_key_int)

def mod_exp_with_base(x):
    return int_to_hex(pow(hex_to_int(x), hex_to_int(BASE_X), N_INT))

def crc32_with_base(x):
    data = bytes.fromhex(x + BASE_X)
    return format(zlib.crc32(data) & 0xFFFFFFFF, '08X')

def permute_with_base(x, base_x, size=8):
    return ''.join(x[i:i+size] if i//size % 2 == 0 else base_x[i:i+size] for i in range(0, len(x), size)).upper()

def bit_permutation_with_base(x, base_x):
    bits = bin(int(x + base_x, 16))[2:].zfill(512)
    return hex(int(''.join(bits[i] for i in [i ^ 0xFF for i in range(512)]), 2))[2:].upper()

def mirror_combine(x, base_x):
    rev_base = reverse_hex(base_x)
    res = add_hex(x, rev_base, N)
    return reverse_hex(res)

def mirror_combine_inverse(x, base_x):
    rev_x = reverse_hex(x)
    res = add_hex(base_x, rev_x, N)
    return reverse_hex(res)

def search_around_seed(x, seed, delta=100):
    combined = bytes.fromhex(x + BASE_X) + (seed.encode() if isinstance(seed, str) else seed)
    seed_value = hashlib.sha256(combined).digest()
    rand_gen = random.Random(seed_value)
    start_key = rand_gen.randint(1, N_INT - 1)

    keys = {}
    for i in range(-delta, delta + 1):
        candidate = (start_key + i) % N_INT
        if 1 <= candidate < N_INT:
            key_hex = int_to_hex(candidate).zfill(64)
            keys[f"Key_{i:+d}"] = key_hex
    return keys

def mod_inverse(a, m=N_INT):
    try:
        return pow(a, -1, m)
    except ValueError:
        return None

def inverse_all_results(results_dict):
    inverses = {}
    for key, value in results_dict.items():
        try:
            val_int = int(value, 16)
            inv = mod_inverse(val_int)
            if inv is not None:
                inverses[f"{key}_inv"] = int_to_hex(inv).zfill(64)
            else:
                inverses[f"{key}_inv"] = "Обратного элемента нет"
        except Exception:
            inverses[f"{key}_inv"] = "Ошибка вычисления"
    return inverses

def hash_all_results(results_dict):
    hashed = {}
    for key, value in results_dict.items():
        try:
            value_int = int(value, 16)
            value_hex = value.zfill(64)
        except:
            value_hex = value.encode().hex()
        hashed[f"{key}_sha256"] = hash_hex(value_hex)
    return hashed

def double_hash_all_results(results_dict):
    """Выполняет SHA256(SHA256(...)) для каждого значения"""
    double_hashed = {}
    for key, value in results_dict.items():
        try:
            value_int = int(value, 16)
            value_hex = value.zfill(64)
        except:
            value_hex = value.encode().hex()
        first_hash = hash_hex(value_hex)
        second_hash = hash_hex(first_hash)
        double_hashed[f"{key}_double_sha256"] = second_hash
    return double_hashed

# --- Меню ---
def show_menu():
    print("\nМетоды генерации приватного ключа:")
    print("1. Арифметические операции между x и y (+, -, *, XOR)")
    print("2. Арифметические операции с обратными x и y")
    print("3. Комбинация с базовой точкой (x*base_x + y*base_y)")
    print("4. Комбинация с обратными базовой точкой")
    print("5. Использование параметров λ и β (x*λ + y*β)")
    print("6. Использование обратных параметров λ и β")
    print("7. Хеширование комбинации (SHA256(x + y + base_x + base_y))")
    print("8. Хеширование обратной комбинации")
    print("9. Перекодировка через конкатенацию первых 32 символов x и y")
    print("10. Перекодировка через конкатенацию последних 32 символов x и y")
    print("——— Дополнительные методы ———")
    print("11. Хэш-цепочка из x/y/base/lambda/etc.")
    print("12. Возведение x в степень y по модулю N")
    print("13. CRC32 от x + y")
    print("14. PBKDF2 с x + y как солью")
    print("15. AES-шифрование с ключом из x")
    print("16. Разбиение x/y на блоки и перестановка")
    print("17. Кастомная перестановка битов x + y")
    print("18. Сложение по модулю P")
    print("19. DRBG от x + y + seed")
    print("20. Возведение x в степень BASE_X по модулю N")
    print("21. CRC32 от x + BASE_X")
    print("22. Перестановка x и BASE_X")
    print("23. Перестановка битов x + BASE_X")
    print("24. DRBG от x + BASE_X + seed (поиск ±100)")
    print("25. Зеркальное отражение x + BASE_X")
    print("26. Зеркальное отражение BASE_X + x")
    print("27. Выполнить все методы подряд")
    print("28. SHA256 всех найденных значений")
    print("29. Обратные значения всех найденных ключей по модулю N")
    print("30. Двойное хеширование SHA256(SHA256(...))")
    print("31. Выход")
    return input("Выберите метод (1-31): ")

# --- Основная логика ---
def main():
    all_results = {}

    print("Генерация приватного ключа из координат эллиптической кривой")
    x = input("Введите координату x: ").strip().upper()
    y = input("Введите координату y: ").strip().upper()

    log_action(f"Введено: x={x}, y={y}")

    while True:
        choice = show_menu()

        if choice == '1':
            res1 = add_hex(x, y, N)
            res2 = mul_hex(x, y, N)
            res3 = xor_hex(x, y)
            all_results.update({"x_plus_y": res1, "x_mul_y": res2, "x_xor_y": res3})
            print(f"x + y = {res1}\nx * y = {res2}\nx XOR y = {res3}")

        elif choice == '2':
            rev_x = reverse_hex(x)
            rev_y = reverse_hex(y)
            res1 = add_hex(rev_x, rev_y, N)
            res2 = xor_hex(rev_x, rev_y)
            all_results.update({"rev_x_plus_rev_y": res1, "rev_x_xor_rev_y": res2})
            print(f"rev_x + rev_y = {res1}\nrev_x XOR rev_y = {res2}")

        elif choice == '3':
            term1 = mul_hex(x, BASE_X, N)
            term2 = mul_hex(y, BASE_Y, N)
            res = add_hex(term1, term2, N)
            all_results["x_base_x_plus_y_base_y"] = res
            print(f"x*base_x + y*base_y = {res}")

        elif choice == '4':
            rev_x = reverse_hex(x)
            rev_y = reverse_hex(y)
            term1 = mul_hex(rev_x, reverse_hex(BASE_X), N)
            term2 = mul_hex(rev_y, reverse_hex(BASE_Y), N)
            res = add_hex(term1, term2, N)
            all_results["rev_x_rev_base_x_plus_rev_y_rev_base_y"] = res
            print(f"rev_x*rev_base_x + rev_y*rev_base_y = {res}")

        elif choice == '5':
            term1 = mul_hex(x, LAMBDA, N)
            term2 = mul_hex(y, BETA, N)
            res = add_hex(term1, term2, N)
            all_results["x_lambda_plus_y_beta"] = res
            print(f"x*λ + y*β = {res}")

        elif choice == '6':
            rev_x = reverse_hex(x)
            rev_y = reverse_hex(y)
            term1 = mul_hex(rev_x, reverse_hex(LAMBDA), N)
            term2 = mul_hex(rev_y, reverse_hex(BETA), N)
            res = add_hex(term1, term2, N)
            all_results["rev_x_rev_lambda_plus_rev_y_rev_beta"] = res
            print(f"rev_x*rev_λ + rev_y*rev_β = {res}")

        elif choice == '7':
            combined = x + y + BASE_X + BASE_Y
            hashed = hash_hex(combined)
            all_results["SHA256_x_y_base"] = hashed
            print(f"SHA256(x+y+base_x+base_y) = {hashed}")

        elif choice == '8':
            rev_x = reverse_hex(x)
            rev_y = reverse_hex(y)
            combined = rev_x + rev_y + reverse_hex(BASE_X) + reverse_hex(BASE_Y)
            hashed = hash_hex(combined)
            all_results["SHA256_rev_x_rev_y_rev_base"] = hashed
            print(f"SHA256(rev_x+rev_y+rev_base_x+rev_base_y) = {hashed}")

        elif choice == '9':
            priv_key = (x[:32] + y[:32]).upper()
            all_results["ConcatFirst32"] = priv_key
            print(f"Конкатенация первых половин x и y: {priv_key}")

        elif choice == '10':
            priv_key = (x[-32:] + y[-32:]).upper()
            all_results["ConcatLast32"] = priv_key
            print(f"Конкатенация последних половин x и y: {priv_key}")

        elif choice == '11':
            res = chained_hash(x, y)
            all_results["ChainedHash"] = res
            print(f"Хэш-цепочка: {res}")

        elif choice == '12':
            res = mod_exp(x, y)
            all_results["ModExpXY"] = res
            print(f"x^y mod N: {res}")

        elif choice == '13':
            res = crc32_sum(x, y)
            all_results["CRC32_xy"] = res
            print(f"CRC32 от x + y: {res}")

        elif choice == '14':
            res = pbkdf2_key(x, y)
            all_results["PBKDF2_xy"] = res
            print(f"PBKDF2: {res}")

        elif choice == '15':
            res = aes_encrypt(x, y)
            all_results["AES_Encrypt"] = res
            print(f"AES-шифрование: {res}")

        elif choice == '16':
            res = permute_blocks(x, y)
            all_results["BlockPermute"] = res
            print(f"Перестановка блоков: {res}")

        elif choice == '17':
            res = bit_permutation(x, y)
            all_results["BitPermutationXY"] = res
            print(f"Битовая перестановка: {res}")

        elif choice == '18':
            res = add_mod_prime(x, y)
            all_results["AddModP"] = res
            print(f"Сложение по модулю P: {res}")

        elif choice == '19':
            custom_seed = input("Введите seed: ").strip()
            result = rng_from_seed(x, y, custom_seed)
            all_results["DRBG_xy_seed"] = result
            print(f"DRBG от x + y + seed: {result}")

        elif choice == '20':
            res = mod_exp_with_base(x)
            all_results["ModExpXBase"] = res
            print(f"x^base_x mod N: {res}")

        elif choice == '21':
            res = crc32_with_base(x)
            all_results["CRC32_x_base"] = res
            print(f"CRC32 от x + base_x: {res}")

        elif choice == '22':
            res = permute_with_base(x, BASE_X)
            all_results["BlockPermuteXBase"] = res
            print(f"Перестановка x и base_x: {res}")

        elif choice == '23':
            res = bit_permutation_with_base(x, BASE_X)
            all_results["BitPermutationXBase"] = res
            print(f"Битовая перестановка x + base_x: {res}")

        elif choice == '24':
            custom_seed = input("Введите seed: ").strip()
            keys = search_around_seed(x, custom_seed)
            all_results.update(keys)
            print(f"\nНайдено {len(keys)} ключей:")
            for k, v in keys.items():
                print(f"{k}: {v}")
            save_results_to_file(keys)
            log_action(f"Поиск ±100 выполнен, найдено {len(keys)} ключей.")

        elif choice == '25':
            res = mirror_combine(x, BASE_X)
            all_results["MirrorXBase"] = res
            print(f"Зеркало x + base_x: {res}")

        elif choice == '26':
            res = mirror_combine_inverse(x, BASE_X)
            all_results["MirrorBaseX"] = res
            print(f"Зеркало base_x + x: {res}")

        elif choice == '27':
            print("\nВыполняем все методы подряд...")
            all_results.update({
                "x_plus_y": add_hex(x, y, N),
                "x_mul_y": mul_hex(x, y, N),
                "x_xor_y": xor_hex(x, y),
                "rev_x_plus_rev_y": add_hex(reverse_hex(x), reverse_hex(y), N),
                "rev_x_xor_rev_y": xor_hex(reverse_hex(x), reverse_hex(y)),
                "x_base_x_plus_y_base_y": add_hex(mul_hex(x, BASE_X, N), mul_hex(y, BASE_Y, N), N),
                "rev_x_rev_base_x_plus_rev_y_rev_base_y": add_hex(mul_hex(reverse_hex(x), reverse_hex(BASE_X), N),
                                                               mul_hex(reverse_hex(y), reverse_hex(BASE_Y), N), N),
                "x_lambda_plus_y_beta": add_hex(mul_hex(x, LAMBDA, N), mul_hex(y, BETA, N), N),
                "rev_x_rev_lambda_plus_rev_y_rev_beta": add_hex(mul_hex(reverse_hex(x), reverse_hex(LAMBDA), N),
                                                              mul_hex(reverse_hex(y), reverse_hex(BETA), N), N),
                "SHA256_x_y_base": hash_hex(x + y + BASE_X + BASE_Y),
                "SHA256_rev_x_rev_y_rev_base": hash_hex(reverse_hex(x) + reverse_hex(y) + reverse_hex(BASE_X) + reverse_hex(BASE_Y)),
                "ConcatFirst32": x[:32] + y[:32],
                "ConcatLast32": x[-32:] + y[-32:],
                "ChainedHash": chained_hash(x, y),
                "ModExpXY": mod_exp(x, y),
                "CRC32_xy": crc32_sum(x, y),
                "PBKDF2_xy": pbkdf2_key(x, y),
                "AES_Encrypt": aes_encrypt(x, y),
                "BlockPermute": permute_blocks(x, y),
                "BitPermutationXY": bit_permutation(x, y),
                "AddModP": add_mod_prime(x, y),
                "ModExpXBase": mod_exp_with_base(x),
                "CRC32_x_base": crc32_with_base(x),
                "BlockPermuteXBase": permute_with_base(x, BASE_X),
                "BitPermutationXBase": bit_permutation_with_base(x, BASE_X),
                "MirrorXBase": mirror_combine(x, BASE_X),
                "MirrorBaseX": mirror_combine_inverse(x, BASE_X),
            })
            print("✅ Все методы выполнены. Результаты собраны в all_results.")

        elif choice == '28':
            if not all_results:
                print("❌ Нет данных для хеширования.")
            else:
                hashed = hash_all_results(all_results)
                all_results.update(hashed)
                print("\n🔐 SHA256 всех результатов:")
                for k, v in hashed.items():
                    print(f"{k}: {v}")
                save_results_to_file(hashed, "hashed_private_keys.txt")
                log_action("Вычислены SHA256 хэши всех результатов")

        elif choice == '29':
            if not all_results:
                print("❌ Нет данных для вычисления обратных значений.")
            else:
                inverses = inverse_all_results(all_results)
                print("\n🧮 Обратные значения по модулю N:")
                for k, v in inverses.items():
                    print(f"{k}: {v}")
                save_results_to_file(inverses, "inverted_private_keys.txt")
                log_action("Вычислены обратные значения по модулю N")

        elif choice == '30':
            if not all_results:
                print("❌ Нет данных для двойного хеширования.")
            else:
                double_hashed = double_hash_all_results(all_results)
                all_results.update(double_hashed)
                print("\n🔁 Двойное хеширование SHA256(SHA256(...)):")
                for k, v in double_hashed.items():
                    print(f"{k}: {v}")
                save_results_to_file(double_hashed, "double_hashed_private_keys.txt")
                log_action("Вычислены двойные SHA256 хэши всех результатов")

        elif choice == '31':
            print("Выход...")
            break

        else:
            print("Неверный выбор!")

# --- Запуск ---
if __name__ == "__main__":
    main()