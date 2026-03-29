import random

# ---------- BASIC GENERATORS ----------
def generate_random_pin():
    return str(random.randint(0, 999999)).zfill(6)


def generate_repeated_pin():
    digit = str(random.randint(0, 9))
    return digit * 6


def generate_sequential_pin():
    sequences = [
        "012345", "123456", "234567", "345678",
        "456789", "987654", "876543", "765432"
    ]
    return random.choice(sequences)


def generate_birthdate_pin():
    day = random.randint(1, 31)
    month = random.randint(1, 12)
    year = random.randint(0, 99)

    return f"{day:02d}{month:02d}{year:02d}"

# ---------- MAIN GENERATOR ----------
def generate_pin():
    r = random.random()

    if r < 0.4:
        return generate_birthdate_pin()
    elif r < 0.6:
        return generate_repeated_pin()
    elif r < 0.75:
        return generate_sequential_pin()
    else:
        return generate_random_pin()


def generate_dataset(n=100000):
    return [generate_pin() for _ in range(n)]