import csv
import random

# ---- Settings ----
n_rows = 100
output_file = "sample_data.csv"
missing_rate = 0.05
missing_tokens = ["", "NA", "NULL", "N/A"]

def maybe_missing(value):
    if random.random() < missing_rate:
        return random.choice(missing_tokens)
    return value

# Example names
first_names = [
    "Alice","Bob","Carol","David","Emma","Frank","Grace","Hannah","Ivan","Julia",
    "Kevin","Laura","Mike","Nina","Omar","Paula","Quinn","Ravi","Sara","Tom"
]

last_names = [
    "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis",
    "Rodriguez","Martinez","Lee","Walker","Hall","Allen"
]

categories1 = ["A","B","C"]
categories2 = ["Yes","No"]
categories3 = ["Low","Medium","High"]

# ---- Column names (10 total) ----
headers = [
    "name",
    "age",
    "height_cm",
    "weight_kg",
    "score",
    "group",
    "smoker",
    "risk_level",
    "visits",
    "satisfaction"
]

# ---- Generate data ----
with open(output_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(headers)

    for _ in range(n_rows):
        name = random.choice(first_names) + " " + random.choice(last_names)

        row = [
            maybe_missing(name),                               # name
            maybe_missing(random.randint(18, 80)),             # age
            maybe_missing(round(random.uniform(150, 200), 1)), # height
            maybe_missing(round(random.uniform(50, 120), 1)),  # weight
            maybe_missing(round(random.uniform(0, 100), 2)),   # score
            maybe_missing(random.choice(categories1)),         # group
            maybe_missing(random.choice(categories2)),         # smoker
            maybe_missing(random.choice(categories3)),         # risk
            maybe_missing(random.randint(0, 20)),              # visits
            maybe_missing(random.randint(1, 5))                # satisfaction
        ]

        writer.writerow(row)

print(f"Created {output_file} with {n_rows} rows.")
