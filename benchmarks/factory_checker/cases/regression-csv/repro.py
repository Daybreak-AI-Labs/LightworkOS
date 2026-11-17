import csv
import io
import sys

from report import to_csv

text = to_csv([{"name": "Doe, Jane", "age": 40}])
rows = list(csv.reader(io.StringIO(text)))
if rows[1] != ["Doe, Jane", "40"]:
    sys.exit(f"a value with a comma did not survive: {rows[1]}")
