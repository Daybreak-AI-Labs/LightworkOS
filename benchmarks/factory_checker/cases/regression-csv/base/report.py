"""Write rows of dicts as CSV text."""
import csv
import io


def to_csv(rows):
    """CSV text with a header line from the first row's keys."""
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()
