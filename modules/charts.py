import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt


def generate_chart(vulnerabilities):

    labels = list(vulnerabilities.keys())
    values = list(vulnerabilities.values())

    plt.figure(figsize=(6,4))

    plt.bar(labels, values)

    plt.title("Vulnerability Summary")
    plt.xlabel("Vulnerability Type")
    plt.ylabel("Count")

    plt.xticks(rotation=45)

    chart_path = "static/chart.png"

    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

    return chart_path