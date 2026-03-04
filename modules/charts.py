import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def generate_chart(vulnerabilities):
    labels = vulnerabilities.keys()
    values = vulnerabilities.values()

    plt.figure()
    plt.bar(labels, values)
    plt.title("Vulnerability Summary")
    plt.xticks(rotation=45)

    chart_path = "static/chart.png"
    plt.savefig(chart_path)
    plt.close()

    return chart_path