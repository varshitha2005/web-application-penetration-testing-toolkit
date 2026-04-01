import matplotlib
matplotlib.use("Agg")

from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator
from io import BytesIO
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_chart(vulnerabilities):
    """Generate a bar chart as a base64 PNG string for Flask templates."""
    try:
        categories = ["SQL", "XSS", "Malware", "Headers", "Directory"]
        counts = [int(vulnerabilities.get(cat, 0) or 0) for cat in categories]

        fig = Figure(figsize=(7, 4), dpi=100)
        ax = fig.subplots()

        bars = ax.bar(
            categories,
            counts,
            color=["#ef4444", "#f59e0b", "#8b5cf6", "#06b6d4", "#10b981"],
            edgecolor="#1f2937",
            linewidth=0.8
        )

        ax.set_title("Vulnerability Summary", fontsize=12, fontweight="bold")
        ax.set_xlabel("Vulnerability Type")
        ax.set_ylabel("Count")
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.set_ylim(0, max(counts + [1]) + 1)

        for tick in ax.get_xticklabels():
            tick.set_rotation(30)
            tick.set_horizontalalignment("right")

        for bar, count in zip(bars, counts):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.05,
                str(count),
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold"
            )

        ax.grid(axis="y", linestyle="--", alpha=0.3)
        fig.tight_layout()

        buf = BytesIO()
        fig.savefig(buf, format="png", bbox_inches="tight")
        buf.seek(0)

        img_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        logger.info(f"Chart generated successfully. Counts={counts}, Base64 length={len(img_base64)}")

        return f"data:image/png;base64,{img_base64}"

    except Exception as e:
        logger.error(f"Chart generation error: {e}")
        return None