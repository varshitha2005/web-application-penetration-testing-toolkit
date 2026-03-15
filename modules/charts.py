import matplotlib.pyplot as plt
import io
import base64

# Ensure non-interactive backend
import matplotlib
matplotlib.use('Agg')

def generate_chart(vulnerabilities):
    """
    Expects: vulnerabilities = {"SQLi": 1, "XSS": 0, "Malware": 0}
    """
    # 1. Filter out zero values so the bar chart is clean
    chart_data = {k: v for k, v in vulnerabilities.items() if v > 0}
    
    # 2. Reset the plot to avoid overlapping previous scans
    plt.figure(figsize=(8, 5))
    
    if chart_data:
        labels = list(chart_data.keys())
        values = list(chart_data.values())
        # Use a more professional color scheme
        plt.bar(labels, values, color='#4ecdc4')
        plt.title('Vulnerability Summary')
        plt.ylabel('Number of Issues')
    else:
        # If no vulnerabilities, show a clear "No Issues" bar
        plt.bar(['No Issues'], [0], color='#00b894')
        plt.title('Scan Complete: No Vulnerabilities Found')
    
    plt.tight_layout()
    
    # 3. Save to buffer and encode
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=100)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    
    # 4. CRITICAL: Close the plot to free up memory
    plt.close()
    
    return f"data:image/png;base64,{img_base64}"