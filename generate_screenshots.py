"""
Generate placeholder preview cards for documentation screenshots.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

os.makedirs("docs/screenshots", exist_ok=True)

cards = [
    (
        "scam.png",
        "LIKELY SCAM (98% Confidence)",
        "Mubarak ho! Apka BISP me 25,000 rupay ka wazifa aya hai...",
        "#d32f2f",
        "#ffebee",
        "Flags: Prize Fraud, Suspicious Cellular Number"
    ),
    (
        "safe.png",
        "LIKELY SAFE (95% Confidence)",
        "Your OTP for Meezan Online Banking is 839210. NEVER share...",
        "#2e7d32",
        "#e8f5e9",
        "Legitimate Security Warning Syntax Verified"
    ),
    (
        "urdu.png",
        "Explain Simply Mode (اردو)",
        "یہ بے نظیر انکم سپورٹ کا جعلی میسج ہے۔ حکومت کبھی عام نمبر سے پیسے نہیں بھیجتی۔",
        "#0288d1",
        "#e1f5fe",
        "Right-to-Left (RTL) Vernacular Urdu"
    ),
    (
        "fallback.png",
        "RULES-ONLY FALLBACK MODE",
        "Deterministic Regex Pattern Engine (Offline Resilient)",
        "#f57f17",
        "#fff8e1",
        "Graceful Degradation When Cloud API Is Offline"
    )
]

for filename, title, subtitle, color, bg_color, footer in cards:
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    fig.patch.set_facecolor(bg_color)
    ax.set_facecolor(bg_color)

    # Draw border
    rect = plt.Rectangle((0.05, 0.05), 0.9, 0.9, fill=False, edgecolor=color, linewidth=3, transform=ax.transAxes)
    ax.add_patch(rect)

    # Text elements
    ax.text(0.5, 0.72, title, color=color, fontsize=16, weight="bold", ha="center", va="center", transform=ax.transAxes)
    ax.text(0.5, 0.48, subtitle, color="#333333", fontsize=11, style="italic", ha="center", va="center", wrap=True, transform=ax.transAxes)
    ax.text(0.5, 0.22, footer, color="#555555", fontsize=10, weight="semibold", ha="center", va="center", transform=ax.transAxes)

    ax.axis("off")
    plt.tight_layout()
    plt.savefig(os.path.join("docs", "screenshots", filename), facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()

print("Generated 4 screenshot preview graphics in docs/screenshots/")
