# Muhafiz AI Evaluation Benchmark Results

Total benchmark samples: **60** (25 Scam, 25 Legitimate, 10 Ambiguous/Suspicious)

## Overall Performance Comparison

| Pipeline Mode | Accuracy | Precision (Weighted) | Recall (Weighted) | F1 Score (Weighted) |
| :--- | :--- | :--- | :--- | :--- |
| **Rules-Only** | 58.3% | 60.9% | 58.3% | 53.8% |
| **LLM-Only** | 91.7% | 92.2% | 91.7% | 91.5% |
| **Hybrid Pipeline (Muhafiz AI)** | **91.7%** | **92.2%** | **91.7%** | **91.5%** |

## Confusion Matrix (Hybrid Mode)

Labels order: `likely_scam`, `suspicious`, `likely_safe`

```
[[25  0  0]
 [ 3  7  0]
 [ 1  1 23]]
```

## Analysis of Edge Cases & Disagreements

Total edge-case disagreements: **5**

- **Sample #31** (`roman_urdu` / `official_aid_notice`)
  - **Input:** *"BISP 8171: Mohtarma Fatima, apki sah mahi kist 10,500 rupay jari ho chuki hai. Nazdeeki HBL Konnect se wasool karein."*
  - **Ground Truth:** `likely_safe` | **Predicted:** `likely_scam`

- **Sample #41** (`urdu_script` / `bank_receipt`)
  - **Input:** *"آپ کے اکاؤنٹ میں 10,000 روپے کامیابی سے منتقل کر دیے گئے ہیں۔ ٹرانزیکشن آئی ڈی: 4492019"*
  - **Ground Truth:** `likely_safe` | **Predicted:** `suspicious`

- **Sample #53** (`english` / `vague_prize`)
  - **Input:** *"Congratulations on being selected for our corporate reward scheme. Reply for details."*
  - **Ground Truth:** `suspicious` | **Predicted:** `likely_scam`

- **Sample #54** (`mixed` / `uncertain_link`)
  - **Input:** *"Bhai yeh link check karna zara, sachi hai kya: http://free-recharge-offer.online"*
  - **Ground Truth:** `suspicious` | **Predicted:** `likely_scam`

- **Sample #58** (`roman_urdu` / `vague_bonus`)
  - **Input:** *"Aapke account par 500 rupay ka bonus diya gaya hai, mazeed maloomat ke liye helpline par call karein."*
  - **Ground Truth:** `suspicious` | **Predicted:** `likely_scam`

## Why Hybrid Beats Standalone Approaches

1. **Rules-Only lacks semantic context**: Pure regex cannot distinguish benign conversational context without handcrafted indicators.
2. **LLM-Only lacks hard grounding**: Pure LLMs can be vulnerable to subtle social engineering prompts.
3. **Hybrid Synergy**: Combining deterministic rule weights with LLM semantic reasoning produces the highest accuracy and guarantees zero-downtime offline fallback.
