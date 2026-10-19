# Phishing Detection through Ensemble Learning

This project is a complete pipeline for detecting phishing websites through ensemble learning models. It collects live phishing and legitimate pages, extracts features from three parts of each page (the URL, the HTML and the JavaScript), trains four tree-based classifiers on those features, and compares them on performance metrics and on computational cost.

The main idea is that phishing pages spread their malicious behaviour across several parts of a page, so a model that sees all three parts together should be harder to evade than one that sees only one.

## Pipeline Overview

### 1. Data Gathering

Phishing URLs are collected from four sources: PhishTank, OpenPhish, the Phishing.Database repository and PhishStats. Legitimate URLs come from the Tranco ranking list, and a domain must stay on the list over time to be counted as benign.

- All seed URLs are normalised, merged and deduplicated before scraping.
- PhishStats and PhishTank are polled as often as each source allows, because phishing sites are often taken down within hours.
- Pages that time out, fail to connect or return a non-200 status are logged and discarded rather than retried.
- If an HTTPS request fails, the scraper makes one retry over HTTP before giving up.
- Malformed seed URLs are logged separately from scrape failures, so the two kinds of loss are reported on their own.

For each page the scraper saves the URL, the raw HTML (fetched with Beautiful Soup) and the inline JavaScript.

### 2. Datasets

The pipeline is run on two datasets, each evaluated on its own and never merged.

- Dataset A is the custom collection built with the scraper above. It contains 11,211 samples after cleaning and deduplication, of which 6,853 are benign and 4,358 are phishing.
- Dataset B is the benchmark from Aljofey et al. (2022). It contains 27,733 samples after conversion and deduplication, of which 17,427 are benign and 10,306 are phishing.

Both are converted to the same sample format so the exact same feature extraction can be applied to each. Duplicates are removed using label and hostname pairs.

### 3. Feature Extraction

Three branches each produce a feature vector, and the vectors are joined into one combined representation.

- **URL features** are lexical features adapted from Innab et al. (2024) and Aljofey et al. (2022).
- **HTML features** are 15 ratio-based features, adapted from Aljofey et al. (2022), that capture structural cloning patterns.
- **JavaScript features** are engineered in this project. They are built in four stages:
  1. Inline scripts are pulled out of the HTML. External scripts are skipped so the pipeline works offline.
  2. Each script is parsed into an Abstract Syntax Tree with Esprima. Scripts that fail to parse get a zero vector, so the sample is kept.
  3. The tree is walked in pre-order to produce a sequence of node types. Variable names and literal values are removed, so renaming variables does not change the result.
  4. The sequence is compressed with Byte-Pair Encoding using the Hugging Face tokenizers library, then turned into numbers with TF-IDF.

No script is ever executed, and the scraper never submits anything to a phishing page.

### 4. Preprocessing

- Missing categorical values receive an explicit unknown token, and missing numeric values are filled with zero.
- Data is split into 80 percent training and 20 percent testing with stratified sampling, using the same random seed for both datasets.
- Numeric features are scaled to the range 0 to 1 with Min-Max scaling.

### 5. Models

Four classifiers are compared on exactly the same features.

| Model | Role |
| --- | --- |
| Decision Tree | Single-model baseline |
| Random Forest | Bagging |
| XGBoost | Boosting |
| Stacking | Random Forest and XGBoost combined by a Logistic Regression meta-learner |

Hyperparameters are tuned with a grid search and 5-fold cross-validation on the training split only. The BPE tokeniser settings are tuned the same way.

### 6. Evaluation

## Results

### Detection performance

| Dataset | Model | Accuracy | Recall | Macro F1 | MCC |
| --- | --- | --- | --- | --- | --- |
| A | Decision Tree | 0.9939 | 0.9836 | 0.9932 | 0.9864 |
| A | Random Forest | 0.9971 | 0.9931 | 0.9967 | 0.9935 |
| A | XGBoost | 0.9954 | 0.9879 | 0.9948 | 0.9896 |
| A | Stacking | 0.9968 | 0.9914 | 0.9964 | 0.9929 |
| B | Decision Tree | 0.7670 | 0.6640 | 0.7484 | 0.4974 |
| B | Random Forest | 0.8238 | 0.7156 | 0.8075 | 0.6175 |
| B | XGBoost | 0.8345 | 0.7349 | 0.8197 | 0.6413 |
| B | Stacking | 0.8367 | 0.7374 | 0.8220 | 0.6461 |

- On Dataset A all four models are close to perfect, and the three ensembles cannot be told apart. Random Forest and Stacking make significantly fewer errors than the Decision Tree.
- On Dataset B all three ensembles make significantly fewer errors than the Decision Tree, with macro F1 gains of 0.0591 to 0.0736. Stacking and XGBoost cannot be separated from each other.
- Recall on Dataset B stays below 0.74, which means roughly a quarter of phishing pages are missed. The default decision threshold was used and was not tuned.

### Ablation

- On Dataset A, the 12 URL features alone reach almost the same score as the full vector, so the near-perfect results can be reached without any page content.
- On Dataset B, no single feature group is enough and no subset beats the full vector. Removing the URL features hurts the ensembles most, and URL plus HTML together keep about 97 percent of the best score using under 10 percent of the features.

## Limitations

- All results come from one train and test split and one random seed.
- Several chosen hyperparameters sit on the edge of the search grid, and the BPE and TF-IDF search covered 15 of 576 combinations.
- Only inline JavaScript is analysed, so payloads loaded from external files are missed.
- The benefit of BPE compared with simpler JavaScript encodings was not isolated.
- Dataset A may be easier because of how its two classes were sampled, so it is best read as an upper bound.

## Requirements

Python with Beautiful Soup, tranco, requests, python-whois, esprima, pandas, tokenizers, scikit-learn and XGBoost.

## Ethics

Only publicly listed phishing URLs are retrieved, and they are retrieved passively. No credentials are submitted, no retrieved script is run, and the collected data is used only for feature extraction and is not redistributed.

## Author

Sello Prince Lebudi, Rhodes University, supervised by Dr. Stones Chindipha.
