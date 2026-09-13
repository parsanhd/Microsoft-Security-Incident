# Microsoft Security Incident Triage Classification

This project predicts whether a security alert is a real threat (TruePositive), a
false alarm (FalsePositive), or benign activity (BenignPositive), using Microsoft's
public [GUIDE dataset](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction).
It's about 9.5M raw alert rows from real SOC (Security Operations Center) triage
decisions.

The model is evaluated under a strict organization-holdout split, meaning it's never
trained on an organization it's later tested on. That's a harder, more realistic
test than the dataset's own recommended benchmark split, which stratifies by
`OrgId` so the same org can show up in both train and test. See the methodology
notes below for why I made that choice.

## Notebooks

| Notebook | What it does |
|---|---|
| [`01_data_cleaning.ipynb`](01_data_cleaning.ipynb) | Loads the raw data, resolves data quality questions (hidden sentinel values, ambiguous zeros, duplicates), and outputs a clean CSV |
| [`02_categorical_data_analysis.ipynb`](02_categorical_data_analysis.ipynb) | Cramér's V correlation and redundancy analysis across categorical features |
| [`03_modeling.ipynb`](03_modeling.ipynb) | Feature engineering, model training, hyperparameter tuning, evaluation, and error analysis |

## Key EDA findings

- **Hidden sentinel values.** Several entity-specific columns (`IpAddress`,
  `RegistryKey`, `FolderPath`, and others) use one dominant value as a stand-in for
  "not applicable to this entity" instead of a true null. I confirmed this with an
  entity-type-conditional breakdown: a real sentinel is rare specifically where the
  column should actually be meaningful, and shows up almost everywhere else. Only
  columns that passed this test got converted to `NaN`. I kept two versions of the
  cleaned dataset (sentinel to NaN vs. no conversion) so I could actually test
  whether the conversion helped instead of just assuming it would.
- **`AlertTitle == 0` turned out to be a real category, not missing data.** All of
  these rows fall under `Category == InitialAccess`, and the zero rate is
  concentrated almost entirely in cloud logon related entity types, which is the
  opposite of what a true placeholder value would look like.
- **`IncidentId` carries no meaning across organizations.** It's just a per-org
  counter that gets reused. I checked this by comparing label agreement among
  `IncidentId` values shared across multiple orgs, and agreement came out lower
  than you'd expect from random chance. Because of that, every split and feature
  in this project uses the combined key `(OrgId, IncidentId)` instead of relying
  on `IncidentId` alone.
- **Correlation strength alone can be misleading if you don't check row overlap.**
  A handful of categorical feature pairs showed near perfect Cramér's V (0.85 or
  higher), but most of those were only backed by under 1% of the dataset, so
  they're sparse, nested relationships rather than genuine redundancy. Only two
  pairs had enough overlap to trust: `EntityType` and `EvidenceRole` (99.9%
  coverage, V = 0.88) and `Category` and `MitreTechniques` (42.4% coverage,
  V = 0.86).

## Modeling approach

- **Leak-safe risk encoding.** `AlertTitleRisk` (the historical true positive rate
  for a given alert title) is computed with 5-fold out-of-fold encoding on the
  training data, then applied to test and external data through a lookup built
  entirely from training data. No row's own label ever leaks into its own feature.
- **Incident-context features.** Alert count, distinct category/entity/detector
  counts, and max/mean historical risk within each incident, all computed from that
  incident's own sibling alerts. These don't depend on having seen the organization
  before, which matters for the org-holdout evaluation.
- **MITRE ATT&CK techniques** as multi-label features, using the top 30 individual
  techniques by frequency, one-hot encoded.
- **Ablation testing.** Dropped `State` and `City` after confirming they're mostly
  redundant with `CountryCode`, and that dropping them actually improved the score
  instead of hurting it.
- **Hyperparameter tuning** with `RandomizedSearchCV` and `GroupKFold` grouped by
  `OrgId`, reproducible across 3 separate reruns.
- **Decision threshold tuning.** Per-class probability weighting, searched on a
  slice carved out of the training data so the test set is never touched.

## Results

| Stage | Macro F1 |
|---|---|
| Baseline (sentinel to NaN cleaning) | 0.4095 |
| Baseline (no conversion cleaning) | 0.4138 |
| Plus AlertTitleRisk (OOF encoding) | 0.4624 |
| Plus MITRE multi-label, dropped State/City | 0.4682 |
| Plus incident-level voting (untuned model) | 0.4901 |
| Plus incident context features | 0.4972 |
| Plus tuned hyperparameters (final model) | 0.5116 |
| External test, full file (includes familiar orgs) | 0.7353 (inflated by org overlap) |
| External test, clean org-disjoint subset | **0.5127 (the real generalization number)** |

The internal test score (0.5116) and the clean external score (0.5127) line up
closely, which is good evidence the model generalizes to unseen organizations
rather than overfitting one particular split.

**PR-AUC by class** (final model): BenignPositive 0.663, TruePositive 0.625,
FalsePositive 0.376.

## Known limitation

TruePositive recall, meaning how well the model catches real threats, is the
weakest part of this project. It sat at 0.34 before tuning and improved to 0.44
after tuning and threshold weighting, but it's still missing a majority of real
threats. When I compared correctly caught threats against missed ones, the missed
ones were consistently "quiet": far fewer alerts per incident (median 19 vs. 604)
and no single alert that looked historically risky (median max risk 0.30 vs. 0.98).
That's consistent with attackers deliberately trying to avoid detection rather than
a generic model weakness. I also tested class weighting as a fix, and it actually
made recall slightly worse (0.31), which ruled out plain class imbalance as the
cause.

FalsePositive is actually the numerically weakest class overall, with a PR-AUC of
0.376. I didn't focus my error analysis on it here, but it's a good candidate for
further digging.

## Methodology notes

The [paper that introduced this dataset](https://arxiv.org/abs/2407.09017) (Freitas
et al., Microsoft Security Research) recommends macro F1 as the evaluation metric
and describes a 70/30 split stratified by `OrgId`, where organizations appear in
both train and test, as the standard benchmark. I used a stricter org-holdout split
instead, where training never sees an organization it's evaluated on, because I
think a triage model's real value is working on a brand new customer with no prior
history, not one already represented in training data. This is a harder task, so
scores here shouldn't be compared directly to results using the stratified split.

Based on a 2026 survey of public SOC alert-triage datasets (Ndichu et al.), GUIDE
is currently the only public dataset with real analyst-assigned labels at this
scale, so I didn't pursue combining it with another dataset for more training
signal.

## Rejected or abandoned approaches

Class weighting, dropping raw ID columns, DetectorRisk/CategoryRisk features,
EntityType by EvidenceRole interaction features, ordinal severity scores, reusing
older hyperparameters on newer features, temporal entity history (it leaked through
same-incident sibling rows), incident-consensus-label training (there was no label
noise to actually fix), context features combined with incident voting (worse than
either alone), and incident-level voting on the final tuned model (no improvement
once tuning and threshold weighting were already applied).

## Future work

- Timing-based features (time of day, gaps between alerts) and MITRE technique
  sequence features, not just presence, to target the "quiet threat" blind spot
- Look into the FalsePositive/BenignPositive confusion with the same kind of error
  analysis used for TruePositive
- Test whether a higher MITRE technique cutoff (currently the top 30 out of 422)
  changes anything
- Break down performance by organization to check for a few bad outliers vs.
  consistently mediocre performance everywhere
- Check probability calibration before relying further on threshold search
- Use bootstrap confidence intervals when comparing model versions

## Dataset

[Microsoft Security Incident Prediction (GUIDE)](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction)
on Kaggle, originally released alongside
[Freitas et al., 2024](https://arxiv.org/abs/2407.09017).
