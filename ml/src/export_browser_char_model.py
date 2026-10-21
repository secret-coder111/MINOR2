"""Export a character TF-IDF logistic model for browser inference."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib


def export_model(metadata_path: Path, model_path: Path, output_path: Path) -> None:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    artifact = joblib.load(model_path)
    if not isinstance(artifact, dict) or "model" not in artifact or "vectorizer" not in artifact:
        raise ValueError("Expected a joblib bundle containing model and vectorizer")

    model = artifact["model"]
    vectorizer = artifact["vectorizer"]
    if not hasattr(model, "coef_") or not hasattr(vectorizer, "vocabulary_"):
        raise ValueError("Expected LogisticRegression and TfidfVectorizer artifacts")
    coefficients = [float(value) for value in model.coef_[0]]
    idf = [float(value) for value in vectorizer.idf_]
    if len(coefficients) != len(idf) or len(coefficients) != len(vectorizer.vocabulary_):
        raise ValueError("Model, IDF, and vocabulary dimensions do not match")

    browser_model = {
        "model_version": metadata["model_version"],
        "algorithm": metadata["algorithm"],
        "ngram_range": list(vectorizer.ngram_range),
        "vocabulary": {
            str(ngram): int(index)
            for ngram, index in vectorizer.vocabulary_.items()
        },
        "idf": idf,
        "coefficients": coefficients,
        "intercept": float(model.intercept_[0]),
        "threshold": float(metadata.get("threshold", 0.5)),
        "high_confidence_threshold": 0.99,
    }
    javascript = (
        "self.PHISH_GUARD_CHAR_MODEL = "
        + json.dumps(browser_model, separators=(",", ":"))
        + ";\n"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(javascript, encoding="utf-8")
    print(
        f"Exported {len(browser_model['vocabulary'])} character n-grams "
        f"to {output_path}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export_model(args.metadata, args.model, args.output)


if __name__ == "__main__":
    main()
